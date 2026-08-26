// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ISL abstract syntax tree: a faithful, unresolved parse of a schema.
//! Name resolution, ordinal rules, bounds, and the ABI-subset restriction are
//! enforced later against this tree (see `check`); the parser only records
//! structure.
//!
//! Every declaration carries the prose written above it (`doc`) and the
//! implementation status claimed for it (`status`), because the reference
//! documentation is generated from the schema rather than written beside it
//! (docs/api/03, "Generated Artifacts"). An empty `doc` is a declaration
//! nobody described; the syscall-surface gate treats that as a finding.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Type System",
//! "Protocols", "System Calls")

use crate::diag::Span;

/// A parsed schema file.
#[derive(Clone, Debug)]
pub struct Schema {
    /// Dotted library name, e.g. `tessera.example.handleops`.
    pub library: String,
    pub library_span: Span,
    /// The file's leading comment block, less its SPDX and copyright lines:
    /// what the schema says about itself.
    pub doc: String,
    pub decls: Vec<Decl>,
}

/// `@available(added=N, deprecated=N, removed=N)` — all parts optional.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Availability {
    pub added: Option<u64>,
    pub deprecated: Option<u64>,
    pub removed: Option<u64>,
}

/// What a declaration claims about itself: whether the thing it describes
/// exists in this tree today.
///
/// **The reason this is in the schema and not in prose.** `docs/api/01`
/// describes about twenty syscall families and marks none of them, so a reader
/// cannot tell which exist — a design document being read as a reference. A
/// generated page can only say what exists if the definition it is generated
/// from knows. Reasoning about *why* something is deferred stays in the
/// deviation ledger, which the doc page links to; a schema is a poor place for
/// an argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Status {
    /// The tree implements this, and a check exercises it.
    Implemented,
    /// Specified here, deliberately, with nothing behind it yet.
    Designed,
    /// Specified and explicitly not built; the ledger says why.
    Deferred,
    /// No claim made. Legal everywhere except a `syscall`, where the checker
    /// requires one — the call surface is the thing whose status a reader
    /// cannot otherwise discover.
    #[default]
    Unstated,
}

impl Status {
    /// The source spelling, and the word the generated page prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Implemented => "implemented",
            Status::Designed => "designed",
            Status::Deferred => "deferred",
            Status::Unstated => "unstated",
        }
    }

    /// Parses a `@status(...)` argument, or `None` for a word outside the set.
    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "implemented" => Some(Status::Implemented),
            "designed" => Some(Status::Designed),
            "deferred" => Some(Status::Deferred),
            _ => None,
        }
    }
}

/// A top-level declaration.
#[derive(Clone, Debug)]
pub enum Decl {
    Bits(BitsDecl),
    Enum(EnumDecl),
    Struct(StructDecl),
    Table(TableDecl),
    Union(UnionDecl),
    Protocol(ProtocolDecl),
    Syscall(SyscallDecl),
    Extern(ExternDecl),
}

impl Decl {
    pub fn name(&self) -> &str {
        match self {
            Decl::Bits(d) => &d.name,
            Decl::Enum(d) => &d.name,
            Decl::Struct(d) => &d.name,
            Decl::Table(d) => &d.name,
            Decl::Union(d) => &d.name,
            Decl::Protocol(d) => &d.name,
            Decl::Syscall(d) => &d.name,
            Decl::Extern(d) => &d.name,
        }
    }

    pub fn name_span(&self) -> Span {
        match self {
            Decl::Bits(d) => d.name_span,
            Decl::Enum(d) => d.name_span,
            Decl::Struct(d) => d.name_span,
            Decl::Table(d) => d.name_span,
            Decl::Union(d) => d.name_span,
            Decl::Protocol(d) => d.name_span,
            Decl::Syscall(d) => d.name_span,
            Decl::Extern(d) => d.name_span,
        }
    }
}

/// Strict rejects unknown values; flexible preserves them (enums and unions).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strictness {
    Strict,
    Flexible,
}

/// An unsigned/signed/float primitive base type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrimType {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float32,
    Float64,
}

impl PrimType {
    /// Size in bytes of the primitive's wire encoding.
    pub fn size(self) -> usize {
        match self {
            PrimType::Bool | PrimType::Int8 | PrimType::Uint8 => 1,
            PrimType::Int16 | PrimType::Uint16 => 2,
            PrimType::Int32 | PrimType::Uint32 | PrimType::Float32 => 4,
            PrimType::Int64 | PrimType::Uint64 | PrimType::Float64 => 8,
        }
    }

    /// Whether the base is an unsigned integer (valid `bits`/`enum` base).
    pub fn is_unsigned(self) -> bool {
        matches!(
            self,
            PrimType::Uint8 | PrimType::Uint16 | PrimType::Uint32 | PrimType::Uint64
        )
    }
}

/// A type reference.
#[derive(Clone, Debug)]
pub enum Type {
    Prim(PrimType),
    /// A reference to a named declaration (resolved later).
    Named(String, Span),
    /// `array<T, N>` — fixed length, inline.
    Array(Box<Type>, u64, Span),
    /// `vector<T>:N` — the bound is optional in the grammar so the checker can
    /// reject an unbounded `vector<T>` (docs/api/03: unbounded is not
    /// expressible, enforced by the compiler).
    Vector(Box<Type>, Option<u64>, Span),
    /// `string:N` — bounded UTF-8; the bound is optional in the grammar for the
    /// same reason as `vector`.
    StringT(Option<u64>, Span),
    /// `handle<Object, {RIGHTS}>`.
    Handle(HandleType),
}

impl Type {
    pub fn span(&self) -> Span {
        match self {
            Type::Prim(_) => Span::point(0),
            Type::Named(_, s)
            | Type::Array(_, _, s)
            | Type::Vector(_, _, s)
            | Type::StringT(_, s) => *s,
            Type::Handle(h) => h.span,
        }
    }
}

/// A `handle<Object, {rights}>` type: object type name plus minimum rights.
#[derive(Clone, Debug)]
pub struct HandleType {
    pub object: String,
    pub rights: Vec<String>,
    pub span: Span,
}

/// Out-of-line ownership mode; `snapshot` is the default.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ownership {
    Transfer,
    Share,
    Snapshot,
}

/// A named field in a struct, table, union, or method payload.
#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub ty: Type,
    pub optional: bool,
    pub ownership: Option<Ownership>,
    pub data_class: Option<String>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct BitsDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    pub base: PrimType,
    pub base_span: Span,
    pub members: Vec<ValueMember>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct EnumDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    pub strictness: Strictness,
    pub base: PrimType,
    pub base_span: Span,
    pub members: Vec<ValueMember>,
    pub availability: Availability,
}

/// A `NAME = VALUE` member of an enum or bits.
#[derive(Clone, Debug)]
pub struct ValueMember {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct StructDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    /// Marked `@abi`: a syscall structured-argument struct, which must lead
    /// with the mandatory `size`/`version`/`flags` header.
    pub abi: bool,
    pub fields: Vec<Field>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct TableDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    pub members: Vec<OrdinalMember>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct UnionDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    pub strictness: Strictness,
    pub members: Vec<OrdinalMember>,
    pub availability: Availability,
}

/// An ordinal-numbered member of a table or union: a field or a reserved slot.
#[derive(Clone, Debug)]
pub struct OrdinalMember {
    pub ordinal: u64,
    pub ordinal_span: Span,
    pub doc: String,
    pub kind: OrdinalKind,
}

#[derive(Clone, Debug)]
pub enum OrdinalKind {
    /// Boxed because the other variant carries nothing: a `Field` is the
    /// largest thing in the tree, and an unboxed one would make every reserved
    /// slot cost as much as a described one.
    Field(Box<Field>),
    Reserved,
}

#[derive(Clone, Debug)]
pub struct ProtocolDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    pub methods: Vec<Method>,
    pub availability: Availability,
}

/// A protocol method, keyed by ordinal.
#[derive(Clone, Debug)]
pub struct Method {
    pub ordinal: u64,
    pub ordinal_span: Span,
    pub doc: String,
    pub status: Status,
    pub availability: Availability,
    pub kind: MethodKind,
}

#[derive(Clone, Debug)]
pub enum MethodKind {
    /// `N: Name(req) -> (resp);`
    Call {
        name: String,
        name_span: Span,
        request: Payload,
        response: Payload,
    },
    /// `N: Name(req);`
    OneWay {
        name: String,
        name_span: Span,
        request: Payload,
    },
    /// `N: -> Name(payload);` (server-initiated event)
    Event {
        name: String,
        name_span: Span,
        payload: Payload,
    },
    /// `N: reserved;`
    Reserved,
}

/// A method request/response body: empty, a named type, or an inline record.
#[derive(Clone, Debug)]
pub enum Payload {
    Empty,
    Named(String, Span),
    Struct(Vec<Field>),
    Table(Vec<OrdinalMember>),
}

/// One system call: a trap number, the register frame it reads, and the value
/// it hands back.
///
/// **Why this is its own declaration and not a `protocol` method.** A protocol
/// method is a message: a request payload, a response payload, a transaction
/// ID pairing them, and a channel underneath. A syscall is none of those. It
/// is a number in a register, up to six more registers beside it, and a single
/// signed word back whose sign is the success/failure discriminator
/// (docs/api/01, "The Result Word"). Spelling one as the other would put a
/// response payload where there is a result word and a channel where there is
/// a trap, and every artifact generated from it would inherit the fiction.
///
/// **What a register slot means.** `argN: T` says register *N* carries a value
/// of type `T` — except when `T` names an `@abi` struct, where the register
/// carries a *user pointer* to one. That is the ABI as the kernel implements
/// it: `kcore::syscall`'s decoders take `arg0` as a pointer and validate the
/// struct behind it, and the calls that take no struct read scalars straight
/// out of the registers. Eighteen of the fifty do the latter, which is the
/// case `docs/roadmap/03` predicted the language would have to grow a
/// construct for.
///
/// **Required rights ride on the handle**, not on the call: a slot declared
/// `handle<Object, {MAP}>` says this call needs `MAP` on the capability in
/// that register, and for a call whose handle arrives inside its argument
/// struct the requirement is already on that struct's handle field.
#[derive(Clone, Debug)]
pub struct SyscallDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    pub status: Status,
    /// The call number, as it appears in the trap's number register.
    pub number: u64,
    pub number_span: Span,
    /// Register slots, in order from `arg0`. A gap is a checker error.
    pub args: Vec<SyscallArg>,
    /// What a success returns, or `None` for a call whose only success is 0.
    pub returns: Option<SyscallReturn>,
    pub availability: Availability,
}

/// One register slot of a syscall's frame.
#[derive(Clone, Debug)]
pub struct SyscallArg {
    /// The slot's index, taken from its `argN` spelling.
    pub index: u64,
    pub name_span: Span,
    pub doc: String,
    pub ty: Type,
}

/// The success value a syscall hands back.
#[derive(Clone, Debug)]
pub struct SyscallReturn {
    pub doc: String,
    pub ty: Type,
    pub span: Span,
}

/// `extern struct Name from dotted.library;` — a type this schema names but
/// another one owns.
///
/// **Why this rather than an import.** The call surface has to point at the
/// fifty argument structs, and they live in the twelve schemas that own the
/// subsystems they belong to — `MemoryMapArgs` belongs beside the rest of the
/// memory ABI, not beside the trap numbers. A real module system would resolve
/// them, and building one in order to write down a call surface is the tail
/// wagging the dog: a syscall's register slot needs the argument struct's
/// *name*, never its layout, because the register holds a pointer.
///
/// So the dependency is declared instead of resolved, and made checkable
/// rather than implicit: the schema says which library owns the name, and
/// `//tools/checks:surface_test` resolves every one of them against the schema set
/// and fails if the named library has no `@abi` struct by that name. What a
/// module system would do at compile time, one gate does across the tree —
/// and the gate has to walk every schema anyway to answer the question the
/// surface exists for.
///
/// An external name may be pointed at by a register slot and nothing else. It
/// carries no layout here, so it cannot be a field of a struct in this schema;
/// the checker refuses that rather than laying it out as zero bytes.
#[derive(Clone, Debug)]
pub struct ExternDecl {
    pub name: String,
    pub name_span: Span,
    pub doc: String,
    /// The library that declares it, e.g. `tessera.kernel.memory`.
    pub library: String,
    pub library_span: Span,
}
