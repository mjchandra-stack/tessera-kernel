// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The ISL abstract syntax tree: a faithful, unresolved parse of a schema.
//! Name resolution, ordinal rules, bounds, and the ABI-subset restriction are
//! enforced later against this tree (see `check`); the parser only records
//! structure.
//!
//! Normative: docs/api/03-interface-schema-language.md ("Type System",
//! "Protocols")

use crate::diag::Span;

/// A parsed schema file.
#[derive(Clone, Debug)]
pub struct Schema {
    /// Dotted library name, e.g. `tessera.example.handleops`.
    pub library: String,
    pub library_span: Span,
    pub decls: Vec<Decl>,
}

/// `@available(added=N, deprecated=N, removed=N)` — all parts optional.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Availability {
    pub added: Option<u64>,
    pub deprecated: Option<u64>,
    pub removed: Option<u64>,
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
    pub base: PrimType,
    pub base_span: Span,
    pub members: Vec<ValueMember>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct EnumDecl {
    pub name: String,
    pub name_span: Span,
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
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct StructDecl {
    pub name: String,
    pub name_span: Span,
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
    pub members: Vec<OrdinalMember>,
    pub availability: Availability,
}

#[derive(Clone, Debug)]
pub struct UnionDecl {
    pub name: String,
    pub name_span: Span,
    pub strictness: Strictness,
    pub members: Vec<OrdinalMember>,
    pub availability: Availability,
}

/// An ordinal-numbered member of a table or union: a field or a reserved slot.
#[derive(Clone, Debug)]
pub struct OrdinalMember {
    pub ordinal: u64,
    pub ordinal_span: Span,
    pub kind: OrdinalKind,
}

#[derive(Clone, Debug)]
pub enum OrdinalKind {
    Field(Field),
    Reserved,
}

#[derive(Clone, Debug)]
pub struct ProtocolDecl {
    pub name: String,
    pub name_span: Span,
    pub methods: Vec<Method>,
    pub availability: Availability,
}

/// A protocol method, keyed by ordinal.
#[derive(Clone, Debug)]
pub struct Method {
    pub ordinal: u64,
    pub ordinal_span: Span,
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
