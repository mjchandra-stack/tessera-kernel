// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The compiled intermediate representation: a resolved, layout-fixed form of
//! a schema. Struct field offsets and sizes are computed by one canonical
//! algorithm here, making the IR the layout-authoritative source a future
//! ABI-diff and C-vs-Rust layout check compare against
//! (docs/lifecycle/02-build-and-test-infrastructure.md:40). `emit_text`
//! renders a deterministic textual form for goldens and diffing.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/api/01-system-call-interface.md ("Structured Arguments")

use crate::ast::PrimType;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A fully compiled schema.
#[derive(Clone, Debug)]
pub struct Ir {
    pub library: String,
    pub decls: Vec<IrDecl>,
}

#[derive(Clone, Debug)]
pub enum IrDecl {
    Enum(IrEnum),
    Bits(IrBits),
    Struct(IrStruct),
    Table(IrTable),
    Union(IrUnion),
    Protocol(IrProtocol),
}

#[derive(Clone, Debug)]
pub struct IrEnum {
    pub name: String,
    pub strict: bool,
    pub base: PrimType,
    pub members: Vec<(String, u64)>,
}

#[derive(Clone, Debug)]
pub struct IrBits {
    pub name: String,
    pub base: PrimType,
    pub members: Vec<(String, u64)>,
}

/// A frozen, fixed-layout struct — the codegen and syscall type.
#[derive(Clone, Debug)]
pub struct IrStruct {
    pub name: String,
    /// True if marked `@abi` (a syscall structured-argument struct).
    pub abi: bool,
    pub size: usize,
    pub align: usize,
    pub fields: Vec<IrField>,
}

#[derive(Clone, Debug)]
pub struct IrField {
    pub name: String,
    pub ty: IrFieldType,
    pub offset: usize,
    pub size: usize,
}

/// A frozen struct's field type (the inline subset only).
#[derive(Clone, Debug)]
pub enum IrFieldType {
    Prim(PrimType),
    Enum {
        name: String,
        base: PrimType,
    },
    Bits {
        name: String,
        base: PrimType,
    },
    /// A handle reference (a 4-byte side-table index).
    Handle,
    Array {
        elem: Box<IrFieldType>,
        len: u64,
    },
    /// A nested frozen struct, referenced by name.
    Struct {
        name: String,
    },
    /// `string:N` — a bounded UTF-8 string (out-of-line; legal in a table or
    /// union field, never a frozen struct). `max` is the byte bound.
    String {
        max: u64,
    },
    /// `vector<T>:N` — a bounded vector of an inline element type (out-of-line;
    /// table/union fields only). `max` is the element-count bound.
    Vector {
        elem: Box<IrFieldType>,
        max: u64,
    },
}

/// Extensible record (parsed and checked; wire codegen deferred).
#[derive(Clone, Debug)]
pub struct IrTable {
    pub name: String,
    pub members: Vec<IrOrdinalMember>,
}

#[derive(Clone, Debug)]
pub struct IrUnion {
    pub name: String,
    pub strict: bool,
    pub members: Vec<IrOrdinalMember>,
}

#[derive(Clone, Debug)]
pub struct IrOrdinalMember {
    pub ordinal: u64,
    /// Field name, or `None` for a reserved slot.
    pub field: Option<String>,
    /// The member's resolved type, or `None` for a reserved slot. Carried so
    /// union (and, later, table) wire codegen has the variant/field type it
    /// must encode — the earlier IR dropped it (deviation D10). An out-of-line
    /// type (string/vector) resolves here but its codegen is still deferred.
    pub ty: Option<IrFieldType>,
}

#[derive(Clone, Debug)]
pub struct IrProtocol {
    pub name: String,
    /// 64-bit interface ID; filled in when interface-ID derivation lands.
    pub interface_id: u64,
    pub methods: Vec<IrMethod>,
}

#[derive(Clone, Debug)]
pub struct IrMethod {
    pub ordinal: u64,
    pub name: String,
    pub kind: IrMethodKind,
}

/// A method request/response body, after inline payloads have been synthesized
/// into named types. Codegen references the type by name; `Empty` is a unit
/// dispatch variant that frames zero bytes.
#[derive(Clone, Debug)]
pub enum IrPayload {
    Empty,
    Type(String),
}

impl IrPayload {
    /// The referenced type name, or `None` for an empty body.
    pub fn type_name(&self) -> Option<&str> {
        match self {
            IrPayload::Empty => None,
            IrPayload::Type(name) => Some(name),
        }
    }
}

#[derive(Clone, Debug)]
pub enum IrMethodKind {
    Call {
        request: IrPayload,
        response: IrPayload,
    },
    OneWay {
        request: IrPayload,
    },
    Event {
        payload: IrPayload,
    },
    Reserved,
}

impl IrMethodKind {
    fn label(&self) -> &'static str {
        match self {
            IrMethodKind::Call { .. } => "call",
            IrMethodKind::OneWay { .. } => "one_way",
            IrMethodKind::Event { .. } => "event",
            IrMethodKind::Reserved => "reserved",
        }
    }
}

/// Rounds `value` up to a multiple of `align` (a power of two ≥ 1).
pub fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

impl IrFieldType {
    /// Wire size in bytes, given the sizes/alignments of already-laid-out
    /// structs (nested struct sizes come from `structs`).
    pub fn size(&self, structs: &BTreeMap<String, (usize, usize)>) -> usize {
        match self {
            IrFieldType::Prim(p) => p.size(),
            IrFieldType::Enum { base, .. } | IrFieldType::Bits { base, .. } => base.size(),
            IrFieldType::Handle => 4,
            IrFieldType::Array { elem, len } => elem.size(structs) * (*len as usize),
            IrFieldType::Struct { name } => structs.get(name).map(|&(s, _)| s).unwrap_or(0),
            // Worst-case wire size: the 4-byte count/len prefix plus a
            // full-capacity payload. Used to bound a union's preservation
            // buffer; the actual envelope size is the value's runtime length.
            IrFieldType::String { max } => 4 + *max as usize,
            IrFieldType::Vector { elem, max } => 4 + elem.size(structs) * (*max as usize),
        }
    }

    /// Wire alignment in bytes.
    pub fn align(&self, structs: &BTreeMap<String, (usize, usize)>) -> usize {
        match self {
            IrFieldType::Prim(p) => p.size().max(1),
            IrFieldType::Enum { base, .. } | IrFieldType::Bits { base, .. } => base.size().max(1),
            IrFieldType::Handle => 4,
            IrFieldType::Array { elem, .. } => elem.align(structs),
            IrFieldType::Struct { name } => structs.get(name).map(|&(_, a)| a).unwrap_or(1),
            // The 4-byte count/len prefix leads a bounded collection.
            IrFieldType::String { .. } | IrFieldType::Vector { .. } => 4,
        }
    }

    /// True for a bounded string or vector — a field whose wire length varies
    /// with its content, so its envelope size must be read from the value at
    /// encode time rather than baked as a constant.
    pub fn is_bounded_collection(&self) -> bool {
        matches!(
            self,
            IrFieldType::String { .. } | IrFieldType::Vector { .. }
        )
    }

    fn render(&self) -> String {
        match self {
            IrFieldType::Prim(p) => prim_name(*p).to_owned(),
            IrFieldType::Enum { name, .. } => format!("enum {name}"),
            IrFieldType::Bits { name, .. } => format!("bits {name}"),
            IrFieldType::Handle => "handle".to_owned(),
            IrFieldType::Array { elem, len } => format!("array<{}, {len}>", elem.render()),
            IrFieldType::Struct { name } => format!("struct {name}"),
            IrFieldType::String { max } => format!("string:{max}"),
            IrFieldType::Vector { elem, max } => format!("vector<{}>:{max}", elem.render()),
        }
    }
}

/// The name of a primitive type as it appears in emitted text.
pub fn prim_name(p: PrimType) -> &'static str {
    match p {
        PrimType::Bool => "bool",
        PrimType::Int8 => "int8",
        PrimType::Int16 => "int16",
        PrimType::Int32 => "int32",
        PrimType::Int64 => "int64",
        PrimType::Uint8 => "uint8",
        PrimType::Uint16 => "uint16",
        PrimType::Uint32 => "uint32",
        PrimType::Uint64 => "uint64",
        PrimType::Float32 => "float32",
        PrimType::Float64 => "float64",
    }
}

impl Ir {
    /// Renders a deterministic textual form of the IR (for goldens and
    /// diffing). Declaration order is preserved; nothing environment-derived
    /// appears, so the output is byte-stable across rebuilds.
    pub fn emit_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "library {}", self.library);
        for decl in &self.decls {
            match decl {
                IrDecl::Bits(b) => {
                    let _ = writeln!(out, "bits {} : {}", b.name, prim_name(b.base));
                    for (name, value) in &b.members {
                        let _ = writeln!(out, "  {name} = {value:#x}");
                    }
                }
                IrDecl::Enum(e) => {
                    let strict = if e.strict { "strict" } else { "flexible" };
                    let _ = writeln!(out, "enum {} {strict} : {}", e.name, prim_name(e.base));
                    for (name, value) in &e.members {
                        let _ = writeln!(out, "  {name} = {value}");
                    }
                }
                IrDecl::Struct(s) => {
                    let abi = if s.abi { " abi" } else { "" };
                    let _ = writeln!(
                        out,
                        "struct {}{abi} size={} align={}",
                        s.name, s.size, s.align
                    );
                    for f in &s.fields {
                        let _ = writeln!(
                            out,
                            "  {}: {} @{} size={}",
                            f.name,
                            f.ty.render(),
                            f.offset,
                            f.size
                        );
                    }
                }
                IrDecl::Table(t) => {
                    let _ = writeln!(out, "table {}", t.name);
                    for m in &t.members {
                        emit_ordinal(&mut out, m);
                    }
                }
                IrDecl::Union(u) => {
                    let strict = if u.strict { "strict" } else { "flexible" };
                    let _ = writeln!(out, "union {} {strict}", u.name);
                    for m in &u.members {
                        emit_ordinal(&mut out, m);
                    }
                }
                IrDecl::Protocol(p) => {
                    let _ = writeln!(out, "protocol {} id={:#018x}", p.name, p.interface_id);
                    for m in &p.methods {
                        let payloads = match &m.kind {
                            IrMethodKind::Call { request, response } => {
                                format!(
                                    "({}) -> ({})",
                                    payload_text(request),
                                    payload_text(response)
                                )
                            }
                            IrMethodKind::OneWay { request } => {
                                format!("({})", payload_text(request))
                            }
                            IrMethodKind::Event { payload } => {
                                format!("({})", payload_text(payload))
                            }
                            IrMethodKind::Reserved => String::new(),
                        };
                        let _ = writeln!(
                            out,
                            "  {}: {} {}{payloads}",
                            m.ordinal,
                            m.kind.label(),
                            m.name
                        );
                    }
                }
            }
        }
        out
    }
}

fn payload_text(p: &IrPayload) -> &str {
    p.type_name().unwrap_or("")
}

fn emit_ordinal(out: &mut String, m: &IrOrdinalMember) {
    match (&m.field, &m.ty) {
        (Some(name), Some(ty)) => {
            let _ = writeln!(out, "  {}: {name}: {}", m.ordinal, ty.render());
        }
        // A named member always carries a type once lowering runs; the
        // type-less arm keeps `emit_text` total rather than panicking.
        (Some(name), None) => {
            let _ = writeln!(out, "  {}: {name}", m.ordinal);
        }
        _ => {
            let _ = writeln!(out, "  {}: reserved", m.ordinal);
        }
    }
}
