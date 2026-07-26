// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Resolution, rule enforcement, and lowering to the compiled IR. Every
//! normative rule the ISL applies to a single schema is checked here, each
//! with a stable `ISLxxxx` code: name resolution, ordinal add-only/no-reuse,
//! required bounds, frozen inline structs, the syscall ABI subset with the
//! mandatory header, handle rights from the catalog, data-class validation,
//! and a warning for `share`-mode fields.
//!
//! Cross-version rules (frozen-struct diffing, permanently-reserved ordinals)
//! need a prior-release baseline and land with the ABI-diff tool (deviation
//! D10); within one schema, a reused ordinal is caught here.
//!
//! Normative: docs/api/03-interface-schema-language.md,
//! docs/api/01-system-call-interface.md ("Structured Arguments"),
//! docs/security/01-security-model.md ("Data Classification", "Rights")

use crate::ast::*;
use crate::diag::{Code, Diagnostics, Span};
use crate::ir::*;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Core rights vocabulary (docs/security/01, "Rights"). Object-class rights
/// are added as those object types land; a right outside this set is a finding.
const RIGHTS: &[&str] = &[
    "READ",
    "WRITE",
    "MAP",
    "EXECUTE",
    "SIGNAL",
    "WAIT",
    "DUPLICATE",
    "TRANSFER",
    "CONFIGURE",
    "BIND",
    "ADMIN",
];

/// The nine normative data-classification classes (docs/security/01,
/// "Data Classification"). Schemas may annotate only these.
const DATA_CLASSES: &[&str] = &[
    "Public",
    "UserPrivate",
    "SensitivePersonal",
    "Health",
    "Biometric",
    "Credentials",
    "EnterpriseConfidential",
    "ProtectedMedia",
    "AiPersonalContext",
];

/// What a declared name refers to, for resolving type references.
#[derive(Clone, Copy)]
enum SymKind {
    Enum(PrimType),
    Bits(PrimType),
    Struct,
    Table,
    Union,
    Protocol,
}

/// Checks `schema`, returning the compiled IR when there are no errors
/// (warnings do not block) plus every diagnostic produced.
pub fn check(schema: &Schema) -> (Option<Ir>, Diagnostics) {
    let mut cx = Checker {
        library: schema.library.clone(),
        symbols: HashMap::new(),
        struct_layout: BTreeMap::new(),
        synthesized: Vec::new(),
        diags: Diagnostics::new(),
    };
    cx.build_symbols(schema);
    let decls = cx.check_and_lower(schema);
    let ir = if cx.diags.has_errors() {
        None
    } else {
        Some(Ir {
            library: schema.library.clone(),
            decls,
        })
    };
    (ir, cx.diags)
}

struct Checker {
    library: String,
    symbols: HashMap<String, SymKind>,
    /// Sizes/alignments of structs already lowered, for nested-struct layout.
    struct_layout: BTreeMap<String, (usize, usize)>,
    /// Types synthesized from inline method payloads, appended to the IR so
    /// codegen emits them like any other declaration.
    synthesized: Vec<IrDecl>,
    diags: Diagnostics,
}

impl Checker {
    fn build_symbols(&mut self, schema: &Schema) {
        for decl in &schema.decls {
            let kind = match decl {
                Decl::Enum(d) => SymKind::Enum(d.base),
                Decl::Bits(d) => SymKind::Bits(d.base),
                Decl::Struct(_) => SymKind::Struct,
                Decl::Table(_) => SymKind::Table,
                Decl::Union(_) => SymKind::Union,
                Decl::Protocol(_) => SymKind::Protocol,
            };
            if self.symbols.insert(decl.name().to_owned(), kind).is_some() {
                self.diags.error(
                    Code::DuplicateName,
                    decl.name_span(),
                    format!("duplicate declaration `{}`", decl.name()),
                );
            }
        }
    }

    fn check_and_lower(&mut self, schema: &Schema) -> Vec<IrDecl> {
        let mut out = Vec::new();
        for decl in &schema.decls {
            match decl {
                Decl::Bits(d) => out.push(IrDecl::Bits(self.lower_bits(d))),
                Decl::Enum(d) => out.push(IrDecl::Enum(self.lower_enum(d))),
                Decl::Struct(d) => out.push(IrDecl::Struct(self.lower_struct(d))),
                Decl::Table(d) => out.push(IrDecl::Table(self.lower_table(d))),
                Decl::Union(d) => out.push(IrDecl::Union(self.lower_union(d))),
                Decl::Protocol(d) => out.push(IrDecl::Protocol(self.lower_protocol(d))),
            }
        }
        // Types synthesized from inline method payloads. Rust item order is
        // irrelevant, so appending is fine; the protocol dispatch above
        // references them by name.
        out.append(&mut self.synthesized);
        out
    }

    // --- bits / enum ---

    fn lower_bits(&mut self, d: &BitsDecl) -> IrBits {
        if !d.base.is_unsigned() {
            self.diags.error(
                Code::InvalidBaseType,
                d.base_span,
                "bits base must be an unsigned integer",
            );
        }
        self.check_unique_member_names(d.members.iter().map(|m| (&m.name, m.name_span)));
        IrBits {
            name: d.name.clone(),
            base: d.base,
            members: d
                .members
                .iter()
                .map(|m| (m.name.clone(), m.value))
                .collect(),
        }
    }

    fn lower_enum(&mut self, d: &EnumDecl) -> IrEnum {
        if matches!(
            d.base,
            PrimType::Bool | PrimType::Float32 | PrimType::Float64
        ) {
            self.diags.error(
                Code::InvalidBaseType,
                d.base_span,
                "enum base must be an integer type",
            );
        }
        self.check_unique_member_names(d.members.iter().map(|m| (&m.name, m.name_span)));
        IrEnum {
            name: d.name.clone(),
            strict: matches!(d.strictness, Strictness::Strict),
            base: d.base,
            members: d
                .members
                .iter()
                .map(|m| (m.name.clone(), m.value))
                .collect(),
        }
    }

    // --- struct ---

    fn lower_struct(&mut self, d: &StructDecl) -> IrStruct {
        self.check_unique_field_names(d.fields.iter());
        if d.abi {
            self.check_abi_header(d);
        }

        let mut fields = Vec::new();
        let mut cursor = 0usize;
        let mut align = 1usize;
        for field in &d.fields {
            if field.optional {
                self.diags.error(
                    Code::OptionalStructField,
                    field.name_span,
                    "frozen struct fields cannot be optional",
                );
            }
            let Some(ty) = self.resolve_inline_type(&field.ty) else {
                continue;
            };
            let fsize = ty.size(&self.struct_layout);
            let falign = ty.align(&self.struct_layout);
            let offset = align_up(cursor, falign.max(1));
            cursor = offset + fsize;
            align = align.max(falign);
            fields.push(IrField {
                name: field.name.clone(),
                ty,
                offset,
                size: fsize,
            });
        }
        // The whole message is 8-byte aligned; a struct's own alignment is the
        // max of its fields, capped at 8.
        let struct_align = align.clamp(1, 8);
        let size = align_up(cursor, struct_align.max(1));
        self.struct_layout
            .insert(d.name.clone(), (size, struct_align));
        IrStruct {
            name: d.name.clone(),
            abi: d.abi,
            size,
            align: struct_align,
            fields,
        }
    }

    /// Checks the mandatory `size: uint32`, `version: uint32`, `flags: uint64`
    /// leading header of a syscall ABI struct (docs/api/01, "Structured
    /// Arguments").
    fn check_abi_header(&mut self, d: &StructDecl) {
        let expected: [(&str, PrimType); 3] = [
            ("size", PrimType::Uint32),
            ("version", PrimType::Uint32),
            ("flags", PrimType::Uint64),
        ];
        let ok = d.fields.len() >= 3
            && expected.iter().enumerate().all(|(i, (name, prim))| {
                d.fields[i].name == *name && matches!(&d.fields[i].ty, Type::Prim(p) if p == prim)
            });
        if !ok {
            self.diags.error(
                Code::MissingAbiHeader,
                d.name_span,
                "@abi struct must begin with `size: uint32; version: uint32; flags: uint64;`",
            );
        }
    }

    /// Resolves a struct field's type to an inline `IrFieldType`, reporting a
    /// diagnostic (and returning `None`) for anything outside the frozen inline
    /// subset. Handle rights are validated here.
    /// Lowers one table/union member, carrying its resolved type into the IR.
    /// Well-formedness (bounds, rights, data class) was already validated by
    /// `check_record_fields`, so this pass emits no diagnostics — it only
    /// extracts the type wire codegen needs.
    fn lower_ordinal_member(&self, m: &OrdinalMember) -> IrOrdinalMember {
        match &m.kind {
            OrdinalKind::Field(f) => IrOrdinalMember {
                ordinal: m.ordinal,
                field: Some(f.name.clone()),
                ty: self.member_field_type(&f.ty),
            },
            OrdinalKind::Reserved => IrOrdinalMember {
                ordinal: m.ordinal,
                field: None,
                ty: None,
            },
        }
    }

    /// The inline-subset type of a table/union member, or `None` for an
    /// out-of-line type (`string`/`vector`/nested `table`/`union`). Unlike
    /// [`resolve_inline_type`](Self::resolve_inline_type), which rejects
    /// out-of-line types as frozen-struct errors, out-of-line member types are
    /// legal here — `None` merely signals that their wire codegen is still
    /// deferred (D10), which the emitter turns into a loud marker rather than
    /// silent mis-generation.
    fn member_field_type(&self, ty: &Type) -> Option<IrFieldType> {
        match ty {
            Type::Prim(p) => Some(IrFieldType::Prim(*p)),
            Type::Array(elem, len, _) => Some(IrFieldType::Array {
                elem: Box::new(self.member_field_type(elem)?),
                len: *len,
            }),
            Type::Handle(_) => Some(IrFieldType::Handle),
            Type::Named(name, _) => match self.symbols.get(name) {
                Some(SymKind::Enum(base)) => Some(IrFieldType::Enum {
                    name: name.clone(),
                    base: *base,
                }),
                Some(SymKind::Bits(base)) => Some(IrFieldType::Bits {
                    name: name.clone(),
                    base: *base,
                }),
                Some(SymKind::Struct) => Some(IrFieldType::Struct { name: name.clone() }),
                // A nested table/union field, or an unknown type already
                // diagnosed by `check_record_fields`: out-of-line, deferred.
                _ => None,
            },
            // `string:N` — the bound is guaranteed present by
            // `check_type_wellformed` (unbounded is an error); default to 0 if
            // somehow absent so this stays total.
            Type::StringT(bound, _) => Some(IrFieldType::String {
                max: bound.unwrap_or(0),
            }),
            // `vector<T>:N` of an inline element. A vector of an out-of-line
            // element (string/vector/nested table/union) stays deferred: the
            // recursive resolve returns `None` and so does this.
            Type::Vector(elem, bound, _) => Some(IrFieldType::Vector {
                elem: Box::new(self.member_field_type(elem)?),
                max: bound.unwrap_or(0),
            }),
        }
    }

    fn resolve_inline_type(&mut self, ty: &Type) -> Option<IrFieldType> {
        match ty {
            Type::Prim(p) => Some(IrFieldType::Prim(*p)),
            Type::Array(elem, len, _) => {
                let inner = self.resolve_inline_type(elem)?;
                Some(IrFieldType::Array {
                    elem: Box::new(inner),
                    len: *len,
                })
            }
            Type::Handle(h) => {
                self.check_rights(&h.rights, h.span);
                Some(IrFieldType::Handle)
            }
            Type::Named(name, span) => match self.symbols.get(name) {
                Some(SymKind::Enum(base)) => Some(IrFieldType::Enum {
                    name: name.clone(),
                    base: *base,
                }),
                Some(SymKind::Bits(base)) => Some(IrFieldType::Bits {
                    name: name.clone(),
                    base: *base,
                }),
                Some(SymKind::Struct) => {
                    if !self.struct_layout.contains_key(name) {
                        self.diags.error(
                            Code::ForwardStructRef,
                            *span,
                            format!("nested struct `{name}` must be declared before use"),
                        );
                    }
                    Some(IrFieldType::Struct { name: name.clone() })
                }
                Some(_) => {
                    self.diags.error(
                        Code::AbiSubsetViolation,
                        *span,
                        format!("frozen struct field cannot hold `{name}` (a table or union)"),
                    );
                    None
                }
                None => {
                    self.diags
                        .error(Code::UnknownType, *span, format!("unknown type `{name}`"));
                    None
                }
            },
            Type::Vector(_, _, span) | Type::StringT(_, span) => {
                self.diags.error(
                    Code::AbiSubsetViolation,
                    *span,
                    "frozen struct fields must be inline; use a table for out-of-line data",
                );
                None
            }
        }
    }

    // --- table / union / protocol ---

    fn lower_table(&mut self, d: &TableDecl) -> IrTable {
        self.check_ordinals(d.members.iter().map(|m| (m.ordinal, m.ordinal_span)));
        self.check_record_fields(&d.members);
        let members = d
            .members
            .iter()
            .map(|m| self.lower_ordinal_member(m))
            .collect();
        IrTable {
            name: d.name.clone(),
            members,
        }
    }

    fn lower_union(&mut self, d: &UnionDecl) -> IrUnion {
        self.check_ordinals(d.members.iter().map(|m| (m.ordinal, m.ordinal_span)));
        self.check_record_fields(&d.members);
        let members = d
            .members
            .iter()
            .map(|m| self.lower_ordinal_member(m))
            .collect();
        IrUnion {
            name: d.name.clone(),
            strict: matches!(d.strictness, Strictness::Strict),
            members,
        }
    }

    /// Checks the fields of a table/union: type resolution, bounds, handle
    /// rights, data classes, and the share-mode warning. These are out-of-line
    /// capable, so vector/string/named types are allowed (wire codegen is
    /// deferred, D10) — only their well-formedness is checked.
    fn check_record_fields(&mut self, members: &[OrdinalMember]) {
        for member in members {
            if let OrdinalKind::Field(field) = &member.kind {
                self.check_field_wellformed(field);
            }
        }
    }

    fn check_field_wellformed(&mut self, field: &Field) {
        self.check_type_wellformed(&field.ty);
        if let Some(class) = &field.data_class
            && !DATA_CLASSES.contains(&class.as_str())
        {
            self.diags.error(
                Code::UnknownDataClass,
                field.name_span,
                format!("unknown data class `{class}`"),
            );
        }
        if field.ownership == Some(Ownership::Share) {
            self.diags.warn(
                Code::ShareInValidateThenUse,
                field.name_span,
                "`share`-mode field may be mutated after validation (validate-then-use race)",
            );
        }
    }

    /// Checks a type used in a table/union/payload: named types resolve,
    /// vectors/strings are bounded, handle rights are known.
    fn check_type_wellformed(&mut self, ty: &Type) {
        match ty {
            Type::Prim(_) => {}
            Type::Array(elem, _, _) => self.check_type_wellformed(elem),
            Type::Vector(elem, bound, span) => {
                if bound.is_none() {
                    self.diags.error(
                        Code::UnboundedVector,
                        *span,
                        "vector must declare a maximum length (`vector<T>:N`)",
                    );
                }
                self.check_type_wellformed(elem);
            }
            Type::StringT(bound, span) => {
                if bound.is_none() {
                    self.diags.error(
                        Code::UnboundedVector,
                        *span,
                        "string must declare a maximum length (`string:N`)",
                    );
                }
            }
            Type::Handle(h) => self.check_rights(&h.rights, h.span),
            Type::Named(name, span) => {
                if !self.symbols.contains_key(name) {
                    self.diags
                        .error(Code::UnknownType, *span, format!("unknown type `{name}`"));
                }
            }
        }
    }

    fn lower_protocol(&mut self, d: &ProtocolDecl) -> IrProtocol {
        self.check_ordinals(d.methods.iter().map(|m| (m.ordinal, m.ordinal_span)));
        let mut names = HashSet::new();
        for method in &d.methods {
            if let Some(name) = method_name(&method.kind)
                && !names.insert(name.to_owned())
            {
                self.diags.error(
                    Code::DuplicateName,
                    method.ordinal_span,
                    format!("duplicate method `{name}`"),
                );
            }
            self.check_method_payloads(&method.kind);
        }
        // Interface ID from the fully-qualified name at major version 1 (v0
        // default; per-protocol major versioning lands with negotiation).
        let fqname = format!("{}.{}", self.library, d.name);
        let methods = d
            .methods
            .iter()
            .map(|m| self.lower_method(&d.name, m))
            .collect();
        IrProtocol {
            name: d.name.clone(),
            interface_id: crate::ifaceid::interface_id(&fqname, 1),
            methods,
        }
    }

    fn lower_method(&mut self, protocol: &str, m: &Method) -> IrMethod {
        use crate::ir::IrMethodKind;
        let (name, kind) = match &m.kind {
            MethodKind::Call {
                name,
                request,
                response,
                ..
            } => (
                name.clone(),
                IrMethodKind::Call {
                    request: self.lower_payload(protocol, name, "Request", request),
                    response: self.lower_payload(protocol, name, "Response", response),
                },
            ),
            MethodKind::OneWay { name, request, .. } => (
                name.clone(),
                IrMethodKind::OneWay {
                    request: self.lower_payload(protocol, name, "Request", request),
                },
            ),
            MethodKind::Event { name, payload, .. } => (
                name.clone(),
                IrMethodKind::Event {
                    payload: self.lower_payload(protocol, name, "Event", payload),
                },
            ),
            MethodKind::Reserved => (String::new(), IrMethodKind::Reserved),
        };
        IrMethod {
            ordinal: m.ordinal,
            name,
            kind,
        }
    }

    /// Resolves a method payload to the type the dispatch references. A named
    /// payload is used directly; an inline `struct`/`table` is synthesized into
    /// a named type `{Protocol}{Method}{Role}` and appended to the IR so
    /// codegen emits it like any declared type.
    fn lower_payload(
        &mut self,
        protocol: &str,
        method: &str,
        role: &str,
        payload: &Payload,
    ) -> IrPayload {
        match payload {
            Payload::Empty => IrPayload::Empty,
            Payload::Named(name, _) => IrPayload::Type(name.clone()),
            Payload::Struct(fields) => {
                let name = format!("{protocol}{method}{role}");
                let synthetic = StructDecl {
                    name: name.clone(),
                    name_span: Span::point(0),
                    abi: false,
                    fields: fields.clone(),
                    availability: Availability::default(),
                };
                let ir = self.lower_struct(&synthetic);
                self.synthesized.push(IrDecl::Struct(ir));
                IrPayload::Type(name)
            }
            Payload::Table(members) => {
                let name = format!("{protocol}{method}{role}");
                let ir = IrTable {
                    name: name.clone(),
                    members: members
                        .iter()
                        .map(|m| self.lower_ordinal_member(m))
                        .collect(),
                };
                self.synthesized.push(IrDecl::Table(ir));
                IrPayload::Type(name)
            }
        }
    }

    fn check_method_payloads(&mut self, kind: &MethodKind) {
        let payloads: Vec<&Payload> = match kind {
            MethodKind::Call {
                request, response, ..
            } => vec![request, response],
            MethodKind::OneWay { request, .. } => vec![request],
            MethodKind::Event { payload, .. } => vec![payload],
            MethodKind::Reserved => vec![],
        };
        for payload in payloads {
            match payload {
                Payload::Empty => {}
                Payload::Named(name, span) => {
                    if !self.symbols.contains_key(name) {
                        self.diags.error(
                            Code::UnknownType,
                            *span,
                            format!("unknown payload type `{name}`"),
                        );
                    }
                }
                Payload::Struct(fields) => {
                    for f in fields {
                        self.check_field_wellformed(f);
                    }
                }
                Payload::Table(members) => self.check_record_fields(members),
            }
        }
    }

    // --- shared helpers ---

    fn check_rights(&mut self, rights: &[String], span: Span) {
        for right in rights {
            if !RIGHTS.contains(&right.as_str()) {
                self.diags.error(
                    Code::UnknownRights,
                    span,
                    format!("unknown right `{right}`"),
                );
            }
        }
    }

    fn check_ordinals(&mut self, ordinals: impl Iterator<Item = (u64, Span)>) {
        let mut seen = HashSet::new();
        for (ordinal, span) in ordinals {
            if !seen.insert(ordinal) {
                self.diags.error(
                    Code::OrdinalReused,
                    span,
                    format!("ordinal {ordinal} is reused; ordinals are add-only and never reused"),
                );
            }
        }
    }

    fn check_unique_member_names<'a>(&mut self, names: impl Iterator<Item = (&'a String, Span)>) {
        let mut seen = HashSet::new();
        for (name, span) in names {
            if !seen.insert(name.clone()) {
                self.diags.error(
                    Code::DuplicateMember,
                    span,
                    format!("duplicate member `{name}`"),
                );
            }
        }
    }

    fn check_unique_field_names<'a>(&mut self, fields: impl Iterator<Item = &'a Field>) {
        let mut seen = HashSet::new();
        for field in fields {
            if !seen.insert(field.name.clone()) {
                self.diags.error(
                    Code::DuplicateMember,
                    field.name_span,
                    format!("duplicate field `{}`", field.name),
                );
            }
        }
    }
}

fn method_name(kind: &MethodKind) -> Option<&str> {
    match kind {
        MethodKind::Call { name, .. }
        | MethodKind::OneWay { name, .. }
        | MethodKind::Event { name, .. } => Some(name),
        MethodKind::Reserved => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::compile;
    use crate::diag::Code;

    /// Compiles and requires success (no error diagnostics), returning the IR
    /// text.
    fn ir_text(src: &str) -> String {
        let (ir, diags) = compile(src);
        assert!(!diags.has_errors(), "unexpected errors: {diags:?}");
        ir.expect("ir").emit_text()
    }

    /// Compiles and requires an error carrying `code`.
    fn expect_error(src: &str, code: Code) {
        let (ir, diags) = compile(src);
        assert!(diags.has(code), "expected {}, got: {diags:?}", code.label());
        assert!(ir.is_none(), "IR should be withheld on error");
    }

    const ABI: &str = "library t.abi;\n\
        bits Rights : uint64 { READ = 0x1; DUPLICATE = 0x4; };\n\
        @abi\n\
        struct DupArgs {\n\
          size: uint32;\n\
          version: uint32;\n\
          flags: uint64;\n\
          handle: handle<Object, {DUPLICATE}>;\n\
          new_rights: Rights;\n\
          reserved: array<uint8, 4>;\n\
        };\n";

    #[test]
    fn frozen_abi_struct_layout_is_canonical() {
        let expected = "library t.abi\n\
            bits Rights : uint64\n\
            \x20\x20READ = 0x1\n\
            \x20\x20DUPLICATE = 0x4\n\
            struct DupArgs abi size=40 align=8\n\
            \x20\x20size: uint32 @0 size=4\n\
            \x20\x20version: uint32 @4 size=4\n\
            \x20\x20flags: uint64 @8 size=8\n\
            \x20\x20handle: handle @16 size=4\n\
            \x20\x20new_rights: bits Rights @24 size=8\n\
            \x20\x20reserved: array<uint8, 4> @32 size=4\n";
        assert_eq!(ir_text(ABI), expected);
    }

    #[test]
    fn emit_text_is_deterministic() {
        assert_eq!(ir_text(ABI), ir_text(ABI));
    }

    #[test]
    fn ordinal_reuse_is_rejected() {
        expect_error(
            "library t.o;\n\
             table T { 1: a: uint32; 1: b: uint32; };\n",
            Code::OrdinalReused,
        );
    }

    #[test]
    fn unbounded_vector_and_string_are_rejected() {
        expect_error(
            "library t.v;\n\
             table T { 1: items: vector<uint32>; };\n",
            Code::UnboundedVector,
        );
        expect_error(
            "library t.s;\n\
             table T { 1: name: string; };\n",
            Code::UnboundedVector,
        );
    }

    #[test]
    fn abi_subset_violation_is_rejected() {
        // A struct may not hold an out-of-line vector.
        expect_error(
            "library t.a;\n\
             struct S { data: vector<uint8>:16; };\n",
            Code::AbiSubsetViolation,
        );
    }

    #[test]
    fn missing_abi_header_is_rejected() {
        expect_error(
            "library t.h;\n\
             @abi struct S { x: uint32; };\n",
            Code::MissingAbiHeader,
        );
    }

    #[test]
    fn unknown_type_rights_and_data_class_are_rejected() {
        expect_error(
            "library t.t;\n\
             struct S { f: Nope; };\n",
            Code::UnknownType,
        );
        expect_error(
            "library t.r;\n\
             struct S { h: handle<Object, {BOGUS}>; };\n",
            Code::UnknownRights,
        );
        expect_error(
            "library t.d;\n\
             table T { 1: @data_class(Nonexistent) x: uint32; };\n",
            Code::UnknownDataClass,
        );
    }

    #[test]
    fn duplicate_names_and_bad_base_are_rejected() {
        expect_error(
            "library t.dup;\n\
             struct A { x: uint32; };\n\
             struct A { y: uint32; };\n",
            Code::DuplicateName,
        );
        expect_error(
            "library t.b;\n\
             bits B : int32 { X = 1; };\n",
            Code::InvalidBaseType,
        );
    }

    #[test]
    fn share_mode_is_a_warning_not_an_error() {
        let src = "library t.sh;\n\
                   table T { 1: buf: share vector<uint8>:64; };\n";
        let (ir, diags) = compile(src);
        assert!(diags.has(Code::ShareInValidateThenUse));
        assert!(!diags.has_errors(), "share-mode is only a warning");
        assert!(ir.is_some(), "a warning still yields IR");
    }

    #[test]
    fn protocol_interface_ids_and_methods_compile() {
        let text = ir_text(
            "library t.svc;\n\
             protocol Echo {\n\
               1: Echo(struct { x: uint32; }) -> (struct { y: uint32; });\n\
               2: -> OnPing(struct { seq: uint64; });\n\
               3: reserved;\n\
             };\n",
        );
        assert!(text.contains("protocol Echo"));
        assert!(text.contains("1: call Echo"));
        assert!(text.contains("2: event OnPing"));
        assert!(text.contains("3: reserved"));
    }
}
