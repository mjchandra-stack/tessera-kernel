// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Recursive-descent parser: token stream to [`Schema`] AST. Errors are
//! accumulated `Diagnostic`s (never panics); on a malformed declaration the
//! parser recovers by skipping to the next declaration boundary, so one run
//! reports many problems. Every loop makes progress, so parsing always
//! terminates on arbitrary input.
//!
//! Normative: docs/api/03-interface-schema-language.md

use crate::ast::*;
use crate::diag::{Code, Diagnostics, Span};
use crate::lexer::tokenize;
use crate::token::{Kw, Token, TokenKind};

/// Parses ISL source into a schema (when a library header was found) plus all
/// diagnostics from lexing and parsing.
pub fn parse(src: &str) -> (Option<Schema>, Diagnostics) {
    let (tokens, diags) = tokenize(src);
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        diags,
    };
    let schema = parser.parse_schema();
    (schema, parser.diags)
}

#[derive(Default)]
struct Annotations {
    availability: Availability,
    data_class: Option<String>,
    abi: bool,
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    diags: Diagnostics,
}

/// Bail out of the current production; a diagnostic was already recorded.
type PResult<T> = Result<T, ()>;

impl Parser<'_> {
    fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn span(&self) -> Span {
        self.tokens[self.pos].span
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
    }

    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.peek() == kind {
            self.advance();
            true
        } else {
            false
        }
    }

    fn eat_kw(&mut self, kw: Kw) -> bool {
        self.eat(&TokenKind::Keyword(kw))
    }

    fn error(&mut self, code: Code, message: impl Into<String>) {
        let span = self.span();
        self.diags.error(code, span, message);
    }

    fn expect(&mut self, kind: &TokenKind, what: &str) -> PResult<()> {
        if self.eat(kind) {
            Ok(())
        } else {
            let code = if self.at_eof() {
                Code::UnexpectedEof
            } else {
                Code::UnexpectedToken
            };
            self.error(code, format!("expected {what}"));
            Err(())
        }
    }

    /// Accepts an identifier, or a keyword used as a name (so field or member
    /// names may spell `handle`, `string`, etc.).
    fn expect_name(&mut self) -> PResult<(String, Span)> {
        match self.peek() {
            TokenKind::Ident(name) => {
                let out = (name.clone(), self.span());
                self.advance();
                Ok(out)
            }
            TokenKind::Keyword(kw) => {
                let out = (kw.spelling().to_owned(), self.span());
                self.advance();
                Ok(out)
            }
            _ => {
                self.error(Code::ExpectedName, "expected a name");
                Err(())
            }
        }
    }

    fn expect_int(&mut self) -> PResult<(u64, Span)> {
        if let TokenKind::Int(value) = *self.peek() {
            let span = self.span();
            self.advance();
            Ok((value, span))
        } else {
            self.error(Code::UnexpectedToken, "expected an integer");
            Err(())
        }
    }

    // --- top level ---

    fn parse_schema(&mut self) -> Option<Schema> {
        let (library, library_span) = match self.parse_library_header() {
            Ok(v) => v,
            Err(()) => (String::new(), Span::point(0)),
        };
        let mut decls = Vec::new();
        while !self.at_eof() {
            match self.parse_decl() {
                Ok(decl) => decls.push(decl),
                Err(()) => self.recover(),
            }
        }
        Some(Schema {
            library,
            library_span,
            decls,
        })
    }

    fn parse_library_header(&mut self) -> PResult<(String, Span)> {
        self.expect(&TokenKind::Keyword(Kw::Library), "`library`")?;
        let start = self.span();
        let (mut name, _) = self.expect_name()?;
        while self.eat(&TokenKind::Dot) {
            let (part, _) = self.expect_name()?;
            name.push('.');
            name.push_str(&part);
        }
        let span = Span::new(start.start, self.span().start);
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok((name, span))
    }

    /// Skips tokens to the next declaration boundary so parsing can continue.
    /// Always advances at least one token, guaranteeing progress.
    fn recover(&mut self) {
        if self.at_eof() {
            return;
        }
        self.advance();
        let mut depth: i32 = 0;
        loop {
            match self.peek() {
                TokenKind::Eof => return,
                TokenKind::LBrace => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::RBrace => {
                    if depth == 0 {
                        self.advance();
                        self.eat(&TokenKind::Semi);
                        return;
                    }
                    depth -= 1;
                    self.advance();
                }
                _ if depth == 0 && self.at_decl_start() => return,
                _ => self.advance(),
            }
        }
    }

    fn at_decl_start(&self) -> bool {
        matches!(
            self.peek(),
            TokenKind::At
                | TokenKind::Keyword(
                    Kw::Bits
                        | Kw::Enum
                        | Kw::Struct
                        | Kw::Table
                        | Kw::Union
                        | Kw::Protocol
                        | Kw::Strict
                        | Kw::Flexible
                )
        )
    }

    // --- declarations ---

    fn parse_decl(&mut self) -> PResult<Decl> {
        let annotations = self.parse_annotations()?;
        let strictness = self.parse_optional_strictness();
        match *self.peek() {
            TokenKind::Keyword(Kw::Bits) => {
                self.reject_strictness(strictness, "bits");
                self.parse_bits(annotations.availability).map(Decl::Bits)
            }
            TokenKind::Keyword(Kw::Enum) => self
                .parse_enum(annotations.availability, strictness)
                .map(Decl::Enum),
            TokenKind::Keyword(Kw::Struct) => {
                self.reject_strictness(strictness, "struct");
                self.parse_struct(annotations.availability, annotations.abi)
                    .map(Decl::Struct)
            }
            TokenKind::Keyword(Kw::Table) => {
                self.reject_strictness(strictness, "table");
                self.parse_table(annotations.availability).map(Decl::Table)
            }
            TokenKind::Keyword(Kw::Union) => self
                .parse_union(annotations.availability, strictness)
                .map(Decl::Union),
            TokenKind::Keyword(Kw::Protocol) => {
                self.reject_strictness(strictness, "protocol");
                self.parse_protocol(annotations.availability)
                    .map(Decl::Protocol)
            }
            _ => {
                self.error(Code::UnexpectedToken, "expected a declaration");
                Err(())
            }
        }
    }

    fn parse_optional_strictness(&mut self) -> Option<Strictness> {
        if self.eat_kw(Kw::Strict) {
            Some(Strictness::Strict)
        } else if self.eat_kw(Kw::Flexible) {
            Some(Strictness::Flexible)
        } else {
            None
        }
    }

    fn reject_strictness(&mut self, strictness: Option<Strictness>, what: &str) {
        if strictness.is_some() {
            self.error(
                Code::UnexpectedToken,
                format!("`{what}` cannot be declared strict or flexible"),
            );
        }
    }

    fn parse_bits(&mut self, availability: Availability) -> PResult<BitsDecl> {
        self.expect(&TokenKind::Keyword(Kw::Bits), "`bits`")?;
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let (base, base_span) = self.parse_prim_type()?;
        let members = self.parse_value_members()?;
        Ok(BitsDecl {
            name,
            name_span,
            base,
            base_span,
            members,
            availability,
        })
    }

    fn parse_enum(
        &mut self,
        availability: Availability,
        strictness: Option<Strictness>,
    ) -> PResult<EnumDecl> {
        self.expect(&TokenKind::Keyword(Kw::Enum), "`enum`")?;
        let strictness = self.require_strictness(strictness, "enum");
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let (base, base_span) = self.parse_prim_type()?;
        let members = self.parse_value_members()?;
        Ok(EnumDecl {
            name,
            name_span,
            strictness,
            base,
            base_span,
            members,
            availability,
        })
    }

    fn require_strictness(&mut self, strictness: Option<Strictness>, what: &str) -> Strictness {
        strictness.unwrap_or_else(|| {
            self.error(
                Code::UnexpectedToken,
                format!("`{what}` must be declared `strict` or `flexible`"),
            );
            Strictness::Strict
        })
    }

    fn parse_value_members(&mut self) -> PResult<Vec<ValueMember>> {
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut members = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated member list");
                return Err(());
            }
            let (name, name_span) = self.expect_name()?;
            self.expect(&TokenKind::Eq, "`=`")?;
            let (value, _) = self.expect_int()?;
            self.expect(&TokenKind::Semi, "`;`")?;
            members.push(ValueMember {
                name,
                name_span,
                value,
            });
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(members)
    }

    fn parse_struct(&mut self, availability: Availability, abi: bool) -> PResult<StructDecl> {
        self.expect(&TokenKind::Keyword(Kw::Struct), "`struct`")?;
        let (name, name_span) = self.expect_name()?;
        let fields = self.parse_field_block()?;
        Ok(StructDecl {
            name,
            name_span,
            abi,
            fields,
            availability,
        })
    }

    fn parse_field_block(&mut self) -> PResult<Vec<Field>> {
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated field list");
                return Err(());
            }
            let annotations = self.parse_annotations()?;
            fields.push(self.parse_field_body(annotations)?);
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(fields)
    }

    fn parse_field_body(&mut self, annotations: Annotations) -> PResult<Field> {
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let ownership = self.parse_optional_ownership();
        let ty = self.parse_type()?;
        let optional = self.eat(&TokenKind::Question);
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(Field {
            name,
            name_span,
            ty,
            optional,
            ownership,
            data_class: annotations.data_class,
            availability: annotations.availability,
        })
    }

    fn parse_optional_ownership(&mut self) -> Option<Ownership> {
        if self.eat_kw(Kw::Transfer) {
            Some(Ownership::Transfer)
        } else if self.eat_kw(Kw::Share) {
            Some(Ownership::Share)
        } else if self.eat_kw(Kw::Snapshot) {
            Some(Ownership::Snapshot)
        } else {
            None
        }
    }

    fn parse_table(&mut self, availability: Availability) -> PResult<TableDecl> {
        self.expect(&TokenKind::Keyword(Kw::Table), "`table`")?;
        let (name, name_span) = self.expect_name()?;
        let members = self.parse_ordinal_block()?;
        Ok(TableDecl {
            name,
            name_span,
            members,
            availability,
        })
    }

    fn parse_union(
        &mut self,
        availability: Availability,
        strictness: Option<Strictness>,
    ) -> PResult<UnionDecl> {
        self.expect(&TokenKind::Keyword(Kw::Union), "`union`")?;
        let strictness = self.require_strictness(strictness, "union");
        let (name, name_span) = self.expect_name()?;
        let members = self.parse_ordinal_block()?;
        Ok(UnionDecl {
            name,
            name_span,
            strictness,
            members,
            availability,
        })
    }

    fn parse_ordinal_block(&mut self) -> PResult<Vec<OrdinalMember>> {
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut members = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated member list");
                return Err(());
            }
            members.push(self.parse_ordinal_member()?);
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(members)
    }

    fn parse_ordinal_member(&mut self) -> PResult<OrdinalMember> {
        let (ordinal, ordinal_span) = self.expect_int()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        if self.eat_kw(Kw::Reserved) {
            self.expect(&TokenKind::Semi, "`;`")?;
            return Ok(OrdinalMember {
                ordinal,
                ordinal_span,
                kind: OrdinalKind::Reserved,
            });
        }
        // Field annotations sit between the ordinal and the field name.
        let annotations = self.parse_annotations()?;
        let field = self.parse_field_body(annotations)?;
        Ok(OrdinalMember {
            ordinal,
            ordinal_span,
            kind: OrdinalKind::Field(field),
        })
    }

    fn parse_protocol(&mut self, availability: Availability) -> PResult<ProtocolDecl> {
        self.expect(&TokenKind::Keyword(Kw::Protocol), "`protocol`")?;
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut methods = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated protocol body");
                return Err(());
            }
            methods.push(self.parse_method()?);
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(ProtocolDecl {
            name,
            name_span,
            methods,
            availability,
        })
    }

    fn parse_method(&mut self) -> PResult<Method> {
        let annotations = self.parse_annotations()?;
        let (ordinal, ordinal_span) = self.expect_int()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let kind = if self.eat_kw(Kw::Reserved) {
            self.expect(&TokenKind::Semi, "`;`")?;
            MethodKind::Reserved
        } else if self.eat(&TokenKind::Arrow) {
            // event: `-> Name(payload);`
            let (name, name_span) = self.expect_name()?;
            let payload = self.parse_payload()?;
            self.expect(&TokenKind::Semi, "`;`")?;
            MethodKind::Event {
                name,
                name_span,
                payload,
            }
        } else {
            let (name, name_span) = self.expect_name()?;
            let request = self.parse_payload()?;
            if self.eat(&TokenKind::Arrow) {
                let response = self.parse_payload()?;
                self.expect(&TokenKind::Semi, "`;`")?;
                MethodKind::Call {
                    name,
                    name_span,
                    request,
                    response,
                }
            } else {
                self.expect(&TokenKind::Semi, "`;`")?;
                MethodKind::OneWay {
                    name,
                    name_span,
                    request,
                }
            }
        };
        Ok(Method {
            ordinal,
            ordinal_span,
            availability: annotations.availability,
            kind,
        })
    }

    fn parse_payload(&mut self) -> PResult<Payload> {
        self.expect(&TokenKind::LParen, "`(`")?;
        let payload = match *self.peek() {
            TokenKind::RParen => Payload::Empty,
            TokenKind::Keyword(Kw::Struct) => {
                self.advance();
                Payload::Struct(self.parse_field_block_no_trailing_semi()?)
            }
            TokenKind::Keyword(Kw::Table) => {
                self.advance();
                Payload::Table(self.parse_ordinal_block_no_trailing_semi()?)
            }
            _ => {
                let (name, span) = self.expect_name()?;
                Payload::Named(name, span)
            }
        };
        self.expect(&TokenKind::RParen, "`)`")?;
        Ok(payload)
    }

    /// Like `parse_field_block` but without the trailing `;` (inline payload).
    fn parse_field_block_no_trailing_semi(&mut self) -> PResult<Vec<Field>> {
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut fields = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated field list");
                return Err(());
            }
            let annotations = self.parse_annotations()?;
            fields.push(self.parse_field_body(annotations)?);
        }
        Ok(fields)
    }

    fn parse_ordinal_block_no_trailing_semi(&mut self) -> PResult<Vec<OrdinalMember>> {
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut members = Vec::new();
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated member list");
                return Err(());
            }
            members.push(self.parse_ordinal_member()?);
        }
        Ok(members)
    }

    // --- types ---

    fn parse_type(&mut self) -> PResult<Type> {
        let span = self.span();
        match self.peek().clone() {
            TokenKind::Keyword(Kw::Array) => {
                self.advance();
                self.expect(&TokenKind::Lt, "`<`")?;
                let inner = self.parse_type()?;
                self.expect(&TokenKind::Comma, "`,`")?;
                let (n, _) = self.expect_int()?;
                self.expect(&TokenKind::Gt, "`>`")?;
                Ok(Type::Array(Box::new(inner), n, span))
            }
            TokenKind::Keyword(Kw::Vector) => {
                self.advance();
                self.expect(&TokenKind::Lt, "`<`")?;
                let inner = self.parse_type()?;
                self.expect(&TokenKind::Gt, "`>`")?;
                let bound = self.parse_optional_bound()?;
                Ok(Type::Vector(Box::new(inner), bound, span))
            }
            TokenKind::Keyword(Kw::StringT) => {
                self.advance();
                let bound = self.parse_optional_bound()?;
                Ok(Type::StringT(bound, span))
            }
            TokenKind::Keyword(Kw::Handle) => {
                self.advance();
                self.expect(&TokenKind::Lt, "`<`")?;
                let (object, _) = self.expect_name()?;
                self.expect(&TokenKind::Comma, "`,`")?;
                self.expect(&TokenKind::LBrace, "`{`")?;
                let mut rights = Vec::new();
                while !self.eat(&TokenKind::RBrace) {
                    if self.at_eof() {
                        self.error(Code::UnexpectedEof, "unterminated rights set");
                        return Err(());
                    }
                    let (right, _) = self.expect_name()?;
                    rights.push(right);
                    if !self.eat(&TokenKind::Comma) && self.peek() != &TokenKind::RBrace {
                        self.expect(&TokenKind::RBrace, "`}`")?;
                        break;
                    }
                }
                self.expect(&TokenKind::Gt, "`>`")?;
                Ok(Type::Handle(HandleType {
                    object,
                    rights,
                    span,
                }))
            }
            TokenKind::Ident(name) => {
                self.advance();
                Ok(Type::Named(name, span))
            }
            TokenKind::Keyword(kw) => match prim_from_kw(kw) {
                Some(prim) => {
                    self.advance();
                    Ok(Type::Prim(prim))
                }
                None => {
                    self.error(Code::UnexpectedToken, "expected a type");
                    Err(())
                }
            },
            _ => {
                self.error(Code::UnexpectedToken, "expected a type");
                Err(())
            }
        }
    }

    /// Parses an optional `:N` bound (present on well-formed `vector`/`string`,
    /// absent on the unbounded form the checker rejects).
    fn parse_optional_bound(&mut self) -> PResult<Option<u64>> {
        if self.eat(&TokenKind::Colon) {
            let (n, _) = self.expect_int()?;
            Ok(Some(n))
        } else {
            Ok(None)
        }
    }

    fn parse_prim_type(&mut self) -> PResult<(PrimType, Span)> {
        if let TokenKind::Keyword(kw) = *self.peek()
            && let Some(prim) = prim_from_kw(kw)
        {
            let span = self.span();
            self.advance();
            return Ok((prim, span));
        }
        self.error(Code::UnexpectedToken, "expected a primitive base type");
        Err(())
    }

    // --- annotations ---

    fn parse_annotations(&mut self) -> PResult<Annotations> {
        let mut annotations = Annotations::default();
        while self.eat(&TokenKind::At) {
            let (name, _) = self.expect_name()?;
            // `@abi` is a bare flag; the rest take parenthesized arguments.
            if name == "abi" {
                annotations.abi = true;
                continue;
            }
            self.expect(&TokenKind::LParen, "`(`")?;
            match name.as_str() {
                "available" => self.parse_available(&mut annotations.availability)?,
                "data_class" => {
                    let (class, _) = self.expect_name()?;
                    annotations.data_class = Some(class);
                }
                _ => {
                    self.error(
                        Code::UnexpectedToken,
                        format!("unknown annotation `{name}`"),
                    );
                    return Err(());
                }
            }
            self.expect(&TokenKind::RParen, "`)`")?;
        }
        Ok(annotations)
    }

    fn parse_available(&mut self, availability: &mut Availability) -> PResult<()> {
        loop {
            if self.peek() == &TokenKind::RParen {
                break;
            }
            let (key, _) = self.expect_name()?;
            self.expect(&TokenKind::Eq, "`=`")?;
            let (value, _) = self.expect_int()?;
            match key.as_str() {
                "added" => availability.added = Some(value),
                "deprecated" => availability.deprecated = Some(value),
                "removed" => availability.removed = Some(value),
                _ => self.error(
                    Code::UnexpectedToken,
                    format!("unknown availability key `{key}`"),
                ),
            }
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        Ok(())
    }
}

fn prim_from_kw(kw: Kw) -> Option<PrimType> {
    let prim = match kw {
        Kw::Bool => PrimType::Bool,
        Kw::Int8 => PrimType::Int8,
        Kw::Int16 => PrimType::Int16,
        Kw::Int32 => PrimType::Int32,
        Kw::Int64 => PrimType::Int64,
        Kw::Uint8 => PrimType::Uint8,
        Kw::Uint16 => PrimType::Uint16,
        Kw::Uint32 => PrimType::Uint32,
        Kw::Uint64 => PrimType::Uint64,
        Kw::Float32 => PrimType::Float32,
        Kw::Float64 => PrimType::Float64,
        _ => return None,
    };
    Some(prim)
}

#[cfg(test)]
#[path = "tests/parser.rs"]
mod tests;
