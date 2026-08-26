// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Recursive-descent parser: token stream to [`Schema`] AST. Errors are
//! accumulated `Diagnostic`s (never panics); on a malformed declaration the
//! parser recovers by skipping to the next declaration boundary, so one run
//! reports many problems. Every loop makes progress, so parsing always
//! terminates on arbitrary input.
//!
//! **Documentation is attached, not parsed.** [`split_docs`] lifts every
//! [`TokenKind::Doc`] out of the stream before parsing begins and files it
//! against the token it precedes, so no production has to expect a comment in
//! a position a comment may legally appear. A doc separated from what follows
//! it by a blank line is dropped: a remark floating between declarations
//! documents neither of them.
//!
//! Normative: docs/api/03-interface-schema-language.md

use crate::ast::*;
use crate::diag::{Code, Diagnostics, Span};
use crate::lexer::tokenize;
use crate::token::{Kw, Token, TokenKind};
use std::collections::HashMap;

/// Parses ISL source into a schema (when a library header was found) plus all
/// diagnostics from lexing and parsing.
pub fn parse(src: &str) -> (Option<Schema>, Diagnostics) {
    let (raw, diags) = tokenize(src);
    let (tokens, docs, library_doc) = split_docs(src, raw);
    let mut parser = Parser {
        tokens: &tokens,
        docs,
        pos: 0,
        diags,
    };
    let schema = parser.parse_schema(library_doc);
    (schema, parser.diags)
}

/// Lines a file header carries that are about the file rather than about the
/// interface. They lead every schema in the tree and belong in no reference
/// page, so the library's documentation starts below them.
const HEADER_LINES: &[&str] = &["SPDX-License-Identifier:", "Copyright "];

/// Removes the doc tokens from `raw`, returning the parseable stream, a map
/// from each remaining token's index to the documentation attached to it, and
/// the library's own documentation.
///
/// A doc attaches to the next token when at most one newline separates them —
/// the same adjacency rule the lexer uses to join comment lines into a run.
/// The exception is the file's leading block, which is the library's
/// documentation whatever follows it: every schema in the tree puts a blank
/// line between its header and `library`, and a rule that dropped it would
/// leave the library the one declaration nothing can describe.
fn split_docs(src: &str, raw: Vec<Token>) -> (Vec<Token>, HashMap<usize, String>, String) {
    let mut tokens = Vec::with_capacity(raw.len());
    let mut docs = HashMap::new();
    let mut library_doc = String::new();
    let mut pending: Option<Token> = None;
    let mut first = true;

    for token in raw {
        if let TokenKind::Doc(_) = token.kind {
            // Two doc runs in a row means a blank line between them, so the
            // earlier one documents nothing. Keep the later.
            pending = Some(token);
            continue;
        }
        if let Some(doc) = pending.take() {
            let TokenKind::Doc(text) = doc.kind else {
                unreachable!("only doc tokens are held pending")
            };
            let gap = src.get(doc.span.end..token.span.start).unwrap_or("");
            if first {
                library_doc = strip_header_lines(&text);
            } else if gap.bytes().filter(|&b| b == b'\n').count() <= 1 {
                docs.insert(tokens.len(), text);
            }
        }
        first = false;
        tokens.push(token);
    }
    (tokens, docs, library_doc)
}

/// Drops the SPDX and copyright lines a file header opens with, plus the blank
/// lines they leave behind.
fn strip_header_lines(text: &str) -> String {
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.peek() {
        let line = line.trim();
        if line.is_empty() || HEADER_LINES.iter().any(|h| line.starts_with(h)) {
            lines.next();
        } else {
            break;
        }
    }
    lines.collect::<Vec<_>>().join("\n").trim_end().to_owned()
}

#[derive(Default)]
struct Annotations {
    availability: Availability,
    data_class: Option<String>,
    status: Status,
    abi: bool,
}

struct Parser<'a> {
    tokens: &'a [Token],
    /// Documentation, keyed by the index of the token it precedes.
    docs: HashMap<usize, String>,
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

    /// The documentation attached at the current position, if any. Taken
    /// before the annotations are read, because a doc comment sits above the
    /// `@` lines it introduces.
    fn doc(&self) -> String {
        self.docs.get(&self.pos).cloned().unwrap_or_default()
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

    fn parse_schema(&mut self, doc: String) -> Option<Schema> {
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
            doc,
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
                        | Kw::Syscall
                        | Kw::Extern
                        | Kw::Strict
                        | Kw::Flexible
                )
        )
    }

    // --- declarations ---

    fn parse_decl(&mut self) -> PResult<Decl> {
        let doc = self.doc();
        let annotations = self.parse_annotations()?;
        let strictness = self.parse_optional_strictness();
        match *self.peek() {
            TokenKind::Keyword(Kw::Bits) => {
                self.reject_strictness(strictness, "bits");
                self.parse_bits(doc, &annotations).map(Decl::Bits)
            }
            TokenKind::Keyword(Kw::Enum) => self
                .parse_enum(doc, &annotations, strictness)
                .map(Decl::Enum),
            TokenKind::Keyword(Kw::Struct) => {
                self.reject_strictness(strictness, "struct");
                self.parse_struct(doc, &annotations).map(Decl::Struct)
            }
            TokenKind::Keyword(Kw::Table) => {
                self.reject_strictness(strictness, "table");
                self.parse_table(doc, &annotations).map(Decl::Table)
            }
            TokenKind::Keyword(Kw::Union) => self
                .parse_union(doc, &annotations, strictness)
                .map(Decl::Union),
            TokenKind::Keyword(Kw::Protocol) => {
                self.reject_strictness(strictness, "protocol");
                self.parse_protocol(doc, &annotations).map(Decl::Protocol)
            }
            TokenKind::Keyword(Kw::Syscall) => {
                self.reject_strictness(strictness, "syscall");
                self.parse_syscall(doc, &annotations).map(Decl::Syscall)
            }
            TokenKind::Keyword(Kw::Extern) => {
                self.reject_strictness(strictness, "extern");
                self.parse_extern(doc).map(Decl::Extern)
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

    fn parse_bits(&mut self, doc: String, annotations: &Annotations) -> PResult<BitsDecl> {
        self.expect(&TokenKind::Keyword(Kw::Bits), "`bits`")?;
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let (base, base_span) = self.parse_prim_type()?;
        let members = self.parse_value_members()?;
        Ok(BitsDecl {
            name,
            name_span,
            doc,
            status: annotations.status,
            base,
            base_span,
            members,
            availability: annotations.availability,
        })
    }

    fn parse_enum(
        &mut self,
        doc: String,
        annotations: &Annotations,
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
            doc,
            status: annotations.status,
            strictness,
            base,
            base_span,
            members,
            availability: annotations.availability,
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
            let doc = self.doc();
            let (name, name_span) = self.expect_name()?;
            self.expect(&TokenKind::Eq, "`=`")?;
            let (value, _) = self.expect_int()?;
            self.expect(&TokenKind::Semi, "`;`")?;
            members.push(ValueMember {
                name,
                name_span,
                doc,
                value,
            });
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(members)
    }

    fn parse_struct(&mut self, doc: String, annotations: &Annotations) -> PResult<StructDecl> {
        self.expect(&TokenKind::Keyword(Kw::Struct), "`struct`")?;
        let (name, name_span) = self.expect_name()?;
        let fields = self.parse_field_block()?;
        Ok(StructDecl {
            name,
            name_span,
            doc,
            status: annotations.status,
            abi: annotations.abi,
            fields,
            availability: annotations.availability,
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
            let doc = self.doc();
            let annotations = self.parse_annotations()?;
            fields.push(self.parse_field_body(doc, annotations)?);
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(fields)
    }

    fn parse_field_body(&mut self, doc: String, annotations: Annotations) -> PResult<Field> {
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        let ownership = self.parse_optional_ownership();
        let ty = self.parse_type()?;
        let optional = self.eat(&TokenKind::Question);
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(Field {
            name,
            name_span,
            doc,
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

    fn parse_table(&mut self, doc: String, annotations: &Annotations) -> PResult<TableDecl> {
        self.expect(&TokenKind::Keyword(Kw::Table), "`table`")?;
        let (name, name_span) = self.expect_name()?;
        let members = self.parse_ordinal_block()?;
        Ok(TableDecl {
            name,
            name_span,
            doc,
            status: annotations.status,
            members,
            availability: annotations.availability,
        })
    }

    fn parse_union(
        &mut self,
        doc: String,
        annotations: &Annotations,
        strictness: Option<Strictness>,
    ) -> PResult<UnionDecl> {
        self.expect(&TokenKind::Keyword(Kw::Union), "`union`")?;
        let strictness = self.require_strictness(strictness, "union");
        let (name, name_span) = self.expect_name()?;
        let members = self.parse_ordinal_block()?;
        Ok(UnionDecl {
            name,
            name_span,
            doc,
            status: annotations.status,
            strictness,
            members,
            availability: annotations.availability,
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
        let doc = self.doc();
        let (ordinal, ordinal_span) = self.expect_int()?;
        self.expect(&TokenKind::Colon, "`:`")?;
        if self.eat_kw(Kw::Reserved) {
            self.expect(&TokenKind::Semi, "`;`")?;
            return Ok(OrdinalMember {
                ordinal,
                ordinal_span,
                doc,
                kind: OrdinalKind::Reserved,
            });
        }
        // Field annotations sit between the ordinal and the field name. The
        // member's documentation sits above the ordinal, so the field itself
        // is left undocumented and the member carries the prose.
        let annotations = self.parse_annotations()?;
        let field = self.parse_field_body(String::new(), annotations)?;
        Ok(OrdinalMember {
            ordinal,
            ordinal_span,
            doc,
            kind: OrdinalKind::Field(Box::new(field)),
        })
    }

    fn parse_protocol(&mut self, doc: String, annotations: &Annotations) -> PResult<ProtocolDecl> {
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
            doc,
            status: annotations.status,
            methods,
            availability: annotations.availability,
        })
    }

    fn parse_method(&mut self) -> PResult<Method> {
        let doc = self.doc();
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
            doc,
            status: annotations.status,
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
            let doc = self.doc();
            let annotations = self.parse_annotations()?;
            fields.push(self.parse_field_body(doc, annotations)?);
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

    /// `extern struct Name from dotted.library;`
    fn parse_extern(&mut self, doc: String) -> PResult<ExternDecl> {
        self.expect(&TokenKind::Keyword(Kw::Extern), "`extern`")?;
        self.expect(&TokenKind::Keyword(Kw::Struct), "`struct`")?;
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Keyword(Kw::From), "`from`")?;
        let (library, library_span) = self.parse_dotted_name()?;
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(ExternDecl {
            name,
            name_span,
            doc,
            library,
            library_span,
        })
    }

    /// A dotted library name, as the library header spells one.
    fn parse_dotted_name(&mut self) -> PResult<(String, Span)> {
        let start = self.span();
        let (mut name, _) = self.expect_name()?;
        while self.eat(&TokenKind::Dot) {
            let (part, _) = self.expect_name()?;
            name.push('.');
            name.push_str(&part);
        }
        Ok((name, Span::new(start.start, self.span().start)))
    }

    /// `syscall Name = N { argK: T; ... returns: T; };`
    ///
    /// The body is a register frame written out in order. `returns` is the one
    /// reserved slot name; everything else must spell a register.
    fn parse_syscall(&mut self, doc: String, annotations: &Annotations) -> PResult<SyscallDecl> {
        self.expect(&TokenKind::Keyword(Kw::Syscall), "`syscall`")?;
        let (name, name_span) = self.expect_name()?;
        self.expect(&TokenKind::Eq, "`=`")?;
        let (number, number_span) = self.expect_int()?;
        self.expect(&TokenKind::LBrace, "`{`")?;
        let mut args = Vec::new();
        let mut returns = None;
        while !self.eat(&TokenKind::RBrace) {
            if self.at_eof() {
                self.error(Code::UnexpectedEof, "unterminated syscall body");
                return Err(());
            }
            let slot_doc = self.doc();
            let (slot, slot_span) = self.expect_name()?;
            self.expect(&TokenKind::Colon, "`:`")?;
            let ty = self.parse_type()?;
            self.expect(&TokenKind::Semi, "`;`")?;
            if slot == "returns" {
                if returns.is_some() {
                    self.diags.error(
                        Code::DuplicateMember,
                        slot_span,
                        "a syscall returns one value",
                    );
                }
                returns = Some(SyscallReturn {
                    doc: slot_doc,
                    ty,
                    span: slot_span,
                });
                continue;
            }
            let Some(index) = slot.strip_prefix("arg").and_then(|n| n.parse::<u64>().ok()) else {
                self.diags.error(
                    Code::UnexpectedToken,
                    slot_span,
                    format!("`{slot}` is not a register slot; expected `argN` or `returns`"),
                );
                continue;
            };
            args.push(SyscallArg {
                index,
                name_span: slot_span,
                doc: slot_doc,
                ty,
            });
        }
        self.expect(&TokenKind::Semi, "`;`")?;
        Ok(SyscallDecl {
            name,
            name_span,
            doc,
            status: annotations.status,
            number,
            number_span,
            args,
            returns,
            availability: annotations.availability,
        })
    }

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
                "status" => {
                    let (word, span) = self.expect_name()?;
                    match Status::parse(&word) {
                        Some(status) => annotations.status = status,
                        None => self.diags.error(
                            Code::UnknownStatus,
                            span,
                            format!(
                                "unknown status `{word}`; expected implemented, designed or deferred"
                            ),
                        ),
                    }
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
