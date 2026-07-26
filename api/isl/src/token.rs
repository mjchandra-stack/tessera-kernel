// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Lexical tokens for the ISL surface syntax (FIDL-like,
//! docs/api/03-interface-schema-language.md:17). Keywords, identifiers,
//! integer literals, and punctuation, each carrying a source span.
//!
//! Normative: docs/api/03-interface-schema-language.md

use crate::diag::Span;

/// A lexical token: its kind and where it came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

/// The kinds of token. Keywords are lexed as `Keyword(Kw)`; everything
/// context-sensitive (primitive type names, `strict`/`flexible`, ownership
/// modes) is a keyword the parser interprets by position.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TokenKind {
    Ident(String),
    Keyword(Kw),
    /// An unsigned integer literal (decimal or `0x` hex).
    Int(u64),
    // Punctuation.
    Semi,     // ;
    Colon,    // :
    Comma,    // ,
    Dot,      // .
    LBrace,   // {
    RBrace,   // }
    LParen,   // (
    RParen,   // )
    Lt,       // <
    Gt,       // >
    Eq,       // =
    At,       // @
    Question, // ?
    Arrow,    // ->
    /// End of input.
    Eof,
}

/// Reserved words.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kw {
    Library,
    Bits,
    Enum,
    Struct,
    Table,
    Union,
    Protocol,
    Strict,
    Flexible,
    Array,
    Vector,
    StringT,
    Handle,
    Reserved,
    // Out-of-line ownership modes.
    Transfer,
    Share,
    Snapshot,
    // Primitive types.
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

impl Kw {
    /// The source spelling of this keyword, so it can be accepted as a name in
    /// name positions (field/member/method names may collide with keywords
    /// like `handle` or `string`).
    pub fn spelling(self) -> &'static str {
        match self {
            Kw::Library => "library",
            Kw::Bits => "bits",
            Kw::Enum => "enum",
            Kw::Struct => "struct",
            Kw::Table => "table",
            Kw::Union => "union",
            Kw::Protocol => "protocol",
            Kw::Strict => "strict",
            Kw::Flexible => "flexible",
            Kw::Array => "array",
            Kw::Vector => "vector",
            Kw::StringT => "string",
            Kw::Handle => "handle",
            Kw::Reserved => "reserved",
            Kw::Transfer => "transfer",
            Kw::Share => "share",
            Kw::Snapshot => "snapshot",
            Kw::Bool => "bool",
            Kw::Int8 => "int8",
            Kw::Int16 => "int16",
            Kw::Int32 => "int32",
            Kw::Int64 => "int64",
            Kw::Uint8 => "uint8",
            Kw::Uint16 => "uint16",
            Kw::Uint32 => "uint32",
            Kw::Uint64 => "uint64",
            Kw::Float32 => "float32",
            Kw::Float64 => "float64",
        }
    }

    /// Maps an identifier spelling to a keyword, if it is one.
    pub fn from_ident(s: &str) -> Option<Kw> {
        let kw = match s {
            "library" => Kw::Library,
            "bits" => Kw::Bits,
            "enum" => Kw::Enum,
            "struct" => Kw::Struct,
            "table" => Kw::Table,
            "union" => Kw::Union,
            "protocol" => Kw::Protocol,
            "strict" => Kw::Strict,
            "flexible" => Kw::Flexible,
            "array" => Kw::Array,
            "vector" => Kw::Vector,
            "string" => Kw::StringT,
            "handle" => Kw::Handle,
            "reserved" => Kw::Reserved,
            "transfer" => Kw::Transfer,
            "share" => Kw::Share,
            "snapshot" => Kw::Snapshot,
            "bool" => Kw::Bool,
            "int8" => Kw::Int8,
            "int16" => Kw::Int16,
            "int32" => Kw::Int32,
            "int64" => Kw::Int64,
            "uint8" => Kw::Uint8,
            "uint16" => Kw::Uint16,
            "uint32" => Kw::Uint32,
            "uint64" => Kw::Uint64,
            "float32" => Kw::Float32,
            "float64" => Kw::Float64,
            _ => return None,
        };
        Some(kw)
    }
}
