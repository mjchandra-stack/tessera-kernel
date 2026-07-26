// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Compiler diagnostics. Every error is a stable numeric `ISLxxxx` code plus a
//! human message and a source span, so tooling can match on the code rather
//! than parse the text (docs/lifecycle/04-coding-guidelines.md, "Errors As
//! Values"). Diagnostics are accumulated, not fail-fast, so one run reports
//! many problems.
//!
//! Normative: docs/lifecycle/04-coding-guidelines.md ("Failure Discipline")

use std::fmt;

/// A half-open byte range into the source text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// A zero-width span at `pos` (for "expected more input" errors).
    pub fn point(pos: usize) -> Self {
        Self {
            start: pos,
            end: pos,
        }
    }
}

/// Stable diagnostic codes. The numeric value is the wire-stable identity;
/// append new codes, never renumber. Rendered as `ISL0007` etc. The reserved
/// checker codes match the milestone plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum Code {
    // Lexer (1..)
    UnexpectedChar = 1,
    InvalidNumber = 2,
    UnterminatedComment = 3,
    // Parser (4..)
    UnexpectedToken = 4,
    UnexpectedEof = 5,
    ExpectedName = 6,
    // Checker (7..)
    OrdinalReused = 7,
    DuplicateName = 8,
    UnknownType = 9,
    UnknownRights = 10,
    UnboundedVector = 11,
    DuplicateMember = 12,
    MissingAbiHeader = 13,
    InvalidBaseType = 14,
    AbiSubsetViolation = 15,
    OptionalStructField = 16,
    FrozenStructChanged = 21,
    ReservedOrdinalUsed = 22,
    UnknownDataClass = 23,
    ForwardStructRef = 24,
    ShareInValidateThenUse = 30,
    BoundTooLarge = 31,
}

impl Code {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// The `ISLxxxx` rendering used in messages and tests.
    pub fn label(self) -> String {
        format!("ISL{:04}", self.as_u16())
    }
}

/// Whether a diagnostic blocks compilation or merely flags a concern.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Error,
    Warning,
}

/// A single diagnostic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Diagnostic {
    pub code: Code,
    pub severity: Severity,
    pub message: String,
    pub span: Span,
}

impl Diagnostic {
    pub fn new(code: Code, span: Span, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            span,
            message: message.into(),
        }
    }

    pub fn warning(code: Code, span: Span, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::new(code, span, message)
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(
            f,
            "{} {} at {}..{}: {}",
            sev,
            self.code.label(),
            self.span.start,
            self.span.end,
            self.message
        )
    }
}

/// An accumulating collector of diagnostics.
#[derive(Default, Debug)]
pub struct Diagnostics {
    items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, diag: Diagnostic) {
        self.items.push(diag);
    }

    pub fn error(&mut self, code: Code, span: Span, message: impl Into<String>) {
        self.push(Diagnostic::new(code, span, message));
    }

    pub fn warn(&mut self, code: Code, span: Span, message: impl Into<String>) {
        self.push(Diagnostic::warning(code, span, message));
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// True if any diagnostic is an error (warnings do not block compilation).
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.items.iter()
    }

    /// True if any diagnostic carries `code` (used by rule-rejection tests).
    pub fn has(&self, code: Code) -> bool {
        self.items.iter().any(|d| d.code == code)
    }

    pub fn into_vec(self) -> Vec<Diagnostic> {
        self.items
    }
}
