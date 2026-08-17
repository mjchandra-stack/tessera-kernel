// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! The kernel's configuration surface: what a build of Tessera can be told to
//! be, and the one program that answers.
//!
//! Three things vary between two builds of this tree, and until now only the
//! first was written down anywhere:
//!
//! * **Sizing** — the fixed-capacity tables `kcore` allocates. Declared since
//!   D195, ranged and documented.
//! * **Features** — whole mechanisms compiled in or out, each gating a
//!   `#[cfg]` in the ports. These were `--cfg=` string literals hand-written
//!   into five kernel `BUILD.bazel` files, declared nowhere, listed nowhere,
//!   and deliberately excluded from the codegen-flag gate.
//! * **Composition** — which ring-3 programs a machine's image carries. A
//!   Starlark dict per machine, which is to say: the driver-selection surface,
//!   as a build-file edit.
//!
//! All three are `config/kernel.config` now, and a *profile* is a statement
//! about all three at once. That is the whole idea: "what is this kernel" has
//! one answer, in one file, that a person can read and a gate can check.
//!
//! **Why a format of its own.** `docs/api/03`'s schema language defines *wire*
//! boundaries, and has no construct for a defaulted, ranged scalar. Adding one
//! would change a language whose job is ABI compatibility, for values that
//! never cross a wire. So `config/kernel.config` is read here and nowhere
//! else, and the parser is strict: an unknown key, a duplicate setting, a
//! missing field, a value outside its declared range, a profile naming a
//! setting that does not exist, and an invariant a profile breaks are each an
//! error naming its line.
//!
//! **A refusal, never a clamp.** A profile asking for a value the declaration
//! says is out of range is rejected rather than pulled to the nearest bound.
//! Clamping would build a kernel sized differently from the one that was asked
//! for, and nothing downstream could tell. The same rule now covers features
//! and components: a profile that turns off a program another program needs is
//! refused, not quietly honoured.
//!
//! Normative: docs/kernel/01-kernel-model.md,
//! docs/lifecycle/02-build-and-test-infrastructure.md
//! Budget: none (build-time tooling)

use std::collections::{BTreeMap, BTreeSet};

pub mod declare;
pub mod emit;
pub mod menu;
pub mod profile;
pub mod resolve;
pub mod term;

pub use declare::parse_declaration;
pub use emit::{Form, emit, emit_components};
pub use profile::parse_profile;
pub use resolve::{Config, resolve};

/// What a setting is, and the fields that only its kind has.
///
/// The kind is declared rather than inferred from which fields are present.
/// Inference would make a typo in a field name silently reclassify a setting —
/// a `rnage` that does not parse would turn a size into a feature — and this
/// file is the one place where guessing is least affordable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A fixed-capacity table in `kcore`, sized by an integer with bounds
    /// outside which the code that reads it does not work.
    Size {
        /// The `kcore` module whose table it sizes.
        module: String,
        /// Inclusive bounds. A claim about the code, not a preference.
        min: u64,
        max: u64,
    },
    /// A mechanism compiled in or out, by the `cfg` name its absence sets.
    Feature {
        /// The `--cfg=` a kernel built with this feature on carries, and the
        /// `#[cfg(…)]` the ports read. Named here so the flag gate can hold
        /// the five `BUILD.bazel` files to what the profile actually says.
        cfg: String,
    },
    /// A ring-3 program the image may carry.
    ///
    /// A component that is off is not a component that is missing: the image
    /// crate still declares the accessor and it returns an empty slice, which
    /// is the state every check already handles (it is what the cargo inner
    /// loop has always seen). Nothing references the program's bytes, so they
    /// do not reach the image — the option genuinely removes the program
    /// rather than only hiding it.
    Component,
}

/// One configurable value: what it is, what it defaults to, which machines it
/// applies to, what it must stay consistent with, and why it is what it is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Setting {
    pub kind: Kind,
    /// The value with no profile applied.
    pub default: Value,
    /// The machines this setting exists on, or `None` for every machine.
    ///
    /// Sizing is machine-independent by construction — one `kcore` is linked
    /// into all five kernels — so only components routinely name machines,
    /// and they must: a program with no image for a machine cannot be turned
    /// on there, and saying so here is what makes that a refusal rather than a
    /// link error.
    pub machines: Option<BTreeSet<String>>,
    /// What must hold once every value is resolved.
    pub requires: Vec<Requirement>,
    /// Why the value is what it is, moved verbatim from the source it used to
    /// sit in.
    pub doc: Vec<String>,
}

impl Setting {
    /// Whether this setting exists on `machine`.
    pub fn applies_to(&self, machine: &str) -> bool {
        self.machines
            .as_ref()
            .is_none_or(|set| set.contains(machine))
    }

    /// The heading this setting is listed under, wherever it is listed.
    ///
    /// Sizes group by the module whose table they size, which is the only
    /// grouping that matches how somebody reads them: `kcore::ipc`'s three
    /// capacities are one decision, not three.
    pub fn group(&self) -> String {
        match &self.kind {
            Kind::Size { module, .. } => format!("kcore::{module}"),
            Kind::Feature { .. } => "features".to_owned(),
            Kind::Component => "components".to_owned(),
        }
    }

    /// Where the kind sorts: sizes, then features, then components.
    pub fn rank(&self) -> u8 {
        match &self.kind {
            Kind::Size { .. } => 0,
            Kind::Feature { .. } => 1,
            Kind::Component => 2,
        }
    }
}

/// A resolved value. Sizes are integers; features and components are on or off.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Value {
    Int(u64),
    Bool(bool),
}

impl Value {
    /// The integer, for a value that is one.
    pub fn int(self) -> Option<u64> {
        match self {
            Value::Int(v) => Some(v),
            Value::Bool(_) => None,
        }
    }

    /// Whether an on/off value is on. An integer is not on or off, and
    /// answering `false` for one would let a requirement quietly read a size as
    /// "off" rather than refusing to compare them.
    pub fn on(self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(v),
            Value::Int(_) => None,
        }
    }

    /// The word for the kind of thing this is, for an error that has to say
    /// why two values could not be compared.
    pub fn noun(self) -> &'static str {
        match self {
            Value::Int(_) => "a size",
            Value::Bool(_) => "an on/off setting",
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Int(v) => write!(f, "{v}"),
            Value::Bool(true) => write!(f, "y"),
            Value::Bool(false) => write!(f, "n"),
        }
    }
}

/// One side of a comparison: a setting's resolved value, or a literal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Operand {
    Setting(String),
    Literal(u64),
}

/// How two sizes are compared.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Le,
    Lt,
    Ge,
    Gt,
    Eq,
}

/// An invariant that must hold across settings once a profile is applied.
///
/// These were prose. `config/kernel.config` said that `MAX_WAITERS` "is sized
/// to the scheduler's thread table" and that an object larger than
/// `pmem::MAX_FREE_FRAMES` "could not be reclaimed without overflowing the free
/// list" — true statements, in comments, which a profile could break without
/// anything noticing until a machine misbehaved. A requirement is the same
/// sentence written where it can be checked.
///
/// This is Tessera's `depends on`, and it is deliberately not Linux's: the
/// constraints that actually exist here are arithmetic relations between
/// capacities, not a boolean dependency tree. Both forms are supported because
/// components do have the boolean one — a client with no driver is a program
/// that will wait for a service nobody offers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Requirement {
    /// `left op right` over two sizes.
    Compare {
        left: Operand,
        op: Op,
        right: Operand,
    },
    /// `left -> right`: if `left` is on, `right` must be on too.
    Implies { left: String, right: String },
}

impl std::fmt::Display for Requirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn operand(f: &mut std::fmt::Formatter<'_>, o: &Operand) -> std::fmt::Result {
            match o {
                Operand::Setting(name) => write!(f, "{name}"),
                Operand::Literal(v) => write!(f, "{v}"),
            }
        }
        match self {
            Requirement::Compare { left, op, right } => {
                operand(f, left)?;
                write!(f, " {} ", op.spelling())?;
                operand(f, right)
            }
            Requirement::Implies { left, right } => write!(f, "{left} -> {right}"),
        }
    }
}

/// The declaration, by setting name.
pub type Declaration = BTreeMap<String, Setting>;

/// A parse or validation failure, naming the line that caused it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Error {
    /// The line that caused it, or zero for a failure that is about a value
    /// rather than a place.
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Resolution failures are about a value, not a place: a profile line
        // and a declaration line are both implicated and neither alone is the
        // answer. They carry no line, and printing `line 0` would be a
        // location that does not exist.
        match self.line {
            0 => write!(f, "{}", self.message),
            line => write!(f, "line {line}: {}", self.message),
        }
    }
}

/// Builds an [`Error`]. Crate-internal so every message is written the same way.
pub(crate) fn err(line: usize, message: impl Into<String>) -> Error {
    Error {
        line,
        message: message.into(),
    }
}
