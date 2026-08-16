<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Contributing To Tessera

Contributions are welcome — to the code, the tests, and the design. All three
are held to the same review discipline.

## License

Tessera is licensed under the [Apache License 2.0](LICENSE). By contributing,
you agree that your contributions are licensed under the same terms
(inbound = outbound).

Every file carries an SPDX header, and a build gate enforces it:

```text
SPDX-License-Identifier: Apache-2.0
```

## Developer Certificate Of Origin

Every commit needs a Developer Certificate of Origin sign-off. Adding a
`Signed-off-by` line certifies the [DCO 1.1](https://developercertificate.org):

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have
> the right under that license to submit that work with modifications,
> whether created in whole or in part by me, under the same open source
> license (unless I am permitted to submit under a different license), as
> indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

Sign off with your real name and email:

```bash
git commit -s
```

which appends:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Unsigned commits are not merged.

## Before You Submit

Run the full gate. It is the same one CI runs, and it is not slow:

```bash
bazel test //...                 # gates, unit tests, and every QEMU boot check
bazel build //... --config=lint  # rustfmt and clippy across the whole graph
```

## Code Standards

These are enforced in review, and several are enforced by the build.

- **No silent failure.** If code drops, truncates, or falls back, it emits a
  structured event saying so. Degradation nobody can see is the defect class
  this project exists to avoid.
- **Panics are bugs.** No `unwrap()` or `expect()` outside tests. Kernel
  allocation is fallible everywhere, and errors are stable values, never
  parsed strings.
- **Unsafe carries its reasoning.** Every `unsafe` block needs a `// SAFETY:`
  comment stating the *invariant* that makes it sound — not a restatement of
  what the code does — plus an entry in the unsafe inventory. Services are
  `#![deny(unsafe_code)]`.
- **Interfaces are schemas.** Every cross-component boundary is defined in the
  interface schema language. No hand-rolled serialization, and never edit
  generated code. Ordinals, fields, and rights are never renumbered or reused.
- **Observability ships with the change.** New mechanisms declare their events
  in a schema. No `println!` debugging.
- **One concern per commit,** with a clear, descriptive title. Call out ABI,
  budget, rights, and schema changes explicitly in the message.

## Testing Standards

- **Test at the lowest tier that reproduces the behaviour.** A host unit test
  beats a boot check when it can see the same thing.
- **Every bug fix gets a regression test,** and every parser of external input
  gets a fuzz target — a build gate fails without one.
- **Watch your test fail.** Break the implementation deliberately, confirm the
  test that names the property actually fails, then restore. A test nobody has
  seen fail is a test nobody has checked. Report the inversion you ran in the
  pull request.
- **Say what is not proven.** A test that covers part of a claim should say
  which part it leaves open, rather than letting its name imply the rest.

## Design Changes

The specifications under `docs/` are normative: where code and a design
document disagree, the document wins, and changing the behaviour means
changing the document first.

- **Single normative definitions.** Rights, data classes, and budgets each live
  in exactly one catalog. Never redefine — reference. Adding one means adding
  it to its catalog first.
- **New mechanisms carry their contracts:** observability, failure and restart
  semantics, syscall surface where applicable, and a budget for anything on a
  hot path.
- **Budgets and ABI-shaped changes get extra scrutiny.** Changing a budget, a
  rights definition, a schema rule, or a syscall family is reviewed like an ABI
  change.
- **Cross-references must resolve.** Use relative paths, and check them before
  submitting:

  ```bash
  cd docs && find . -name '*.md' | while read -r f; do
    d=$(dirname "$f")
    grep -ohE '\]\([^)#]+\.md\)|`[.A-Za-z0-9_/-]+\.md`' "$f" |
      tr -d '`()]' | sed 's/^\[//' | while read -r ref; do
        [ -f "$d/$ref" ] || [ -f "$ref" ] || echo "BROKEN in $f: $ref"
      done
  done
  ```

## Submitting Changes

1. Fork, branch, and keep the change focused — one concern per pull request.
2. Run the full gate above, and make sure new files carry an SPDX header.
3. Sign off every commit (`git commit -s`).
4. In the pull request, say what you changed, which inversion you ran to prove
   it, and — for substantive design changes — the alternatives you considered.
   Decisions with recorded reasoning are this project's habit.

## Proposals

For substantial changes — a new subsystem, a budget change, an architectural
revision — open an issue describing the problem and the shape of the proposed
solution before writing the full change. Sequencing the discussion before the
prose is cheaper for everyone.
