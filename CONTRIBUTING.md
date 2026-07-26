<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>
-->

# Contributing To Tessera

Tessera is an operating system design — currently a specification set under
`docs/`, on its way to an implementation per
[Sequencing And MVP](docs/roadmap/01-sequencing-and-mvp.md). Contributions
to the design documents are as welcome as future code contributions, and are
held to the same review discipline.

## License

Tessera is licensed under the [Apache License 2.0](LICENSE). By
contributing, you agree that your contributions are licensed under the same
terms (inbound = outbound). Every file carries an SPDX header:

```text
SPDX-License-Identifier: Apache-2.0
```

## Developer Certificate Of Origin

Contributions require a Developer Certificate of Origin sign-off. By adding
a `Signed-off-by` line you certify the DCO 1.1
(https://developercertificate.org):

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
>     right to submit it under the open source license indicated in the
>     file; or
>
> (b) The contribution is based upon previous work that, to the best of my
>     knowledge, is covered under an appropriate open source license and I
>     have the right under that license to submit that work with
>     modifications, whether created in whole or in part by me, under the
>     same open source license (unless I am permitted to submit under a
>     different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who
>     certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are
>     public and that a record of the contribution (including all personal
>     information I submit with it, including my sign-off) is maintained
>     indefinitely and may be redistributed consistent with this project
>     or the open source license(s) involved.

Sign off every commit with your real name and email:

```text
git commit -s
```

which appends:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Unsigned commits are not merged.

## Design Document Conventions

The specification's value is its internal consistency; contributions must
preserve it:

- **Single normative definitions.** Rights live in the Rights Catalog, data
  classes in Data Classification, security domains in the security model,
  and so on. Never redefine — reference. If you add a right, a data class,
  or a budget, add it to its catalog first.
- **Cross-references must resolve.** Use relative paths
  (`../kernel/01-kernel-model.md`). Before submitting, run the link check:

  ```bash
  cd docs && for f in $(find . -name '*.md'); do d=$(dirname "$f"); \
    grep -ohE '\]\([^)#]+\.md\)|`[.A-Za-z0-9_/-]+\.md`' "$f" | \
    tr -d '`()]' | sed 's/^\[//' | while read -r ref; do \
    [ -f "$d/$ref" ] || [ -f "$ref" ] || echo "BROKEN in $f: $ref"; \
    done; done
  ```

- **New mechanisms carry their contracts.** A new subsystem document needs
  its observability section, its failure/restart semantics, its syscall
  surface in `docs/api/01-system-call-interface.md` where applicable, and —
  for anything on a hot path — a budget row in
  `docs/architecture/03-performance-budgets.md`. "Named but undesigned"
  components are the defect class this project exists to avoid.
- **Index every new document** in `docs/README.md` (reading order and
  hierarchy) and, if it adds a directory, in `OVERVIEW.txt`.
- **Budgets and ABI-shaped changes get extra scrutiny.** Changing a budget,
  a rights definition, an ISL rule, or a syscall family is reviewed like an
  ABI change, per the project's own governance rules in
  `docs/lifecycle/01-development-maintenance-update-model.md`.

## Code Contributions

Implementation code follows the
[Coding Guidelines](docs/lifecycle/04-coding-guidelines.md) — unsafe-code
policy, failure discipline, concurrency rules, ABI hygiene, and the
observability and testing obligations every change carries. The guidelines
are derived from the design documents and cite them; where they conflict,
the design document wins.

## Submitting Changes

1. Fork, branch, and make focused changes — one design concern per pull
   request.
2. Run the link check; keep new files carrying the SPDX header.
3. Sign off every commit (`git commit -s`).
4. In the PR description, state which documents you touched and, for
   substantive design changes, the alternatives you considered — decisions
   with recorded reasoning are this project's habit.

## Questions And Proposals

For substantial design proposals (new subsystems, budget changes,
architectural revisions), open an issue describing the problem and the
proposed shape before writing the full document — sequencing discussion
before prose is cheaper for everyone.
