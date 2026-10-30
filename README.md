# DNP3 current implementation

This checkout contains the current SEL-751 response-obfuscation implementation and manuscript.

- `p4/`: editable P4 and the current semantic profile (`p4/README.md`: pipeline layout and build).
- `scripts/`: supported build, model, hardware and checking tools (`scripts/hardware/README.md`: the master and a
  guarded hardware block).
- `tests/`: current behavioral regressions and minimal fixtures.
- `paper/`: current manuscript, sections, tables, figures and build tools.
- `results/`: current build/model/hardware/paper results, including logs, PCAPs and JSON evidence.
- `Archive/`: historical material; excluded from normal commands and search.

Read `PLAN.md` for the active task and `HANDOVER.md` for verified state. `CLAUDE.md` contains operating rules.
Current evidence is indexed by `results/current.json`. Do not use archived instructions or scripts as current commands.
