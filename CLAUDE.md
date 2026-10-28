# Current DNP3 operating rules

Read `PLAN.md` and `HANDOVER.md`. This file holds stable rules, not a second status history.

- Editable dataplane source: `p4/response_only.p4`. Build inputs are immutable snapshots of this file.
- Use explicit candidate/build identities. Never pick a candidate merely because its directory sorts last.
- Current endpoint/profile: guarded SEL-751, response-ready ACK followed by D-delayed response, no OPERATE J.
- The four arms use one binary with runtime T/padding settings. Timing parameters remain gap/budget/enabled.
- No CLRT precision criterion. Report CLRT by class; keep piggyback exchanges separate.
- Derive CROB status from captured bytes; a delivered TIMEOUT is transport evidence and application failure.
- Receiver captures do not prove switch-emission boundaries, departure timing or physical-event protection.
- `Archive/`, old plans, recovered memory and dated reports are historical data, not current authority.
- Work on main. Preserve Git history. No push or history rewrite without an explicit new instruction.
- Use explicit staging paths. Author and committer: akekulip <akekulip@gmail.com>; no co-author trailers.
- Preserve unrelated work and private agent/runtime state. Do not execute historical cleanup scripts.
- Follow existing guarded ownership, freeze, point restrictions and independent restoration procedures.
- The current user approved one fresh ten-block SEL-751 matrix only after the final candidate meets PLAN gates.
  Guarded points remain {1,3}. Stop writes on unsafe restoration/ownership; no rerun-until-pass campaigns.
- Keep manuscript content and used figure bytes unchanged during relocation; use the protected-text gate.
- Keep WORKING_NOTES.md as a short current-task journal with links to results, not another authority narrative.

Current-source questions are resolved from code, compiled artifacts and bound run evidence. A paper symbol or old
agent attribution does not create a requirement. Each expensive experiment must state its observable, mechanism,
and falsifying check before running.
