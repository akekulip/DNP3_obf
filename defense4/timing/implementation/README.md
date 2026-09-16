# The implementation that produced the captures

Everything here is preserved **unchanged** from the campaign. Nothing in this directory was
edited during any cleanup, and none of it is on the reproduction path: the figures are
rebuilt from the captures by `../analysis/` and `../figures/source/`, which import nothing
from here.

## Contents

```
exact_experiment_source/
  defense4_rrc_bor_unified12.p4          the P4 that was compiled and loaded
control/
  defense4_rrc_bor_unified12_setup.py    top of the control-plane chain
  defense4_rrc_setup.py                  RRC layer
  defense4_caseA_setup.py                timing-parameter and queue helpers
  case_a_defense3_fixed_ack_delay_setup.py   \
  parameter_policy.py                         > the three Defense-3 modules the chain loads
  counter_map.py                              /
harness/
  relay_read_g10_23.py                   READ driver
  relay_sbo_operate_guarded.py           guarded SELECT -> OPERATE driver
  relay_operate_guarded.py               guarded OPERATE driver
  dnp3_wire.py                           DNP3 frame construction
```

## Hashes

| file | sha256 |
|---|---|
| `defense4_rrc_bor_unified12.p4` | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| `case_a_defense3_fixed_ack_delay_setup.py` | `927c9eea21f79980a391873717f797d4658beed6d34ff19dde9c47a9785b6e80` |
| `parameter_policy.py` | `1c76ab95bdcc295408f4e8325b3e16a35f6e54d454087298bf266ad6647b4afc` |
| `counter_map.py` | `4e3f3236614132eabc4e779e37448a35a7dfce85822485bf247c4d17cf99599e` |

The P4 hash is the value recorded in `E0_testbed_preservation.md` as the source of the loaded
binary `33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa`. The other files in
`control/` and `harness/` come from the same commit, `c1871384`, which is the repository HEAD
recorded at capture time.

## This is the combined program

One binary carrying both the timing mechanism and the size carve, exactly as it ran. The
paper reports timing only; the size code is present because it was present on the switch, and
it was **enabled during every capture, in both arms**. That is why the arms are called Timing
OFF and Obfuscated rather than native and defended.

## Why the three Defense-3 modules are here

`defense4_caseA_setup.py` loads `case_a_defense3_fixed_ack_delay_setup.py` at runtime, which
in turn imports `parameter_policy` and `counter_map`. Three files, traced from the import
graph rather than assumed. The rest of the Defense-3 tree is not a dependency and is not
retained.

They sit beside `defense4_caseA_setup.py` because that is a layout the loader already
supports: it tries `$D4_D3SETUP`, then a sibling in its own directory, then a repo-relative
path, and its own comment describes the sibling case as how the code is "staged on the
switch". The Defense-3 module puts its own directory on `sys.path`, so it finds the other two
there. No file was modified to make this work.

## Importing the chain offline

The whole chain imports with no SDE and no hardware — `bfrt_grpc` is lazy-imported inside
functions. One environment variable is needed, because
`defense4_rrc_bor_unified12_setup.py` resolves `defense4_caseA_setup.py` through
`$D4_CASEA_SETUP` or a repo-relative fallback written for the directory depth this chain had
before it was consolidated here:

```sh
cd defense4/timing/implementation/control
D4_CASEA_SETUP=$PWD/defense4_caseA_setup.py \
  python3 -c "import importlib.util as u; \
    s=u.spec_from_file_location('m','defense4_rrc_bor_unified12_setup.py'); \
    m=u.module_from_spec(s); s.loader.exec_module(m); print('chain imports OK')"
```

This is the same override the campaign's own `shape_set.py` used. Patching the fallback would
mean editing a file that must stay byte-identical to what ran, so it is documented instead.

## A stale default that is deliberately left stale

`control/defense4_rrc_setup.py` carries `--master-ip` with a default of `10.10.54.19`, which
was Vision's management address at the time of the campaign. Vision moved to `10.10.54.166`
on 2026-08-24, so that default is now wrong.

It is **not** corrected here, and it should not be. This directory is the byte-identical
record of what ran: the file's SHA-256 is recorded in the manifest and in the paper's
`FIGURE_PROVENANCE.md`, and editing it would break that chain and misrepresent the program
that produced the captures. The default was also never exercised by the campaign, which drove
the testbed subnet (`192.168.10.1` master, `192.168.10.7` relay) rather than the management
network. Pass `--master-ip` explicitly if this is ever run again.

The testbed addresses themselves are unchanged.

## Running it against hardware

Not from here, and not without authorisation. Every hardware operation refuses unless
`DEFENSE4_HW_AUTHORIZED=1` is set, and running for real additionally needs Barefoot SDE 9.13,
the compiled binary loaded, and the physical testbed. The default path is an offline dry-run
that builds an in-process model and runs a fail-closed readback self-test.
