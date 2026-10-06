# Evidence recovery and remaining provenance limits

Recovery commit `d7a904c3d` retains 14,291 direct files and 904 compressed originals.
See [recovery instructions](README.md#evidence-recovery), `recovery_manifest.json`,
and `git_restore_check.json`. Original inputs remain unchanged.

Versioning closes the local recoverability gap for those selected artifacts. It
does not promote later experiments to paper evidence, reconstruct missing original
readbacks, or turn September 29 hashes into collection-time provenance. Excluded
intermediate copies remain local and are listed in the recovery manifest.

Some historical analysis records contain original absolute paths. Byte recovery
is verified; rerunning every analysis from a relocated checkout is not established.
No remote backup or push was performed.
