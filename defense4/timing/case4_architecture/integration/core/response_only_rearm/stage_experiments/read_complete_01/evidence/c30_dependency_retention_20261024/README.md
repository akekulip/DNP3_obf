# c30 historical dependency and raw-log retention

`manifest.json` binds19original executed closures,59unique source contents and38byte-exact compressed model/console logs
(about4GBraw,276MBxz). Every source object filename is its SHA256. Sources were recovered only from bytes matching
the original closure: unchanged files, committed/index versions or retained driver_source.py copies. The manifest
records each recovery origin. Original closures, launch records, results and failed attempts were not rewritten.

`../../restore_retained_logs.py` verifies each archive pin and the decompressed SHA256 before restoring an absent log;
it verifies existing logs without replacing them. The same utility still honors reset-postcheck pins on older runs.

These snapshots preserve c30 evidence after current model helpers change. They do not make the current helpers
identical to historical executed closures, and do not authorize a relay-SBO gate. A current v3 summary must remain
blocked on changed dependencies. Six c30 READ driver results total1332/1332; corrected control_timing04 is415/415.
Control_timing01/02 retain the unsupported software247integrity fixture and their failed results. Attempt03 retains
its pre-driver sandbox failure. No old failed attempt is relabeled passed.
