# IED vendor security-support survey (crawler output, supplied 2026-10-19)

Supplied by Philip in the session of 2026-10-19 as pasted text: three summary tables (by vendor, by
generation, devices by vendor and generation) and the 55 per-device rows, saved here as
`ied_security_devices.tsv` (15 columns, tab-separated). The paste was column-aligned, and the
alignment was converted to tabs. One character repair: the mojibake "â€”" in the SEL-3530 note is
written as "—". The crawler code and its run identity (the notes mention `run1_v1_3`) are not in
the repository.

**Check (2026-10-19).** All three pasted summary tables are reproduced exactly from the 55 rows
(`paper_evidence.py` `table_crawler`).

**Findings to resolve before the paper cites it:**
1. **It disagrees with the draft.** Dr. Lin's draft (III-B) says "a stratified sample of 99
   catalogued entries, 32 … DNP3 support, … encryption for six entries, and one had DNP3
   authentication". This output has 55 devices with security support Encryption+Auth 4,
   Authentication 2, Opt-in (unconfirmed) 1, None 48. Either the draft cites an earlier run, or
   the numbers need updating; his sentence is protected text and is not changed here.
2. **Encryption is not all DNP3 encryption.**
   - Two of the four Encryption+Auth rows are Rockwell PLCs (ControlLogix 5580, CompactLogix 5380)
     whose security is CIP Security on EtherNet/IP; DNP3 reaches them only through an add-on
     module.
   - DNP3-native security therefore appears on 2 devices with TLS (SEL-3530 RTAC, SICAM A8000,
     the latter also with SAv5) and 2 with DNP3-SA only (ADVC3, SCADAPack 470), plus 1
     unconfirmed (ION9000).
3. **Three rows are not DNP3 outstations by their own `dnp3` field:** SEL-251 and SEL-501
   ("none/serial") and SEL-2030 ("serial").
