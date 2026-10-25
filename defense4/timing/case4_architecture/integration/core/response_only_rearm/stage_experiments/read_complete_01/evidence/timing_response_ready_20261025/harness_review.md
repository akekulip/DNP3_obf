# Harness review, 2026-10-25

Independent review_harness found: missing mandatory request-bypass zero gate; argparse abbreviation could
silently install defaultD instead of requestedD; relative manifest configs broke supervisorcwd; tagged
reference_rest defaults unsupported. api_harness reproduced RED then fixed all four. 118focusedtests passed.
Independent scopedre-review approved allfixes; fresh13passed/13deselected. No hardware touched.

Initial APIimplementation suites: protocol887passed/4privilegedskipped; installer/profile/freeze67passed;
candidate-series24passed; finalfocused27passed. Physicalqualification remainspending.
