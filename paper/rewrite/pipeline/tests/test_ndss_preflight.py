#!/usr/bin/env python3
"""Tests for the venue page-budget rule. No PDF, no LaTeX: the classifier is fed page texts.

The rule has been wrong twice in the same way, by throwing away a whole page because an excluded
section began on it, and once by recognising resumed body only through numbered headings, which
misses the Open Science section that the venue counts. These cases pin all of that down.

    python3 -m pytest paper/rewrite/pipeline/tests -q
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.dirname(HERE)
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)

from ndss_preflight import count_body                                   # noqa: E402

BODY = "I. I NTRODUCTION\nsome body text that runs on for a while\n"
MORE = "II. D ESIGN\nmore body text\n"
ETHICS = "E THICS C ONSIDERATIONS\nno human subjects were involved\n"
OPEN = "O PEN S CIENCE\nthe captures and the analysis are released\n"
REFS = "R EFERENCES\n[1] a citation\n[2] another citation\n"
APPX = "A PPENDIX\nsupporting material\n"


class TestPageBudgetRule(unittest.TestCase):

    def test_a_page_where_ethics_begins_still_counts(self):
        """The defect: counting to the page before Ethics lost a page of Conclusion."""
        pages = [BODY, MORE, "body continues\n" + ETHICS, REFS]
        body, ref, eth = count_body(pages)
        self.assertEqual((body, ref, eth), (3, 4, 3))

    def test_open_science_after_ethics_is_body(self):
        """The venue excludes Ethics, references and appendices, and nothing else."""
        pages = [BODY, MORE, ETHICS, OPEN, REFS]
        body, _, _ = count_body(pages)
        self.assertEqual(body, 3, "two body pages plus the Open Science page")

    def test_a_page_of_ethics_alone_is_not_counted(self):
        pages = [BODY, MORE, ETHICS, "ethics text continues\n", OPEN, REFS]
        body, _, _ = count_body(pages)
        self.assertEqual(body, 3, "both ethics-only pages are excluded, Open Science is not")

    def test_body_above_the_references_heading_still_counts(self):
        """The second defect: everything from the References page onward was excluded."""
        pages = [BODY, MORE, OPEN + "\nmore open science\n" + REFS, "[3] more citations\n"]
        body, ref, _ = count_body(pages)
        self.assertEqual(ref, 3)
        self.assertEqual(body, 3, "the page carrying Open Science above References is body")

    def test_appendices_are_excluded(self):
        pages = [BODY, MORE, APPX, "appendix continues\n"]
        body, _, _ = count_body(pages)
        self.assertEqual(body, 2, "the appendix heading sits at the top of its page")

    def test_a_blank_page_counts_as_nothing(self):
        pages = [BODY, "   \n", MORE, ETHICS, REFS]
        body, _, _ = count_body(pages)
        self.assertEqual(body, 2)

    def test_the_rule_cannot_pass_a_paper_by_hiding_body_after_ethics(self):
        """A layout that resumes body after Ethics must not escape the count."""
        pages = [BODY, MORE, ETHICS, MORE, MORE, REFS]
        body, _, _ = count_body(pages)
        self.assertEqual(body, 4, "resumed numbered sections are body again")


if __name__ == "__main__":
    unittest.main()
