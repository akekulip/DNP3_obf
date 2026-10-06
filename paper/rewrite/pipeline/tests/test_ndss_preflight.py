#!/usr/bin/env python3
"""Tests for the venue page-budget rule. No PDF, no LaTeX: the classifier is fed page texts.

The rule has been wrong three times: by throwing away a whole page because an excluded section
began on it; by recognising resumed body only through numbered headings, which misses the Open
Science section that the venue counts; and by reading a two-column page in interleaved-y order,
which puts a heading low in the left column after one high in the right column and so misreports
which region the page ends in. These cases pin all of that down.

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

from ndss_preflight import count_body, reading_order                  # noqa: E402

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


class ReadingOrder(unittest.TestCase):
    """Two-column reading order: the whole left column, then the whole right column."""

    W = 612.0
    # (y, x_min, x_max, text). Left column x in [72, 290]; right column x in [320, 540].

    def test_left_column_is_read_before_right(self):
        lines = [
            (100.0, 72.0, 290.0, "left top"),
            (110.0, 320.0, 540.0, "right top"),
            (600.0, 72.0, 216.0, "VIII. CONCLUSION"),
            (590.0, 320.0, 492.0, "ETHICS CONSIDERATIONS"),
        ]
        self.assertEqual(
            reading_order(lines, self.W),
            ["left top", "VIII. CONCLUSION", "right top", "ETHICS CONSIDERATIONS"],
            "the left-column heading at y=600 precedes the right-column heading at y=590")

    def test_full_width_line_splits_the_page_into_bands(self):
        lines = [
            (50.0, 72.0, 540.0, "TITLE SPANNING BOTH COLUMNS"),
            (100.0, 72.0, 290.0, "left"),
            (105.0, 320.0, 540.0, "right"),
        ]
        self.assertEqual(reading_order(lines, self.W),
                         ["TITLE SPANNING BOTH COLUMNS", "left", "right"])

    def test_single_column_page_keeps_its_order(self):
        lines = [(100.0, 72.0, 290.0, "a"), (120.0, 72.0, 290.0, "b"),
                 (140.0, 72.0, 290.0, "c")]
        self.assertEqual(reading_order(lines, self.W), ["a", "b", "c"])

    def test_page_thirteen_shape_ends_inside_the_excluded_region(self):
        """The real failure: Conclusion sits below Ethics on the page but is read first."""
        page13 = "\n".join(reading_order([
            (300.0, 72.0, 290.0, "related work text"),
            (602.9, 132.0, 216.0, "VIII. C ONCLUSION"),
            (620.0, 72.0, 290.0, "conclusion body"),
            (335.6, 405.0, 469.0, "O PEN S CIENCE"),
            (592.2, 382.0, 492.0, "E THICS C ONSIDERATIONS"),
        ], self.W))
        body, _, ethics = count_body([page13, "ethics continued, no heading"])
        self.assertEqual(ethics, 1)
        self.assertEqual(body, 1, "the page that continues Ethics is not body")


if __name__ == "__main__":
    unittest.main()
