from __future__ import annotations

import re
import unittest
from pathlib import Path


class WorkflowTests(unittest.TestCase):
    def test_external_actions_use_reviewed_full_commit_pins(self) -> None:
        workflow = Path(__file__).parents[1] / ".github" / "workflows" / "test.yml"
        refs = re.findall(r"^\s*- uses: (actions/[^\s]+)", workflow.read_text(), re.MULTILINE)

        self.assertEqual(
            refs,
            [
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            ],
        )
        self.assertTrue(all(re.fullmatch(r"actions/[^@]+@[0-9a-f]{40}", ref) for ref in refs))


if __name__ == "__main__":
    unittest.main()
