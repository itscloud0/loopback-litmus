from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]
RELEASE_COMMIT = "26c01e802e33ca4b285e1f4ba1149d0f20b50135"
RELEASE_WHEEL_URL = (
    "https://github.com/itscloud0/loopback-litmus/releases/download/"
    "v0.1.0/loopback_litmus-0.1.0-py3-none-any.whl"
)
RELEASE_SDIST_URL = (
    "https://github.com/itscloud0/loopback-litmus/releases/download/"
    "v0.1.0/loopback_litmus-0.1.0.tar.gz"
)


class OnboardingTests(unittest.TestCase):
    def test_readme_offers_direct_release_artifacts(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn(RELEASE_WHEEL_URL, readme)
        self.assertIn(RELEASE_SDIST_URL, readme)

    def test_readme_offers_git_free_immutable_release_archive(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        archive_url = (
            "https://github.com/itscloud0/loopback-litmus/"
            f"archive/{RELEASE_COMMIT}.tar.gz"
        )

        self.assertIn("If Git is not available", readme)
        self.assertIn(archive_url, readme)

    def test_public_install_ci_smokes_the_same_archive(self) -> None:
        workflow = (
            PROJECT_ROOT / ".github" / "workflows" / "test.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            f"https://github.com/itscloud0/loopback-litmus/archive/{RELEASE_COMMIT}.tar.gz",
            workflow,
        )
        self.assertIn("loopback-litmus scan --known-agent-ports --json", workflow)

    def test_public_install_ci_smokes_the_release_artifacts(self) -> None:
        workflow = (
            PROJECT_ROOT / ".github" / "workflows" / "test.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(RELEASE_WHEEL_URL, workflow)
        self.assertIn(RELEASE_SDIST_URL, workflow)


if __name__ == "__main__":
    unittest.main()
