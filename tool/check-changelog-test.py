#!/usr/bin/env python3
"""Tests of tool/check-changelog.py, run by `make check`: each rule broken alone gives its
exact error, and the tree's own changelog and crates pass."""

import importlib.util
import pathlib
import sys
import tempfile
import unittest

# Loading the checker writes no __pycache__ in tool/.
sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_changelog", HERE / "check-changelog.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

UPGRADING = "### Upgrading\n\n- Nothing to do.\n"


def release(version: str, date: str, body: str = UPGRADING) -> str:
    return f"## {version} — {date}\n\n{body}\n"


def changelog(*releases: str, unreleased: str = "") -> str:
    return "# Changelog\n\nWhat changed.\n\n## Unreleased\n\n" + unreleased + "\n" + "".join(releases)


GOOD = changelog(
    release("0.2.0", "2026-12-01", UPGRADING + "\n### Added\n\n- A thing.\n\n### Fixed\n\n- A bug.\n"),
    release("0.1.1", "2026-11-20"),
    release("0.1.0", "2026-11-15"),
    unreleased="### Added\n\n- Something new.\n",
)


class Rules(unittest.TestCase):
    def assert_errors(self, text: str, workspace: str, expected: list[str]):
        self.assertEqual(checker.check(text, workspace), expected)

    def test_a_good_changelog_passes(self):
        self.assert_errors(GOOD, "0.2.0", [])
        # An empty Unreleased, and one release only, pass too.
        self.assert_errors(changelog(release("0.1.0", "2026-11-15")), "0.1.0", [])

    def test_the_version_moved_with_no_release(self):
        self.assert_errors(
            GOOD,
            "0.3.0",
            [
                "the workspace is 0.3.0 but the newest release is 0.2.0: the version moves "
                "only with its release, and a release only with the version"
            ],
        )

    def test_a_release_added_with_the_version_not_moved(self):
        self.assert_errors(
            GOOD,
            "0.1.1",
            [
                "the workspace is 0.1.1 but the newest release is 0.2.0: the version moves "
                "only with its release, and a release only with the version"
            ],
        )

    def test_no_release_at_all(self):
        self.assert_errors(
            changelog(), "0.1.0", ["no release: the workspace is 0.1.0, and it needs its release"]
        )

    def test_a_version_released_twice(self):
        text = changelog(release("0.1.0", "2026-11-16"), release("0.1.0", "2026-11-15"))
        self.assert_errors(text, "0.1.0", ["line 14: 0.1.0 is released twice (line 8 too)"])

    def test_releases_out_of_order(self):
        text = changelog(release("0.1.0", "2026-11-15"), release("0.2.0", "2026-11-15"))
        self.assert_errors(
            text,
            "0.1.0",
            ["line 14: 0.2.0 is below a lower version: newest first"],
        )
        # Compared as numbers, not text: 0.10.0 is above 0.9.0.
        text = changelog(release("0.10.0", "2026-11-16"), release("0.9.0", "2026-11-15"))
        self.assert_errors(text, "0.10.0", [])

    def test_dates_out_of_order(self):
        text = changelog(release("0.2.0", "2026-11-15"), release("0.1.0", "2026-11-16"))
        self.assert_errors(
            text, "0.2.0", ["line 14: 0.1.0 is dated after the release above it"]
        )
        # The same day, two releases: fine.
        text = changelog(release("0.2.0", "2026-11-15"), release("0.1.0", "2026-11-15"))
        self.assert_errors(text, "0.2.0", [])

    def test_a_version_that_is_not_semver(self):
        for bad in ["v0.1.0", "0.1", "01.0.0", "0.1.0-rc.1", "0.1.0.0"]:
            with self.subTest(bad=bad):
                self.assert_errors(
                    changelog(release(bad, "2026-11-15")),
                    "0.1.0",
                    [
                        f"line 8: {bad!r} is not a version (MAJOR.MINOR.PATCH, no leading zero)",
                        "no release: the workspace is 0.1.0, and it needs its release",
                    ],
                )

    def test_a_date_that_is_not_one(self):
        for bad in ["2026-13-01", "2026-02-30", "15-11-2026", "20261115", "2026-11-15T00:00"]:
            with self.subTest(bad=bad):
                self.assert_errors(
                    changelog(release("0.1.0", bad)),
                    "0.1.0",
                    [
                        f"line 8: {bad!r} is not a date (YYYY-MM-DD)",
                        "no release: the workspace is 0.1.0, and it needs its release",
                    ],
                )

    def test_a_release_heading_in_another_shape(self):
        text = changelog("## [0.1.0] - 2026-11-15\n\n" + UPGRADING)
        self.assert_errors(
            text,
            "0.1.0",
            [
                "line 8: a release is '## <version> — <YYYY-MM-DD>': '## [0.1.0] - 2026-11-15'",
                "no release: the workspace is 0.1.0, and it needs its release",
            ],
        )

    def test_a_release_without_upgrading_first(self):
        text = changelog(release("0.1.0", "2026-11-15", "### Added\n\n- A thing.\n"))
        self.assert_errors(text, "0.1.0", ["line 8: 0.1.0 starts with '### Upgrading'"])

    def test_an_unknown_section(self):
        text = changelog(
            release("0.1.0", "2026-11-15", UPGRADING + "\n### Improved\n\n- A thing.\n")
        )
        self.assert_errors(
            text,
            "0.1.0",
            [
                "line 14: unknown section 'Improved': one of Upgrading, Added, Changed, "
                "Deprecated, Removed, Fixed, Security"
            ],
        )

    def test_sections_out_of_order_or_twice(self):
        body = UPGRADING + "\n### Fixed\n\n- A bug.\n\n### Added\n\n- A thing.\n"
        self.assert_errors(
            changelog(release("0.1.0", "2026-11-15", body)),
            "0.1.0",
            [
                "line 8: the sections are in this order: Upgrading, Added, Changed, "
                "Deprecated, Removed, Fixed, Security"
            ],
        )
        body = UPGRADING + "\n### Added\n\n- A thing.\n\n### Added\n\n- Another.\n"
        self.assert_errors(
            changelog(release("0.1.0", "2026-11-15", body)),
            "0.1.0",
            ["line 14: 'Added' twice in one release", "line 18: 'Added' twice in one release"],
        )

    def test_an_empty_section(self):
        body = UPGRADING + "\n### Added\n\nNothing listed.\n"
        self.assert_errors(
            changelog(release("0.1.0", "2026-11-15", body)),
            "0.1.0",
            ["line 14: 'Added' has no '- ' item"],
        )

    def test_unreleased_missing_or_not_first(self):
        text = "# Changelog\n\n" + release("0.1.0", "2026-11-15")
        self.assert_errors(text, "0.1.0", ["the first '## ' heading is '## Unreleased'"])
        text = "# Changelog\n\n" + release("0.1.0", "2026-11-15") + "## Unreleased\n"
        self.assert_errors(
            text,
            "0.1.0",
            [
                "the first '## ' heading is '## Unreleased'",
                "line 9: '## Unreleased' comes first, once",
            ],
        )

    def test_headings_out_of_place(self):
        text = "Changelog\n\n## Unreleased\n\n# Again\n\n#### Deep\n\n" + release("0.1.0", "2026-11-15")
        self.assert_errors(
            text,
            "0.1.0",
            [
                "line 1: the file starts with '# Changelog'",
                "line 5: one '# ' heading only, the first line",
                "line 7: only '## ' releases and '### ' sections: '#### Deep'",
            ],
        )

    def test_the_workspace_version_must_be_one(self):
        self.assert_errors(
            GOOD, "", ["the workspace's version '' is not MAJOR.MINOR.PATCH"]
        )


class Crates(unittest.TestCase):
    def test_a_crate_with_its_own_version_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, line in [
                ("good", "version.workspace = true"),
                ("own", 'version = "0.1.0"'),
                ("none", ""),
            ]:
                (root / "crates" / name).mkdir(parents=True)
                (root / "crates" / name / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\n{line}\n'
                )
            self.assertEqual(
                checker.crate_errors(root),
                [
                    "crates/none/Cargo.toml: the crate takes the workspace's version "
                    "(version.workspace = true)",
                    "crates/own/Cargo.toml: the crate takes the workspace's version "
                    "(version.workspace = true)",
                ],
            )


class Tree(unittest.TestCase):
    def test_the_tree_passes(self):
        self.assertEqual(checker.main(), 0)


if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-q"], exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
