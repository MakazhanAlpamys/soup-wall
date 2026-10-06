# SPDX-License-Identifier: Apache-2.0
"""Exercise the documentation checker CLI against real, disposable Git repositories."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_docs.py"


class DocumentationLinks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="soup-wall-docs-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True, capture_output=True, text=True,
        )

    def write(self, relative, content, tracked=True):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        if tracked:
            self.git("add", "--", relative)

    def check(self, directory=None):
        return subprocess.run(
            [sys.executable, "-I", "-B", str(SCRIPT)],
            cwd=directory or self.root, capture_output=True, text=True,
        )

    def assert_success(self, result, markdown_files, local_links):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"{markdown_files} Markdown files", result.stdout)
        self.assertIn(f"{local_links} local links", result.stdout)

    def assert_problem(self, result, *details):
        self.assertNotEqual(result.returncode, 0)
        for detail in details:
            self.assertIn(detail, result.stdout + result.stderr)

    def test_nested_links_and_duplicate_heading_anchors_are_resolved_from_each_file(self):
        self.write("README.md", "# Home\n[Nested](docs/nested/readme.md#setup)\n")
        self.write("docs/nested/readme.md", "# Setup\n## Setup\n"
                   "[Again](#setup-1)\n[Home](../../README.md#home)\n")
        self.assert_success(self.check(), markdown_files=2, local_links=3)

    def test_missing_local_file_is_reported_with_source_line(self):
        self.write("README.md", "# Home\n[Missing](missing.md)\n")
        self.assert_problem(self.check(), "README.md:2", "missing.md", "missing file")

    def test_missing_heading_in_existing_markdown_is_rejected(self):
        self.write("README.md", "[Missing](guide.md#absent)\n")
        self.write("guide.md", "# Present\n")
        self.assert_problem(self.check(), "README.md:1", "#absent", "missing heading")

    def test_duplicate_anchor_does_not_exist_until_a_second_heading(self):
        self.write("README.md", "# Setup\n[Missing](#setup-1)\n")
        self.assert_problem(self.check(), "#setup-1", "missing heading")

    def test_fenced_samples_are_ignored_including_their_heading_candidates(self):
        self.write("README.md", "# Home\n```markdown\n[Missing](missing.md)\n"
                   "# Home\n```\n~~~markdown\n![Missing](missing.png)\n~~~\n"
                   "[Home](#home)\n")
        self.assert_success(self.check(), markdown_files=1, local_links=1)

    def test_a_heading_inside_a_fence_does_not_create_an_anchor(self):
        self.write("README.md", "```markdown\n# Hidden\n```\n[Missing](#hidden)\n")
        self.assert_problem(self.check(), "#hidden", "missing heading")

    def test_locally_present_ignored_note_is_not_a_versioned_target(self):
        self.write(".gitignore", "personal/\n")
        self.write("personal/note.md", "# Private\n", tracked=False)
        self.write("README.md", "[Private](personal/note.md)\n")
        self.assert_problem(self.check(), "personal/note.md", "not Git-tracked")

    def test_locally_present_untracked_file_is_not_a_versioned_target(self):
        self.write("note.txt", "private fixture", tracked=False)
        self.write("README.md", "[Note](note.txt)\n")
        self.assert_problem(self.check(), "note.txt", "not Git-tracked")

    def test_nonignored_new_markdown_is_checked_before_staging(self):
        self.write("README.md", "# Home\n")
        self.write("new.md", "[Missing](missing.md)\n", tracked=False)
        self.assert_problem(self.check(), "new.md:1", "missing.md", "missing file")

    def test_percent_encoded_paths_images_and_quoted_titles_are_supported(self):
        self.write("README.md", '[Guide](docs/space%20guide.md#next-step "A guide")\n'
                   "![Picture](assets/picture%20one.png 'A picture')\n")
        self.write("docs/space guide.md", "# Next step\n")
        self.write("assets/picture one.png", b"synthetic image fixture")
        self.assert_success(self.check(), markdown_files=2, local_links=2)

    def test_percent_encoded_heading_fragment_is_decoded(self):
        self.write("README.md", "# Next step\n[Next](#next%2Dstep)\n")
        self.assert_success(self.check(), markdown_files=1, local_links=1)

    def test_angle_bracket_destination_can_contain_spaces_and_a_title(self):
        self.write("README.md", '[Guide](<docs/space guide.md#hello-world> "Read me")\n')
        self.write("docs/space guide.md", "## Hello, *world*! ##\n")
        self.assert_success(self.check(), markdown_files=2, local_links=1)

    def test_directory_links_require_a_tracked_descendant(self):
        self.write("README.md", "[Sources](src/)\n")
        self.write("src/main.rs", "// synthetic fixture\n")
        self.assert_success(self.check(), markdown_files=1, local_links=1)

    def test_directory_containing_only_ignored_files_is_rejected(self):
        self.write(".gitignore", "personal/\n")
        self.write("personal/note.txt", "private fixture", tracked=False)
        self.write("README.md", "[Private](personal/)\n")
        self.assert_problem(self.check(), "personal/", "no Git-tracked files")

    def test_directory_with_only_deleted_tracked_descendants_is_rejected(self):
        self.write(".gitignore", "src/local.txt\n")
        self.write("src/main.rs", "// synthetic fixture\n")
        (self.root / "src/main.rs").unlink()
        self.write("src/local.txt", "local fixture", tracked=False)
        self.write("README.md", "[Sources](src/)\n")
        self.assert_problem(self.check(), "src/", "no Git-tracked files")

    def test_external_links_are_skipped_without_network_requests(self):
        self.write("README.md", "[Web](https://must-not-fetch.invalid/missing#fragment)\n"
                   "![Remote](//must-not-fetch.invalid/image.png)\n"
                   "[Email](mailto:fixture@example.invalid)\n")
        self.assert_success(self.check(), markdown_files=1, local_links=0)

    def test_local_html_image_source_is_checked(self):
        self.write("README.md", '<img alt="Fixture" src="assets/picture%20one.png">\n')
        self.write("assets/picture one.png", b"synthetic image fixture")
        self.assert_success(self.check(), markdown_files=1, local_links=1)

    def test_missing_html_image_source_is_rejected(self):
        self.write("README.md", '<img src="missing.png" alt="Fixture">\n')
        self.assert_problem(self.check(), "README.md:1", "missing.png", "missing file")

    def test_html_image_checks_actual_src_instead_of_other_attributes(self):
        self.write("present.png", b"synthetic image fixture")
        for markup in ['<img data-src="present.png" src="missing.png">',
                       '<img alt=\'src="present.png"\' src="missing.png">']:
            with self.subTest(markup=markup):
                self.write("README.md", markup + "\n")
                self.assert_problem(self.check(), "missing.png", "missing file")

    def test_html_image_inside_a_fence_is_ignored(self):
        self.write("README.md", '```html\n<img src="missing.png">\n```\n')
        self.assert_success(self.check(), markdown_files=1, local_links=0)

    def test_inline_code_sample_does_not_create_a_link(self):
        self.write("README.md", "Use `[sample](missing.md)` as a syntax example.\n")
        self.assert_success(self.check(), markdown_files=1, local_links=0)

    def test_nested_image_link_checks_the_outer_destination(self):
        self.write("README.md", "[![Icon](icon.png)](missing.md)\n")
        self.write("icon.png", b"synthetic image fixture")
        self.assert_problem(self.check(), "missing.md", "missing file")

    def test_parenthesized_filename_and_parenthesized_title_are_supported(self):
        self.write("README.md", "[Guide](docs/guide(one).md (Read me))\n")
        self.write("docs/guide(one).md", "# Guide\n")
        self.assert_success(self.check(), markdown_files=2, local_links=1)

    def test_deleted_tracked_target_is_rejected(self):
        self.write("README.md", "[Gone](gone.txt)\n")
        self.write("gone.txt", "synthetic fixture")
        (self.root / "gone.txt").unlink()
        self.assert_problem(self.check(), "gone.txt", "missing file")

    def test_anchor_allocation_avoids_collisions_with_other_heading_slugs(self):
        self.write("README.md", "# A\n# A\n# A-1\n"
                   "[First](#a) [Second](#a-1) [Third](#a-1-1)\n")
        self.assert_success(self.check(), markdown_files=1, local_links=3)

    def test_relative_path_cannot_escape_the_repository(self):
        self.write("README.md", "[Outside](../outside.md)\n")
        self.assert_problem(self.check(), "../outside.md", "outside repository")

    def test_percent_encoded_path_cannot_escape_the_repository(self):
        for target in ["..%2Foutside.md", "%2Foutside.md"]:
            with self.subTest(target=target):
                self.write("README.md", f"[Outside]({target})\n")
                self.assert_problem(self.check(), target, "outside repository")

    def test_replaced_tracked_directory_is_not_read_through_a_symlink(self):
        self.write("README.md", "[Guide](docs/guide.md#guide)\n")
        self.write("docs/guide.md", "# Guide\n")
        (self.root / "docs").rename(self.root / "replacement")
        try:
            os.symlink(self.root / "replacement", self.root / "docs", target_is_directory=True)
        except OSError as error:
            self.skipTest(f"Creating a test symlink is unavailable: {error}")
        self.assert_problem(self.check(), "docs/guide.md", "symlink or reparse")

    def test_running_from_a_nested_directory_uses_the_git_root(self):
        self.write("README.md", "[Guide](docs/guide.md)\n")
        self.write("docs/guide.md", "# Guide\n")
        self.assert_success(self.check(self.root / "docs"), markdown_files=2, local_links=1)

    def test_diagnostics_are_sorted_by_repository_path_then_source_line(self):
        self.write("z.md", "[First](first.md)\n[Second](second.md)\n")
        self.write("a.md", "[Earlier](earlier.md)\n")
        result = self.check()
        self.assert_problem(result, "a.md:1", "z.md:1", "z.md:2")
        diagnostics = result.stdout + result.stderr
        self.assertLess(diagnostics.index("a.md:1"), diagnostics.index("z.md:1"))
        self.assertLess(diagnostics.index("z.md:1"), diagnostics.index("z.md:2"))


if __name__ == "__main__":
    unittest.main()
