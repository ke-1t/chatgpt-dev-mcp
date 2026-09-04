from __future__ import annotations

import unittest

from chatgpt_dev_mcp.git_hunks import (
    GitHunkSelectionError,
    build_hunk_patch,
    enumerate_file_hunks,
)


_TWO_HUNK_DIFF = """diff --git a/demo.txt b/demo.txt
index 1111111..2222222 100644
--- a/demo.txt
+++ b/demo.txt
@@ -1,3 +1,3 @@
 one
-two
+TWO
 three
@@ -8,3 +8,3 @@
 eight
-nine
+NINE
 ten
"""


class GitHunkModelTests(unittest.TestCase):
    def test_enumerates_stable_content_derived_hunks(self) -> None:
        first = enumerate_file_hunks("demo.txt", _TWO_HUNK_DIFF)
        second = enumerate_file_hunks("demo.txt", _TWO_HUNK_DIFF)

        self.assertEqual(len(first), 2)
        self.assertEqual([h.hunk_id for h in first], [h.hunk_id for h in second])
        self.assertNotEqual(first[0].hunk_id, first[1].hunk_id)
        self.assertTrue(first[0].hunk_id.startswith("hunk:"))

    def test_builds_patch_with_only_selected_hunk(self) -> None:
        hunks = enumerate_file_hunks("demo.txt", _TWO_HUNK_DIFF)
        selection = build_hunk_patch("demo.txt", _TWO_HUNK_DIFF, [hunks[1].hunk_id])

        self.assertIn("-nine", selection.patch)
        self.assertIn("+NINE", selection.patch)
        self.assertNotIn("-two", selection.patch)
        self.assertNotIn("+TWO", selection.patch)
        self.assertEqual(selection.hunk_ids, (hunks[1].hunk_id,))

    def test_rejects_unsupported_or_unknown_hunks(self) -> None:
        with self.assertRaises(GitHunkSelectionError) as unsupported:
            enumerate_file_hunks(
                "demo.txt",
                "diff --git a/demo.txt b/demo.txt\nnew file mode 100644\n--- /dev/null\n+++ b/demo.txt\n@@ -0,0 +1 @@\n+x\n",
            )
        self.assertEqual(unsupported.exception.code, "GIT_HUNK_UNSUPPORTED_CHANGE")

        with self.assertRaises(GitHunkSelectionError) as unknown:
            build_hunk_patch("demo.txt", _TWO_HUNK_DIFF, ["hunk:" + "0" * 64])
        self.assertEqual(unknown.exception.code, "GIT_HUNK_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
