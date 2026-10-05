# SPDX-License-Identifier: Apache-2.0
"""Fidelity and fail-closed tests; neutral fixtures are not benchmark samples."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "history_import", Path(__file__).resolve().parents[1] / "import-agentdojo-history.py"
)
IMPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORT)
PATH = f"runs/{IMPORT.MODEL}/workspace/user_task_0/none/none.json"


def fixture():
    calls = [
        {"function": "search_calendar_events", "args": {"query": "résumé\nexact", "date": None}, "id": "one"},
        {"function": "get_current_day", "args": {}, "id": "two"},
    ]
    return {
        "suite_name": "workspace", "pipeline_name": IMPORT.MODEL,
        "user_task_id": "user_task_0", "injection_task_id": None,
        "attack_type": None, "error": None,
        "messages": [
            {"role": "system", "content": "Neutral system text"},
            {"role": "user", "content": "Neutral user request"},
            {"role": "assistant", "content": None, "tool_calls": calls},
            {"role": "tool", "tool_call_id": "two", "tool_call": calls[1], "content": "2024-01-01\n", "error": None},
            {"role": "tool", "tool_call_id": "one", "tool_call": calls[0], "content": "  Meeting\n\tLocation: room 7\n", "error": None},
            {"role": "assistant", "content": "Done", "tool_calls": None},
        ],
    }


class HistoryImportTests(unittest.TestCase):
    def test_parallel_call_and_result_order_values_and_names_survive(self):
        trace = fixture()
        before = copy.deepcopy(trace)
        session, metadata = IMPORT.project(trace, PATH)
        self.assertEqual(trace, before)
        events = session["events"]
        self.assertEqual([event["tool"] for event in events], [
            "search_calendar_events", "get_current_day", "get_current_day", "search_calendar_events"
        ])
        self.assertEqual(events[0]["args"], trace["messages"][2]["tool_calls"][0]["args"])
        self.assertEqual(events[3]["content"], trace["messages"][4]["content"])
        self.assertEqual(events[2]["source"], {"origin": "local_system"})
        self.assertEqual(metadata["event_count"], 4)
        self.assertNotIn("Neutral user request", str(events))

    def test_output_cannot_change_its_original_call_or_invent_one(self):
        for mutation in ("changed_args", "unknown_id", "duplicate_result"):
            with self.subTest(mutation=mutation):
                trace = fixture()
                if mutation == "changed_args":
                    trace["messages"][4]["tool_call"] = copy.deepcopy(trace["messages"][4]["tool_call"])
                    trace["messages"][4]["tool_call"]["args"]["query"] = "changed"
                elif mutation == "unknown_id":
                    trace["messages"][4]["tool_call_id"] = "not-a-call"
                else:
                    trace["messages"].append(trace["messages"][4])
                with self.assertRaises(ValueError):
                    IMPORT.project(trace, PATH)

    def test_incomplete_or_multimodal_trace_is_not_silently_adapted(self):
        for mutation in ("unfinished", "multimodal", "mcp_name", "upstream_error"):
            with self.subTest(mutation=mutation):
                trace = fixture()
                if mutation == "unfinished":
                    del trace["messages"][4]
                elif mutation == "multimodal":
                    trace["messages"][4]["content"] = [{"type": "text", "content": "plain"}]
                elif mutation == "mcp_name":
                    trace["messages"][2]["tool_calls"][0]["function"] = "mcp__invented__search"
                else:
                    trace["error"] = "Neutral run error"
                with self.assertRaises(ValueError):
                    IMPORT.project(trace, PATH)

    def test_attack_label_means_attempt_even_if_original_model_resisted(self):
        trace = fixture()
        trace.update({"attack_type": "direct", "injection_task_id": "injection_task_0", "security": False})
        session, _ = IMPORT.project(trace, PATH.replace("none/none.json", "direct/injection_task_0.json"))
        self.assertEqual(session["label"], "attack")

    def test_selection_is_tree_order_independent_and_has_matching_benign_tasks(self):
        entries = []
        for task in range(40):
            prefix = f"runs/{IMPORT.MODEL}/workspace/user_task_{task}/"
            for suffix in ("none/none.json", "direct/injection_task_0.json", "tool_knowledge/injection_task_1.json"):
                entries.append({"path": prefix + suffix, "type": "blob", "sha": "0" * 40})
        selected, candidates = IMPORT.select({"truncated": False, "tree": entries})
        reversed_selection, _ = IMPORT.select({"truncated": False, "tree": list(reversed(entries))})
        self.assertEqual(selected, reversed_selection)
        self.assertEqual(candidates, 80)
        self.assertEqual(len(selected), 80)
        for task in range(40):
            self.assertIn(f"user_task_{task}/none/none.json", selected[2 * task]["path"])
            self.assertIn(f"user_task_{task}/", selected[2 * task + 1]["path"])
        with self.assertRaises(ValueError):
            IMPORT.select({"truncated": True, "tree": entries})
        with self.assertRaises(ValueError):
            IMPORT.select({"truncated": False, "tree": entries[3:]})

    def test_writes_cannot_leave_ignored_datasets_or_overwrite_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "datasets/existing").mkdir(parents=True)
            with patch.object(IMPORT, "ROOT", root):
                for path in (root / "outside", root / "datasets/existing", root / "datasets"):
                    with self.assertRaises(ValueError):
                        IMPORT.destination(path)
                self.assertEqual(IMPORT.destination(root / "datasets/new"), root / "datasets/new")

    def test_git_object_and_sha256_bind_exact_original_bytes(self):
        self.assertEqual(IMPORT.git_blob(b"test\n"), "9daeafb9864cf43055ae93beb0afd6c7d144bfa4")
        self.assertNotEqual(IMPORT.digest(b"test\n"), IMPORT.digest(b"test"))
        with self.assertRaises(ValueError):
            IMPORT.parse_json(b'{"x":NaN}')

    def test_datasets_base_cannot_redirect_raw_data_to_unignored_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            base = root / "datasets"
            original_resolve = Path.resolve
            for redirected_base in (root, root / "unignored"):
                # Canonical behavior of either a directory symlink or junction;
                # no Windows link privilege or filesystem mutation is needed.
                def redirected(path, *args, **kwargs):
                    if path.is_relative_to(base):
                        return redirected_base / path.relative_to(base)
                    return original_resolve(path, *args, **kwargs)

                with self.subTest(target=redirected_base), patch.object(IMPORT, "ROOT", root), \
                     patch.object(Path, "resolve", autospec=True, side_effect=redirected):
                    with self.assertRaises(ValueError):
                        IMPORT.destination(base / "fresh-run")


if __name__ == "__main__":
    unittest.main()
