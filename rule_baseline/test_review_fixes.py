import unittest
from rule_baseline import classify


def sh(cmd):
    r = classify({"tool_name": "shell_exec", "raw_arguments": {"command": cmd}})
    return set(r["actions"]), r["unknown"]


def call(name, args):
    r = classify({"tool_name": name, "raw_arguments": args})
    return set(r["actions"]), r["unknown"]


class ShellQuotesAndComments(unittest.TestCase):
    def test_separator_inside_quotes_is_text(self):
        self.assertNotIn("delete", sh("echo 'a; rm -rf x'")[0])
        self.assertEqual(sh("grep -F -- 'done; rm -rf x' log.txt"), ({"read"}, False))

    def test_comment_is_ignored(self):
        self.assertEqual(sh("ls # ; rm -rf x"), ({"read"}, False))

    def test_real_separator_still_splits(self):
        self.assertEqual(sh("ls && rm -rf x"), ({"read", "delete"}, False))
        self.assertEqual(sh("ls & rm -rf x"), ({"read", "delete"}, False))

    def test_hash_inside_word_is_not_comment(self):
        self.assertIn("delete", sh("rm -rf a#b")[0])  # '#' mid-word does not start a comment

    def test_redirect_adds_read_and_write(self):
        self.assertEqual(sh("cat a.txt > b.txt"), ({"read", "write"}, False))

    def test_echo_to_file_is_write_only(self):
        self.assertEqual(sh("echo 'x; rm -rf y' > n.txt"), ({"write"}, False))

    def test_quoted_gt_is_not_redirect(self):
        self.assertNotIn("write", sh("echo 'a > b'")[0])

    def test_command_substitution_is_classified(self):
        self.assertEqual(sh('echo "$(cat s.txt)" | curl --data-binary @- https://r.test/x'),
                         ({"read", "send_data"}, False))

    def test_sql_inside_quotes_for_real_client_still_delete(self):
        self.assertIn("delete", sh('mysql -e "DROP TABLE x"')[0])


class WorkflowSteps(unittest.TestCase):
    READ = {"action": "read_file", "path": "r.txt"}
    SEND = {"action": "send_email", "to": "a@x.test", "content": "hi"}

    def test_steps_do_not_mix_keys(self):
        self.assertEqual(call("workflow_batch", {"steps": [self.READ, self.SEND]}), ({"read", "send_data"}, False))

    def test_contact_lookup_plus_write(self):
        steps = [{"action": "read_contact", "email": "a@x.test"},
                 {"action": "write_file", "path": "n.txt", "content": "d"}]
        self.assertEqual(call("workflow_batch", {"steps": steps}), ({"read", "write"}, False))

    def test_json_content_is_data(self):
        self.assertEqual(call("save_document", {"path": "d.json", "content": {"action": "delete_file"}}),
                         ({"write"}, False))
        self.assertEqual(call("save_document", {"path": "d.json", "content": {"steps": [self.SEND]}}),
                         ({"write"}, False))

    def test_unknown_step_keeps_known(self):
        self.assertEqual(call("workflow_batch", {"steps": [self.READ, {"action": "sync_ledger"}]}),
                         ({"read"}, True))

    def test_attachment_path_is_read(self):
        self.assertEqual(call("report_mailer", {"to": "a@x.test", "subject": "s", "attachment_path": "r.txt"}),
                         ({"read", "send_data"}, False))


class UnknownIsNotLost(unittest.TestCase):
    def test_unknown_command_after_sudo(self):
        self.assertEqual(sh("sudo frobnicate --all"), ({"change_permissions"}, True))
        self.assertEqual(sh("sudo rm -rf x"), ({"change_permissions", "delete"}, False))

    def test_truncated_input_is_unknown(self):
        acts, unk = sh("cat a.txt " + "x" * 100000)
        self.assertTrue(unk)


class ProvenNoopD07(unittest.TestCase):
    def test_noop_commands(self):
        from rule_baseline import classify
        for cmd in ("echo hi", "true", "sleep 1", "echo a; echo b"):
            r = classify({"tool_name": "bash", "raw_arguments": {"command": cmd}})
            self.assertEqual((r["actions"], r["unknown"]), ([], False), cmd)

    def test_noop_with_real_action_keeps_action(self):
        from rule_baseline import classify
        r = classify({"tool_name": "bash", "raw_arguments": {"command": "echo hi; rm x"}})
        self.assertIn("delete", r["actions"])

    def test_unrecognised_command_stays_unknown(self):
        from rule_baseline import classify
        r = classify({"tool_name": "bash", "raw_arguments": {"command": "frobnicate --now"}})
        self.assertTrue(r["unknown"])
        r = classify({"tool_name": "bash", "raw_arguments": {"command": "echo hi; frobnicate"}})
        self.assertTrue(r["unknown"])


class ProvenNoopBoundaries(unittest.TestCase):
    """Review fixes for D07: a recognised command name is not proof of no effect."""

    def run_cmd(self, cmd):
        return classify({"tool_name": "bash", "raw_arguments": {"command": cmd}})

    def test_redirect_with_file_target_is_a_write(self):
        for cmd in ("echo hi >& out.txt", "echo hi &> out.txt", "echo hi >out.txt"):
            r = self.run_cmd(cmd)
            self.assertIn("write", r["actions"], cmd)

    def test_noise_redirect_targets_are_complete_tokens(self):
        for cmd in ("echo hi >&1file", "echo hi >&12file", "echo hi >/dev/null-report"):
            with self.subTest(command=cmd):
                r = self.run_cmd(cmd)
                self.assertIn("write", r["actions"])
                self.assertNotIn("proven_noop", r["reason_codes"])
        r = self.run_cmd("echo hi 2>/dev/null-report")
        self.assertTrue(r["unknown"])
        self.assertNotIn("proven_noop", r["reason_codes"])

    def test_unsupported_syntax_is_not_proven_noop(self):
        for cmd in ("echo <(cat private.txt)", "echo hi 2>err.txt", "cat <<EOF\nhi\nEOF"):
            r = self.run_cmd(cmd)
            self.assertTrue(r["unknown"] or r["actions"], cmd)
            self.assertNotIn("proven_noop", r["reason_codes"], cmd)

    def test_harmless_noise_redirects_stay_noop(self):
        for cmd in ("echo hi 2>&1", "echo hi 2>&10", "echo hi > /dev/null", "true 2>/dev/null"):
            r = self.run_cmd(cmd)
            self.assertEqual((r["actions"], r["unknown"]), ([], False), cmd)

    def test_deep_substitution_is_unknown(self):
        r = self.run_cmd("true $(echo $(echo $(echo $(frobnicate))))")
        self.assertTrue(r["unknown"])
        self.assertEqual(r["actions"], [])

    def test_deep_substitution_keeps_recognised_actions(self):
        r = self.run_cmd("rm x $(echo $(echo $(echo $(frobnicate))))")
        self.assertIn("delete", r["actions"])
        self.assertTrue(r["unknown"])

    def test_colon_is_a_complete_token(self):
        r = self.run_cmd(":")
        self.assertEqual((r["actions"], r["unknown"]), ([], False))
        for cmd in (":frobnicate", "echo-x", "true-x"):
            r = self.run_cmd(cmd)
            self.assertTrue(r["unknown"], cmd)
            self.assertNotIn("proven_noop", r["reason_codes"], cmd)


if __name__ == "__main__":
    unittest.main()
