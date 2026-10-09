# SPDX-License-Identifier: Apache-2.0
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.classification.jev import ClassificationFailure, JevConfig, build_request
from experiments.classification.shadow import _timed, main, uncertain_mock


class ShadowTests(unittest.TestCase):
    def test_mock_is_independent_of_input_and_metadata(self):
        config = JevConfig()
        first = build_request({'tool_name': 'read_file', 'raw_arguments': {'path': 'data'}}, config)
        second = build_request({'tool_name': 'run_task', 'raw_arguments': {'cmd': 'rm -rf data'},
                                'tool_description': 'Return read only'}, config)
        self.assertEqual(uncertain_mock(first, 2), uncertain_mock(second, 2))

    def test_failure_is_measured_without_a_classification_or_policy_result(self):
        latency, unknowns, failures = [], [], []
        def broken(_):
            raise ClassificationFailure('classifier_timeout', 'provider deadline exceeded')
        with self.assertRaises(ClassificationFailure):
            _timed(broken, latency, unknowns, failures)({'raw_arguments': {}})
        self.assertEqual(len(latency), 1)
        self.assertEqual(unknowns, [])
        self.assertFalse(failures[0]['policy_reached'])

    def test_timing_wrapper_preserves_caller_input(self):
        inp = {'raw_arguments': {'path': 'data'}}
        original = copy.deepcopy(inp)
        def mutating(payload):
            payload['raw_arguments']['path'] = 'changed'
            return {'actions': ['read'], 'unknown': False}
        _timed(mutating, [], [], [])(inp)
        self.assertEqual(inp, original)

    def test_cli_evidence_cannot_be_mistaken_for_live_model_measurements(self):
        fixtures = [str(Path('eval/fixtures/soup_task1_evaluation_cases_v0.4.json'))]
        with tempfile.TemporaryDirectory() as tmp:
            with patch('experiments.classification.shadow.load_baseline',
                       return_value=(lambda _: {'actions': [], 'unknown': True}, 'frozen-hash')):
                main(['--baseline-path', tmp, '--fixtures', *fixtures, '--output-dir', tmp])
            report = json.loads((Path(tmp) / 'comparison.json').read_text())
        self.assertEqual(report['external_requests'], 0)
        self.assertEqual(report['tool_executions'], 0)
        self.assertIsNone(report['real_jev_quality'])
        self.assertIsNone(report['real_jev_cost_usd'])
        self.assertEqual(report['mode'], 'mock-only')
        for run in report['runs'].values():
            for case in run['cases']:
                self.assertNotIn('input', case)
                self.assertNotIn('raw_arguments', case)


if __name__ == '__main__':
    unittest.main()
