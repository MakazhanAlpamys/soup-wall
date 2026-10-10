# SPDX-License-Identifier: Apache-2.0
"""Regression checks for a custodian's shared pilot ledger, using toy inputs only."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from experiments.local_classifier.pilot import main, reserve_reviewed_run, toy_data


class ReviewedRunLedger(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.model = self.root / 'model'
        self.model.mkdir()
        self.ledger = self.root / 'custodian-ledger'
        self.ledger.mkdir()
        self.authorization = self.root / 'run.json'
        self.record = {'format': 'soup-wall/classifier-run-authorization/1',
                       'run_id': 'unit-test-run', 'holdout_id': 'unit-test-heldout-family-set',
                       'approval_reference': 'UNIT TEST ONLY, NOT APPROVED DATA',
                       'dataset_sha256': 'd' * 64, 'model_sha256': 'a' * 64,
                       'baseline_sha256': 'b' * 64}
        self.save()

    def save(self):
        self.authorization.write_text(json.dumps(self.record), encoding='utf-8')

    def reserve(self, model=None):
        return reserve_reviewed_run(self.authorization, self.ledger, model or self.model,
                                    self.record['dataset_sha256'], self.record['model_sha256'], 'b' * 64)

    def test_artifact_copy_and_new_run_id_cannot_reuse_same_holdout(self):
        journal, reservation = self.reserve()
        self.assertEqual(json.loads(journal.read_text()), reservation)
        self.record['run_id'] = 'renamed-run'
        self.save()
        copied = self.root / 'copied-model'
        copied.mkdir()
        with self.assertRaises(FileExistsError):
            self.reserve(copied)

    def test_concurrent_reservations_allow_exactly_one_attempt(self):
        def attempt(_):
            try:
                self.reserve()
                return True
            except FileExistsError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)

    def test_unreviewed_or_mismatched_hashes_do_not_consume_holdout(self):
        for field, value in (('baseline_sha256', 'c' * 64), ('model_sha256', 'bad'),
                             ('dataset_sha256', None), ('approval_reference', ' '),
                             ('format', 'unreviewed'), ('holdout_id', ''), ('unexpected', True)):
            original = dict(self.record)
            self.record[field] = value
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.reserve()
            self.assertEqual(list(self.ledger.iterdir()), [])
            self.record = original

    def test_missing_or_artifact_local_ledger_is_rejected(self):
        for ledger in (self.root / 'absent', self.model, self.model / 'local-ledger'):
            with self.subTest(ledger=ledger), self.assertRaises(ValueError):
                reserve_reviewed_run(self.authorization, ledger, self.model, 'd' * 64, 'a' * 64, 'b' * 64)

    def test_authorization_copied_inside_artifacts_is_rejected(self):
        local = self.model / 'run.json'
        shutil.copyfile(self.authorization, local)
        with self.assertRaises(ValueError):
            reserve_reviewed_run(local, self.ledger, self.model, 'd' * 64, 'a' * 64, 'b' * 64)

    def prepare_training(self):
        dataset, approval = self.root / 'dataset.json', self.root / 'review.json'
        dataset.write_text(json.dumps(toy_data()), encoding='utf-8')
        dataset_hash = hashlib.sha256(dataset.read_bytes()).hexdigest()
        approval.write_text(json.dumps({'format': 'soup-wall/classifier-data-approval/1',
                            'approval_reference': 'UNIT TEST ONLY', 'source': 'unit toy data',
                            'license': 'Apache-2.0', 'dataset_sha256': dataset_hash}), encoding='utf-8')
        common = ['--dataset', str(dataset), '--approval', str(approval)]
        main(['train', *common, '--output-dir', str(self.model), '--epochs', '2', '--dimensions', '32'])
        self.record['dataset_sha256'] = dataset_hash
        self.record['model_sha256'] = hashlib.sha256((self.model / 'model.json').read_bytes()).hexdigest()
        self.save()
        return ['evaluate', *common, '--model-dir', str(self.model), '--baseline-path', str(self.root),
                '--run-authorization', str(self.authorization), '--run-ledger-dir', str(self.ledger)]

    def test_cli_requires_external_ledger_before_holdout_inference(self):
        args = self.prepare_training()
        with patch('experiments.local_classifier.pilot.evaluate') as evaluate, patch('sys.stderr'):
            with self.assertRaises(SystemExit):
                main(args[:-4])
            evaluate.assert_not_called()

    def test_completed_run_retains_receipt_and_refuses_copied_artifacts(self):
        args = self.prepare_training()
        copied = self.root / 'copied-model'
        shutil.copytree(self.model, copied)
        with patch('experiments.local_classifier.pilot.load_baseline',
                   return_value=(lambda _: {'actions': [], 'unknown': True}, 'b' * 64)):
            main(args)
            report = json.loads((self.model / 'evaluation.json').read_text())
            receipts = list(self.ledger.glob('*.result.json'))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text())
            self.assertEqual(receipt['evaluation_sha256'],
                             hashlib.sha256((self.model / 'evaluation.json').read_bytes()).hexdigest())
            self.assertEqual(report['reviewed_run']['authorization'], self.record)
            args[args.index('--model-dir') + 1] = str(copied)
            with patch('experiments.local_classifier.pilot.evaluate') as evaluate:
                with self.assertRaises(FileExistsError):
                    main(args)
                evaluate.assert_not_called()

    def test_interrupted_attempt_stays_consumed_without_success_receipt(self):
        args = self.prepare_training()
        with patch('experiments.local_classifier.pilot.load_baseline',
                   return_value=(lambda _: {'actions': [], 'unknown': True}, 'b' * 64)), \
                patch('experiments.local_classifier.pilot.evaluate', side_effect=RuntimeError('interrupted')):
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                main(args)
        self.assertEqual(len(list(self.ledger.glob('*.reserved.json'))), 1)
        self.assertEqual(list(self.ledger.glob('*.result.json')), [])
        with self.assertRaises(FileExistsError):
            self.reserve()


if __name__ == '__main__':
    unittest.main()
