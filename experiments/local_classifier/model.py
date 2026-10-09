# SPDX-License-Identifier: Apache-2.0
"""Independent sigmoid heads with masked labels and deterministic hashed features.

This is a newly trained linear reference candidate, not a pretrained language
model, encoder fine-tune, runtime policy or permission-granting component.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import re
from array import array
from dataclasses import asdict, dataclass

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')
HEADS = (*ACTIONS, 'unknown')
INPUT_KEYS = {'tool_name', 'tool_description', 'tool_schema', 'pinned_schema',
              'raw_arguments', 'server_id'}
FEATURE_VERSION = 'semantic-hash-v1-no-description'


def semantic_bytes(inp: dict) -> bytes:
    if not isinstance(inp, dict) or set(inp) - INPUT_KEYS:
        raise ValueError('only agreed semantic input fields are accepted')
    if not isinstance(inp.get('tool_name'), str) or not inp['tool_name']:
        raise ValueError('nonempty tool_name required')
    if 'raw_arguments' not in inp or inp['raw_arguments'] is None:
        raise ValueError('validated non-null actual arguments required')
    if inp.get('tool_description') is not None and not isinstance(inp['tool_description'], str):
        raise ValueError('description must be text or null')
    for key in ('tool_schema', 'pinned_schema'):
        if inp.get(key) is not None and not isinstance(inp[key], (dict, bool)):
            raise ValueError('schema must be an object, Boolean or null')
    if 'server_id' in inp and not isinstance(inp['server_id'], str):
        raise ValueError('server_id must be a string')
    budget = [0]
    def check(value, depth=0):
        budget[0] += 1
        if budget[0] > 2048 or depth > 16:
            raise ValueError('semantic input exceeds structural bounds')
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float and math.isfinite(value):
            return
        if isinstance(value, list):
            for child in value:
                check(child, depth + 1)
            return
        if isinstance(value, dict) and all(isinstance(k, str) for k in value):
            for child in value.values():
                check(child, depth + 1)
            return
        raise ValueError('semantic input must be finite JSON')
    check(inp)
    try:
        encoded = json.dumps(inp, sort_keys=True, ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise ValueError('semantic input is not encodable JSON') from exc
    if len(encoded) > 16384:
        raise ValueError('semantic input exceeds 16 KiB; no truncation')
    return encoded


def input_identity(inp: dict) -> str:
    semantic_bytes(inp)
    # Ignore presentation-only descriptions for cross-split leakage detection.
    core = {k: v for k, v in inp.items() if k != 'tool_description'}
    return hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def features(inp: dict, dimensions: int) -> tuple[int, ...]:
    semantic_bytes(inp)
    tokens = set()
    def visit(value, path):
        if isinstance(value, dict):
            for key, child in sorted(value.items()):
                tokens.add('key:' + path + ':' + key.lower())
                visit(child, path + '.' + key.lower())
        elif isinstance(value, list):
            for child in value:
                visit(child, path + '[]')
        else:
            for token in re.findall(r'[\w./:@+-]+|[;|><]', str(value).lower()):
                tokens.add(path + ':' + token)
    for key in ('tool_name', 'tool_schema', 'pinned_schema', 'raw_arguments', 'server_id'):
        if key in inp:
            visit(inp[key], key)
    if len(tokens) > 512:
        raise ValueError('semantic feature count exceeds 512; no truncation')
    return tuple(sorted({int.from_bytes(hashlib.sha256(t.encode('utf-8')).digest()[:8], 'big') % dimensions
                         for t in tokens}))


def sigmoid(value: float) -> float:
    if value >= 0:
        return 1 / (1 + math.exp(-value))
    exp = math.exp(value)
    return exp / (1 + exp)


@dataclass(frozen=True)
class Config:
    dimensions: int = 512
    epochs: int = 60
    learning_rate: float = 0.2
    l2: float = 0.0001
    seed: int = 42

    def __post_init__(self):
        if type(self.dimensions) is not int or not 16 <= self.dimensions <= 16384:
            raise ValueError('dimensions must be an integer in [16,16384]')
        if type(self.epochs) is not int or not 1 <= self.epochs <= 1000 or type(self.seed) is not int:
            raise ValueError('bounded integer epochs and integer seed required')
        for value in (self.learning_rate, self.l2):
            if type(value) not in (int, float) or not 0 <= value <= 1:
                raise ValueError('finite learning rate and regularization in [0,1] required')
        if self.learning_rate == 0:
            raise ValueError('learning rate must be positive')


def check_labels(labels: dict) -> None:
    if not isinstance(labels, dict) or set(labels) != set(HEADS):
        raise ValueError('five action labels plus separate unknown label required')
    if any(v is not None and type(v) is not bool for v in labels.values()):
        raise ValueError('labels must be true, false or null; null is never negative')
    if labels['unknown'] is False and any(labels[a] is None for a in ACTIONS):
        raise ValueError('unknown=false contradicts an undetermined action label')


class LinearClassifier:
    def __init__(self, config: Config):
        self.config = config
        self.weights = [array('d', [0.0]) * config.dimensions for _ in HEADS]
        self.bias = [0.0] * len(HEADS)
        self.seen_features: set[int] = set()
        self.known_labels = {h: 0 for h in HEADS}
        self.low, self.high = 0.2, 0.8
        self.calibrated = False

    def probabilities(self, inp: dict) -> dict:
        active = features(inp, self.config.dimensions)
        scale = 1 / math.sqrt(max(1, len(active)))
        return {head: sigmoid(self.bias[index] + scale * sum(self.weights[index][j] for j in active))
                for index, head in enumerate(HEADS)}

    def update(self, inp: dict, labels: dict) -> None:
        check_labels(labels)
        active = features(inp, self.config.dimensions)
        if all(labels[head] is None for head in HEADS):
            return
        scale = 1 / math.sqrt(max(1, len(active)))
        self.seen_features.update(active)
        for index, head in enumerate(HEADS):
            if labels[head] is None:
                continue  # This head receives no loss, decay or gradient for this row.
            probability = sigmoid(self.bias[index] + scale * sum(self.weights[index][j] for j in active))
            gradient = probability - float(labels[head])
            for j in active:
                self.weights[index][j] -= self.config.learning_rate * (
                    gradient * scale + self.config.l2 * self.weights[index][j])
            self.bias[index] -= self.config.learning_rate * gradient

    def fit(self, train: list[dict]) -> dict:
        if not train or any(row['split'] != 'train' for row in train):
            raise ValueError('fit receives only a nonempty train split')
        for row in train:
            check_labels(row['labels'])
        self.known_labels = {h: sum(row['labels'][h] is not None for row in train) for h in HEADS}
        rng = random.Random(self.config.seed)
        order = list(range(len(train)))
        for _ in range(self.config.epochs):
            rng.shuffle(order)
            for index in order:
                self.update(train[index]['input'], train[index]['labels'])
        return {'rows': len(train), 'known_labels': self.known_labels,
                'masked_labels': {h: len(train) - self.known_labels[h] for h in HEADS}}

    def classify(self, inp: dict) -> dict:
        scores = self.probabilities(inp)
        active = features(inp, self.config.dimensions)
        unfamiliar = not active or len(set(active) - self.seen_features) / len(active) > 0.5
        actions = [a for a in ACTIONS if scores[a] >= self.high]
        unknown = (unfamiliar or scores['unknown'] > self.low or
                   any(self.low < scores[a] < self.high for a in ACTIONS))
        certainty = min(max(p, 1 - p) for p in scores.values())
        return {'actions': actions, 'unknown': unknown, 'confidence': certainty,
                'uncertainty': 1 - certainty,
                'reason': 'Local linear shadow prediction; no execution authority.'}

    def calibrate(self, calibration: list[dict]) -> dict:
        if not calibration or any(row['split'] != 'calibration' for row in calibration):
            raise ValueError('threshold fitting receives only calibration rows')
        best = None
        for low in (0.1, 0.2, 0.3):
            for high in (0.7, 0.8, 0.9):
                self.low, self.high = low, high
                score = 0.0
                for row in calibration:
                    check_labels(row['labels'])
                    out = self.classify(row['input'])
                    for action in ACTIONS:
                        expected = row['labels'][action]
                        if expected is None:
                            continue
                        predicted = action in out['actions']
                        if expected and not predicted:
                            score += 20 if action in ('delete', 'send_data', 'change_permissions') else 1
                        elif not expected and predicted:
                            score += 2
                    if row['labels']['unknown'] is True and not out['unknown']:
                        score += 20
                    if out['unknown']:
                        score += 0.5
                item = (score, low, high)
                if best is None or item < best:
                    best = item
        _, self.low, self.high = best
        self.calibrated = True
        return {'rows': len(calibration), 'negative_threshold': self.low,
                'positive_threshold': self.high, 'objective': best[0],
                'objective_semantics': 'critical FN=20, other FN=1, FP=2, lost unknown=20, abstention=0.5'}

    def artifact(self) -> dict:
        return {'format': 'soup-wall/local-linear/1', 'feature_version': FEATURE_VERSION,
                'config': asdict(self.config), 'weights': [list(w) for w in self.weights],
                'bias': list(self.bias), 'seen_features': sorted(self.seen_features),
                'known_labels': dict(self.known_labels), 'low': self.low, 'high': self.high,
                'calibrated': self.calibrated, 'shadow_only': True}

    @classmethod
    def restore(cls, record: dict):
        if record.get('format') != 'soup-wall/local-linear/1' or record.get('feature_version') != FEATURE_VERSION:
            raise ValueError('unsupported model artifact')
        model = cls(Config(**record['config']))
        weights, bias = record['weights'], record['bias']
        if len(weights) != len(HEADS) or len(bias) != len(HEADS):
            raise ValueError('wrong number of model heads')
        if any(len(w) != model.config.dimensions for w in weights):
            raise ValueError('wrong model dimensions')
        if any(type(v) not in (int, float) or not math.isfinite(v) for w in weights for v in w):
            raise ValueError('non-finite or invalid weights')
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in bias):
            raise ValueError('non-finite or invalid bias')
        low, high = record['low'], record['high']
        if type(low) not in (int, float) or type(high) not in (int, float) or not 0 <= low < high <= 1:
            raise ValueError('invalid frozen thresholds')
        seen = record['seen_features']
        if not isinstance(seen, list) or any(type(j) is not int or not 0 <= j < model.config.dimensions for j in seen):
            raise ValueError('invalid feature provenance')
        if record.get('shadow_only') is not True or type(record['calibrated']) is not bool:
            raise ValueError('invalid artifact scope')
        if set(record['known_labels']) != set(HEADS) or any(type(v) is not int or v < 0 for v in record['known_labels'].values()):
            raise ValueError('invalid label provenance')
        model.weights = [array('d', w) for w in weights]
        model.bias = list(bias)
        model.seen_features = set(seen)
        model.low, model.high = low, high
        model.calibrated = record['calibrated']
        model.known_labels = dict(record['known_labels'])
        return model
