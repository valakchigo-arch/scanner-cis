import os
from pathlib import Path
from typing import List
import yaml

from .rule_model import Rule, Condition, Probe
from .exceptions import RuleValidationError


def load_rule(path: str) -> Rule:
    """Load single YAML rule → Rule object."""
    p = Path(path)
    if not p.exists():
        raise RuleValidationError(f"Rule file not found: {path}")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RuleValidationError(f"Invalid YAML in {path}: {e}")

    if not isinstance(raw, dict):
        raise RuleValidationError(f"Rule must be a mapping: {path}")

    required = [
        "rule_id", "title", "category", "os",
        "standard", "severity", "confidence",
        "condition", "probe", "remediation",
    ]
    for key in required:
        if key not in raw:
            raise RuleValidationError(
                f"Missing required field '{key}' in {path}"
            )

    for key in ("condition", "probe"):
        if not isinstance(raw[key], dict):
            raise RuleValidationError(f"'{key}' must be a mapping in {path}")

    try:
        condition = Condition(
            operator=raw["condition"]["operator"],
            expected_value=raw["condition"]["expected_value"],
            display=str(raw["condition"].get("display") or ""),
        )
    except KeyError as e:
        raise RuleValidationError(
            f"condition missing '{e.args[0]}' in {path}"
        )

    probe = Probe(
        provider=raw["probe"].get("provider", ""),
        params=raw["probe"].get("params", {}),
    )

    rule = Rule(
        rule_id=raw["rule_id"],
        title=raw["title"],
        category=raw["category"],
        os=raw["os"],
        standard=raw["standard"],
        severity=raw["severity"],
        confidence=raw["confidence"],
        condition=condition,
        probe=probe,
        remediation=raw["remediation"],
        description=raw.get("description", ""),
        version=raw.get("version", "1.0"),
    )
    rule.validate()
    return rule


def load_rules_from_dir(dir_path: str) -> List[Rule]:
    """Load semua *.yaml / *.yml di directory. Cek duplicate rule_id."""
    rules: List[Rule] = []
    seen_ids: dict[str, str] = {}

    if not os.path.isdir(dir_path):
        raise RuleValidationError(f"Rules directory not found: {dir_path}")

    for fname in sorted(os.listdir(dir_path)):
        if not (fname.endswith(".yaml") or fname.endswith(".yml")):
            continue
        full = os.path.join(dir_path, fname)
        rule = load_rule(full)

        if rule.rule_id in seen_ids:
            raise RuleValidationError(
                f"Duplicate rule_id '{rule.rule_id}' "
                f"in {full} (already in {seen_ids[rule.rule_id]})"
            )
        seen_ids[rule.rule_id] = full
        rules.append(rule)

    return rules