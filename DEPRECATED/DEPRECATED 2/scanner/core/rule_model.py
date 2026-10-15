from dataclasses import dataclass, field
from typing import Any
from .exceptions import RuleValidationError


# Enum — sinkron dengan docs/assessment/SCHEMA.md
VALID_CATEGORIES = {
    "authentication", "authorization", "network_security", "logging",
    "cryptography", "patching", "services", "filesystem", "audit",
    "update", "compromise_indicators",
}

VALID_SEVERITIES = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNCLASSIFIED",
}

VALID_CONFIDENCES = {"DIRECT", "INFERRED", "MANUAL"}

VALID_OPERATORS = {
    "equals", "not_equals", "gt", "gte", "lt", "lte",
    "in", "not_in", "matches", "contains",
    "exists", "not_exists", "one_of",
}

VALID_OS = {"windows", "linux", "any"}


@dataclass(frozen=True)
class Condition:
    operator: str
    expected_value: Any

    def validate(self):
        if self.operator not in VALID_OPERATORS:
            raise RuleValidationError(
                f"Invalid operator: {self.operator}. "
                f"Must be one of {sorted(VALID_OPERATORS)}"
            )


@dataclass(frozen=True)
class Probe:
    provider: str
    params: dict = field(default_factory=dict)

    def validate(self):
        if not self.provider:
            raise RuleValidationError("probe.provider is required")
        if not isinstance(self.params, dict):
            raise RuleValidationError("probe.params must be a dict")


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    os: str
    standard: dict
    severity: str
    confidence: str
    condition: Condition
    probe: Probe
    remediation: dict
    description: str = ""
    version: str = "1.0"

    def validate(self):
        if not self.rule_id:
            raise RuleValidationError("rule_id is required")
        if self.category not in VALID_CATEGORIES:
            raise RuleValidationError(
                f"Invalid category: {self.category}. "
                f"Must be one of {sorted(VALID_CATEGORIES)}"
            )
        if self.severity not in VALID_SEVERITIES:
            raise RuleValidationError(
                f"Invalid severity: {self.severity}. "
                f"Must be one of {sorted(VALID_SEVERITIES)}"
            )
        if self.confidence not in VALID_CONFIDENCES:
            raise RuleValidationError(
                f"Invalid confidence: {self.confidence}. "
                f"Must be one of {sorted(VALID_CONFIDENCES)}"
            )
        if self.os not in VALID_OS:
            raise RuleValidationError(
                f"Invalid os: {self.os}. Must be one of {sorted(VALID_OS)}"
            )
        if not isinstance(self.standard, dict) or "name" not in self.standard:
            raise RuleValidationError("standard.name is required")
        if not isinstance(self.remediation, dict) or "action" not in self.remediation:
            raise RuleValidationError("remediation.action is required")

        self.condition.validate()
        self.probe.validate()