class RuleEngineError(Exception):
    """Base error for rule engine."""

class RuleValidationError(RuleEngineError):
    """Rule YAML tidak valid (enum, missing field, dsb)."""

class ProbeNotFoundError(RuleEngineError):
    """Provider belum terdaftar di registry."""

class ProbeExecutionError(RuleEngineError):
    """Provider gagal execute (command error, file not found, dsb)."""

class EvaluationError(RuleEngineError):
    """Operator gagal evaluate (tipe mismatch, regex invalid, dsb)."""