class DetectorError(Exception):
    """Base exception for detector errors."""


class CaptureError(DetectorError):
    """Raised when packet capture fails."""


class ParserError(DetectorError):
    """Raised when packet parsing fails."""


class RuleError(DetectorError):
    """Raised when rule loading or validation fails."""


class DetectionError(DetectorError):
    """Raised when detection fails."""

