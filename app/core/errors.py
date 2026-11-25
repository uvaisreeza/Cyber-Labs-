"""Exceptions shared by tools and guards."""


class ToolError(Exception):
    """A user-facing, expected failure (bad input, upstream unreachable...)."""


class TargetBlocked(ToolError):
    """The SSRF guard refused the target (loopback, private range, bad scheme...)."""
