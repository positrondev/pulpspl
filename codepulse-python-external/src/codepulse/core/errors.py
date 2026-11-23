"""Typed errors. Callers branch on type, never on message text."""


class CodePulseError(Exception):
    """Base for every error CodePulse raises deliberately."""


class ConfigError(CodePulseError):
    """Invalid or unreadable configuration. Maps to CLI exit code 2."""


class RegistryError(ConfigError):
    """Invalid rule metadata, plugin, or rule override. Maps to exit code 2."""


class SourceError(CodePulseError):
    """The analysis target cannot be resolved (bad ref, not a repo). Maps to exit code 2."""


class SourceReadError(SourceError):
    """One file cannot be read or decoded. The resolver records it as a skip, not a failure."""
