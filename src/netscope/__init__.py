"""NetScope defensive network diagnostics toolkit."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("netscope-toolkit")
except PackageNotFoundError:  # pragma: no cover - package metadata always installed
    __version__ = "0.0.0+unknown"
