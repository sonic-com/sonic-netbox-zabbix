"""Sync Netbox devices and virtual-machines to Zabbix hosts."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sonic-netbox-zabbix")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
