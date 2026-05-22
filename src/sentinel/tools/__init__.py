"""Forensic tool wrappers. Each tool is exposed as a typed Pydantic function."""

from .volatility_pslist import volatility_pslist, PslistInput
from .volatility_netscan import volatility_netscan, NetscanInput
from .regripper_amcache import regripper_amcache, AmcacheInput
from .plaso_log2timeline import plaso_log2timeline, Log2TimelineInput
from .evtxecmd_security import evtxecmd_security, EvtxSecurityInput

from . import _subprocess

__all__ = [
    "volatility_pslist", "PslistInput",
    "volatility_netscan", "NetscanInput",
    "regripper_amcache", "AmcacheInput",
    "plaso_log2timeline", "Log2TimelineInput",
    "evtxecmd_security", "EvtxSecurityInput",
    "_subprocess",
]