"""
XMRig module initializer.

This module provides the `XMRigAPI` object to interact with the XMRig miner API.
"""

__name__ = "xmrig"
__author__ = "Coulter Stutz"
__email__ = "coulterstutz@gmail.com"
__version__ = "1.1.2"

from .xmrig import XMRigAPI

__all__ = ["XMRigAPI"]
