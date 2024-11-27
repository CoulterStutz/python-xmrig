"""
XMRig module initializer.

This module provides the `XMRigAPI` object to interact with the XMRig miner API.
"""

__name__ = "xmrig"
__author__ = "Coulter Stutz"
__email__ = "coulterstutz@gmail.com"
__version__ = "1.1.1"

from .xmrig import XMRigAPI, XMRig, XMRigPool, PoolCoin, PoolAlgorithm
__all__ = ["XMRig", "XMRigAPI", "XMRigPool", "PoolCoin", "PoolAlgorithm"]