__name__ = "xmrig"
__author__ = "Coulter Stutz"
__email__ = "coulterstutz@gmail.com"
__version__ = "1.1.0"

from .xmrig import XMRigAPI, XMRigAuthorizationError
__all__ = ["XMRig", "XMRigAPI", "XMRigAuthorizationError"]