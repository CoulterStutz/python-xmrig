__name__ = "xmrig"
__author__ = "Coulter Stutz"
__email__ = "coulterstutz@gmail.com"
__version__ = "1.0.4"

from .xmrig import XMRig, XMRigAuthorizationError
__all__ = ["XMRig", "XMRigAuthorizationError"]