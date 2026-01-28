"""
Stealth Suite
=============
Anti-detection and human simulation for evading bot protection.
"""

from .behavior import BehavioralSimulator
from .fingerprint import FingerprintSpoofer
from .headers import HeaderGenerator
from .injector import StealthInjector
from .session import SessionStealer

__all__ = [
    "StealthInjector",
    "BehavioralSimulator",
    "FingerprintSpoofer",
    "HeaderGenerator",
    "SessionStealer",
]
