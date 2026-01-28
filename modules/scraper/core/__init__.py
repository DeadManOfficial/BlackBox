"""Core orchestration: Engine, Scheduler, Signals, Config"""

# Graceful imports - allow module to load even with missing deps
try:
    from .config import Config
except ImportError:
    Config = None

try:
    from .scheduler import Scheduler, Priority
except ImportError:
    Scheduler = None
    Priority = None

try:
    from .signals import Signal, SignalManager
    Signals = SignalManager
except ImportError:
    Signal = None
    SignalManager = None
    Signals = None

try:
    from .engine import Engine
except ImportError:
    Engine = None

__all__ = ["Engine", "Scheduler", "Priority", "Signal", "SignalManager", "Signals", "Config"]
