"""Fetch module - adaptive downloading with TOR support"""

from .downloader import AdaptiveDownloader
from .tor import TORManager
from .proxy_manager import ProxyManager

__all__ = ['AdaptiveDownloader', 'TORManager', 'ProxyManager']
