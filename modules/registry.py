#!/usr/bin/env python3
"""
BlackBox AI - Module Registry
==============================

Central registry for tracking all loaded modules, their tools,
and routes. Provides lookup and management functionality.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import threading

from .base import BaseModule, ModuleStatus, ModuleCategory

logger = logging.getLogger(__name__)


@dataclass
class ModuleRecord:
    """Record of a registered module"""
    module: BaseModule
    loaded_at: datetime = field(default_factory=datetime.now)
    load_order: int = 0
    error_message: Optional[str] = None


class ModuleRegistry:
    """
    Central registry for all BlackBox modules.

    Provides:
    - Module registration and lookup
    - Tool and route tracking
    - Category-based filtering
    - Health monitoring
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern for global registry access"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._modules: Dict[str, ModuleRecord] = {}
        self._tools: Dict[str, str] = {}  # tool_name -> module_name
        self._routes: Dict[str, str] = {}  # route_path -> module_name
        self._load_counter = 0
        self._initialized = True
        self.logger = logging.getLogger("blackbox.registry")

    def register(self, module: BaseModule) -> bool:
        """
        Register a module with the registry.

        Args:
            module: Module instance to register

        Returns:
            True if registration successful
        """
        if module.name in self._modules:
            self.logger.warning(f"Module {module.name} already registered, skipping")
            return False

        self._load_counter += 1
        record = ModuleRecord(
            module=module,
            load_order=self._load_counter
        )
        self._modules[module.name] = record

        # Track tools
        for tool in module._tools:
            if tool.name in self._tools:
                self.logger.warning(f"Tool {tool.name} already registered by {self._tools[tool.name]}")
            else:
                self._tools[tool.name] = module.name

        # Track routes
        for route in module._routes:
            if route.path in self._routes:
                self.logger.warning(f"Route {route.path} already registered by {self._routes[route.path]}")
            else:
                self._routes[route.path] = module.name

        self.logger.info(f"Registered module: {module.name} ({len(module._tools)} tools, {len(module._routes)} routes)")
        return True

    def unregister(self, name: str) -> bool:
        """
        Unregister a module from the registry.

        Args:
            name: Module name to unregister

        Returns:
            True if unregistration successful
        """
        if name not in self._modules:
            self.logger.warning(f"Module {name} not found in registry")
            return False

        record = self._modules[name]
        module = record.module

        # Remove tool mappings
        for tool in module._tools:
            if tool.name in self._tools:
                del self._tools[tool.name]

        # Remove route mappings
        for route in module._routes:
            if route.path in self._routes:
                del self._routes[route.path]

        del self._modules[name]
        self.logger.info(f"Unregistered module: {name}")
        return True

    def get(self, name: str) -> Optional[BaseModule]:
        """Get a module by name"""
        record = self._modules.get(name)
        return record.module if record else None

    def get_all(self) -> List[BaseModule]:
        """Get all registered modules"""
        return [r.module for r in self._modules.values()]

    def get_by_category(self, category: ModuleCategory) -> List[BaseModule]:
        """Get all modules in a category"""
        return [
            r.module for r in self._modules.values()
            if r.module.category == category
        ]

    def get_by_status(self, status: ModuleStatus) -> List[BaseModule]:
        """Get all modules with a specific status"""
        return [
            r.module for r in self._modules.values()
            if r.module.status == status
        ]

    def get_tool_module(self, tool_name: str) -> Optional[str]:
        """Get the module name that provides a tool"""
        return self._tools.get(tool_name)

    def get_route_module(self, route_path: str) -> Optional[str]:
        """Get the module name that provides a route"""
        return self._routes.get(route_path)

    def list_tools(self) -> Dict[str, str]:
        """Get all registered tools and their modules"""
        return dict(self._tools)

    def list_routes(self) -> Dict[str, str]:
        """Get all registered routes and their modules"""
        return dict(self._routes)

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        status_counts = {}
        category_counts = {}

        for record in self._modules.values():
            module = record.module

            status = module.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

            category = module.category.value
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total_modules": len(self._modules),
            "total_tools": len(self._tools),
            "total_routes": len(self._routes),
            "by_status": status_counts,
            "by_category": category_counts
        }

    def health_check(self) -> Dict[str, Any]:
        """Get health status of all modules"""
        results = {}
        healthy_count = 0

        for name, record in self._modules.items():
            health = record.module.health_check()
            results[name] = health
            if health.get("healthy"):
                healthy_count += 1

        return {
            "total": len(self._modules),
            "healthy": healthy_count,
            "unhealthy": len(self._modules) - healthy_count,
            "modules": results
        }

    def clear(self) -> None:
        """Clear all registered modules (use with caution)"""
        self._modules.clear()
        self._tools.clear()
        self._routes.clear()
        self._load_counter = 0
        self.logger.info("Registry cleared")
