#!/usr/bin/env python3
"""
BlackBox AI - Module Loader
============================

Dynamic module loading system that discovers, loads, and registers
modules with the BlackBox platform.
"""

import os
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
import logging
import yaml

from .base import BaseModule, ModuleStatus, ModuleCategory
from .registry import ModuleRegistry

logger = logging.getLogger(__name__)


class ModuleLoader:
    """
    Dynamic module loader for BlackBox.

    Features:
    - Automatic module discovery
    - Configuration-based enable/disable
    - Dependency resolution
    - Hot reload support (development)
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the module loader.

        Args:
            config_path: Path to modules.yaml configuration file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.registry = ModuleRegistry()
        self._discovered: Dict[str, Type[BaseModule]] = {}
        self._load_order: List[str] = []
        self.logger = logging.getLogger("blackbox.loader")

        if config_path and os.path.exists(config_path):
            self.load_config(config_path)

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load module configuration from YAML file.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            self.logger.info(f"Loaded module config from {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            self.config = {}

        return self.config

    def discover_modules(self, modules_path: str) -> List[str]:
        """
        Discover all available modules in a directory.

        Args:
            modules_path: Path to modules directory

        Returns:
            List of discovered module names
        """
        modules_dir = Path(modules_path)
        if not modules_dir.exists():
            self.logger.warning(f"Modules directory not found: {modules_path}")
            return []

        discovered = []

        # Look for module directories with __init__.py
        for item in modules_dir.iterdir():
            if item.is_dir() and not item.name.startswith('_'):
                init_file = item / "__init__.py"
                module_file = item / "module.py"

                if module_file.exists():
                    # Prefer module.py if it exists
                    module_name = item.name
                    try:
                        module_class = self._load_module_class(str(module_file), module_name)
                        if module_class:
                            self._discovered[module_name] = module_class
                            discovered.append(module_name)
                            self.logger.debug(f"Discovered module: {module_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to discover {module_name}: {e}")

                elif init_file.exists():
                    # Fall back to __init__.py
                    module_name = item.name
                    try:
                        module_class = self._load_module_class_from_package(str(item), module_name)
                        if module_class:
                            self._discovered[module_name] = module_class
                            discovered.append(module_name)
                            self.logger.debug(f"Discovered module: {module_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to discover {module_name}: {e}")

        self.logger.info(f"Discovered {len(discovered)} modules")
        return discovered

    def _load_module_class(self, file_path: str, module_name: str) -> Optional[Type[BaseModule]]:
        """Load a module class from a Python file"""
        spec = importlib.util.spec_from_file_location(f"blackbox_module_{module_name}", file_path)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[f"blackbox_module_{module_name}"] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            self.logger.error(f"Error loading {file_path}: {e}")
            return None

        # Find the module class (subclass of BaseModule)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and
                issubclass(attr, BaseModule) and
                attr is not BaseModule):
                return attr

        return None

    def _load_module_class_from_package(self, package_path: str, module_name: str) -> Optional[Type[BaseModule]]:
        """Load a module class from a Python package"""
        init_path = os.path.join(package_path, "__init__.py")
        return self._load_module_class(init_path, module_name)

    def is_enabled(self, module_name: str) -> bool:
        """
        Check if a module is enabled in configuration.

        Args:
            module_name: Name of the module

        Returns:
            True if enabled (default) or explicitly enabled
        """
        modules_config = self.config.get("modules", {})
        module_config = modules_config.get(module_name, {})

        # Default to enabled if not specified
        return module_config.get("enabled", True)

    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific module.

        Args:
            module_name: Name of the module

        Returns:
            Module configuration dictionary
        """
        modules_config = self.config.get("modules", {})
        return modules_config.get(module_name, {})

    def resolve_dependencies(self, module_name: str) -> List[str]:
        """
        Resolve module dependencies and return load order.

        Args:
            module_name: Name of the module

        Returns:
            List of module names in load order
        """
        if module_name not in self._discovered:
            return []

        module_class = self._discovered[module_name]
        dependencies = getattr(module_class, 'dependencies', [])

        load_order = []
        for dep in dependencies:
            if dep in self._discovered and dep not in load_order:
                # Recursively resolve dependencies
                dep_order = self.resolve_dependencies(dep)
                for d in dep_order:
                    if d not in load_order:
                        load_order.append(d)
                if dep not in load_order:
                    load_order.append(dep)

        if module_name not in load_order:
            load_order.append(module_name)

        return load_order

    def load_module(self, module_name: str) -> Optional[BaseModule]:
        """
        Load a single module by name.

        Args:
            module_name: Name of the module to load

        Returns:
            Loaded module instance or None
        """
        if module_name not in self._discovered:
            self.logger.error(f"Module not discovered: {module_name}")
            return None

        if not self.is_enabled(module_name):
            self.logger.info(f"Module disabled: {module_name}")
            return None

        module_class = self._discovered[module_name]
        module_config = self.get_module_config(module_name)

        try:
            # Create module instance
            module = module_class(config=module_config)
            module.status = ModuleStatus.LOADING

            # Call on_load hook
            if not module.on_load():
                self.logger.error(f"Module on_load failed: {module_name}")
                module.status = ModuleStatus.ERROR
                return None

            module.status = ModuleStatus.LOADED
            self.logger.info(f"Loaded module: {module_name} v{module.version}")
            return module

        except Exception as e:
            self.logger.error(f"Failed to load module {module_name}: {e}")
            return None

    def register_module(self, module: BaseModule, mcp: Any = None, app: Any = None, client: Any = None) -> bool:
        """
        Register a loaded module with MCP and Flask.

        Args:
            module: Module instance to register
            mcp: FastMCP instance (optional)
            app: Flask app instance (optional)
            client: BlackBoxClient instance (optional)

        Returns:
            True if registration successful
        """
        try:
            # Register MCP tools
            if mcp and client:
                tools = module.register_tools(mcp, client)
                module._tools = tools or []
                self.logger.debug(f"Registered {len(module._tools)} tools for {module.name}")

            # Register Flask routes
            if app:
                routes = module.register_routes(app)
                module._routes = routes or []
                self.logger.debug(f"Registered {len(module._routes)} routes for {module.name}")

            # Register with central registry
            self.registry.register(module)

            module.status = ModuleStatus.ACTIVE
            return True

        except Exception as e:
            self.logger.error(f"Failed to register module {module.name}: {e}")
            module.status = ModuleStatus.ERROR
            return False

    def load_all(self, modules_path: str = None) -> List[BaseModule]:
        """
        Discover and load all enabled modules.

        Args:
            modules_path: Path to modules directory (optional)

        Returns:
            List of loaded modules
        """
        if modules_path:
            self.discover_modules(modules_path)

        loaded = []
        for module_name in self._discovered:
            if self.is_enabled(module_name):
                module = self.load_module(module_name)
                if module:
                    loaded.append(module)

        return loaded

    def register_all(self, mcp: Any = None, app: Any = None, client: Any = None, modules_path: str = None) -> int:
        """
        Discover, load, and register all enabled modules.

        Args:
            mcp: FastMCP instance
            app: Flask app instance
            client: BlackBoxClient instance
            modules_path: Path to modules directory

        Returns:
            Number of successfully registered modules
        """
        if modules_path:
            self.discover_modules(modules_path)

        registered_count = 0

        # Build load order respecting dependencies
        all_modules = list(self._discovered.keys())
        load_order = []
        for module_name in all_modules:
            if self.is_enabled(module_name):
                order = self.resolve_dependencies(module_name)
                for m in order:
                    if m not in load_order:
                        load_order.append(m)

        # Load and register in order
        for module_name in load_order:
            module = self.load_module(module_name)
            if module:
                if self.register_module(module, mcp=mcp, app=app, client=client):
                    registered_count += 1

        self.logger.info(f"Registered {registered_count} modules")
        return registered_count

    def unload_module(self, module_name: str) -> bool:
        """
        Unload a module.

        Args:
            module_name: Name of module to unload

        Returns:
            True if successful
        """
        module = self.registry.get(module_name)
        if not module:
            return False

        try:
            module.on_unload()
            module.status = ModuleStatus.UNLOADED
            self.registry.unregister(module_name)
            return True
        except Exception as e:
            self.logger.error(f"Error unloading {module_name}: {e}")
            return False

    def reload_module(self, module_name: str, mcp: Any = None, app: Any = None, client: Any = None) -> Optional[BaseModule]:
        """
        Reload a module (for development).

        Args:
            module_name: Name of module to reload
            mcp: FastMCP instance
            app: Flask app instance
            client: BlackBoxClient instance

        Returns:
            Reloaded module instance
        """
        self.unload_module(module_name)

        # Re-discover to pick up changes
        if module_name in self._discovered:
            del self._discovered[module_name]

        # Reload the module class
        # This is a simplified version - full hot reload would need more work
        module = self.load_module(module_name)
        if module:
            self.register_module(module, mcp=mcp, app=app, client=client)

        return module

    def get_stats(self) -> Dict[str, Any]:
        """Get loader statistics"""
        return {
            "discovered": len(self._discovered),
            "enabled": sum(1 for m in self._discovered if self.is_enabled(m)),
            "registry": self.registry.get_stats()
        }
