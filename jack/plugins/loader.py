"""Plugin loading and management."""

import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional
from .interface import PluginInterface


class PluginLoader:
    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self._plugins: Dict[str, PluginInterface] = {}
        self._plugin_dirs = plugin_dirs or []

    def discover(self, directory: str):
        plugin_dir = Path(directory)
        if not plugin_dir.exists():
            return
        for py_file in plugin_dir.glob("*_plugin.py"):
            self._load_plugin_file(py_file)
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            self._load_plugin_file(py_file)

    def _load_plugin_file(self, filepath: Path):
        try:
            spec = importlib.util.spec_from_file_location(filepath.stem, str(filepath))
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                            issubclass(attr, PluginInterface) and
                            attr is not PluginInterface):
                        self.register(attr())
        except Exception:
            pass

    def register(self, plugin: PluginInterface):
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Optional[PluginInterface]:
        return self._plugins.get(name)

    def list_plugins(self) -> List[dict]:
        return [
            {"name": p.name, "version": p.version, "type": type(p).__name__}
            for p in self._plugins.values()
        ]

    def initialize_all(self, config: dict = None):
        for plugin in self._plugins.values():
            try:
                plugin.initialize(config or {})
            except Exception:
                pass

    def shutdown_all(self):
        for plugin in self._plugins.values():
            try:
                plugin.shutdown()
            except Exception:
                pass
