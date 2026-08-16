"""Plugin interface definitions."""

from abc import ABC, abstractmethod
from typing import Dict, Any


class PluginInterface(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        pass

    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def shutdown(self):
        pass


class HashPlugin(PluginInterface):
    @abstractmethod
    def get_algorithm(self):
        pass


class AttackPlugin(PluginInterface):
    @abstractmethod
    def get_attack_class(self):
        pass


class ReportPlugin(PluginInterface):
    @abstractmethod
    def get_generator(self):
        pass


class BackendPlugin(PluginInterface):
    @abstractmethod
    def get_backend(self):
        pass
