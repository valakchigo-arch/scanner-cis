from typing import Callable, Dict, List
from .exceptions import ProbeNotFoundError


class ProbeRegistry:
    """Registry provider. Provider = function(params) → dict."""

    def __init__(self):
        self._providers: Dict[str, Callable] = {}

    def register(self, name: str, fn: Callable):
        if name in self._providers:
            raise ValueError(f"Provider '{name}' already registered")
        self._providers[name] = fn

    def get(self, name: str) -> Callable:
        if name not in self._providers:
            raise ProbeNotFoundError(
                f"Provider '{name}' not registered. "
                f"Available: {sorted(self._providers.keys())}"
            )
        return self._providers[name]

    def list_providers(self) -> List[str]:
        return sorted(self._providers.keys())


# Global singleton
registry = ProbeRegistry()