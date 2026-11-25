"""Tool registry.

A tool is a plain function ``handler(params: dict) -> dict`` plus metadata that
describes its input form. The dashboard builds every form from this metadata, so
adding a tool means writing one decorated function - no template or route changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List

CATEGORIES = [
    ("recon", "Reconnaissance & Footprinting"),
    ("crypto", "Crypto & Integrity"),
    ("intel", "Threat Intelligence"),
    ("utils", "Utilities"),
]


@dataclass
class Tool:
    id: str
    name: str
    category: str
    description: str
    handler: Callable[[dict], dict]
    fields: List[dict] = field(default_factory=list)
    network: bool = False       # contacts the outside world
    store_result: bool = True   # False => result is not saved to history
    active: bool = False        # sends probes straight at the target

    def public(self) -> dict:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "description": self.description, "fields": self.fields,
            "network": self.network, "active": self.active,
        }


REGISTRY: Dict[str, Tool] = {}


def F(name: str, label: str, type: str = "text", **kw) -> dict:
    """Shorthand for a form-field definition.

    type: text | textarea | number | select | password | checkbox | file
    extra: default, placeholder, options, required, sensitive, help
    """
    d = {"name": name, "label": label, "type": type, "required": True}
    d.update(kw)
    return d


def tool(id: str, name: str, category: str, description: str, fields=None, *,
         network=False, store_result=True, active=False):
    def deco(fn: Callable[[dict], dict]):
        if id in REGISTRY:
            raise RuntimeError(f"duplicate tool id {id}")
        REGISTRY[id] = Tool(id, name, category, description, fn, fields or [],
                            network, store_result, active)
        return fn
    return deco


def all_tools() -> List[Tool]:
    order = {c: i for i, (c, _) in enumerate(CATEGORIES)}
    return sorted(REGISTRY.values(), key=lambda t: order[t.category])


def load_all() -> None:
    """Import every tool module so decorators run."""
    from app.tools import recon, crypto, threat_intel, utilities  # noqa: F401
