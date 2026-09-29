"""Duplicate-key-rejecting YAML helpers for governed configuration."""

from __future__ import annotations

from typing import Any

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader which rejects duplicate mapping keys at every depth."""


def _construct_mapping(
    loader: UniqueKeyLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate protected configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_unique_yaml(raw: str | bytes) -> Any:
    """Parse safe YAML while rejecting duplicate mapping keys."""

    try:
        return yaml.load(raw, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid protected configuration YAML") from exc
