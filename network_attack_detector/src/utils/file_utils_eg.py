from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def ensure_dir(path: str | Path) -> Path:
    """Create a directory if it does not exist and return it as a Path."""
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def ensure_parent_dir(path: str | Path) -> Path:
    """Create the parent directory for a file path and return that parent."""
    parent = Path(path).parent
    parent.mkdir(parents=True, exist_ok=True)
    return parent


def read_text(path: str | Path, encoding: str = "utf-8") -> str:
    """Read a text file with a consistent default encoding."""
    return Path(path).read_text(encoding=encoding)


def write_text(path: str | Path, content: str, encoding: str = "utf-8") -> Path:
    """Write text to a file, creating the parent directory first."""
    target = Path(path)
    ensure_parent_dir(target)
    target.write_text(content, encoding=encoding)
    return target


def read_json(path: str | Path) -> Any:
    """Read a JSON file and return the decoded Python object."""
    return json.loads(read_text(path))


def write_json(path: str | Path, data: Any, indent: int = 2) -> Path:
    """Write a Python object as JSON, creating the parent directory first."""
    content = json.dumps(data, ensure_ascii=False, indent=indent)
    return write_text(path, content + "\n")


def read_yaml(path: str | Path) -> Any:
    """Read a YAML file and return the decoded Python object."""
    with Path(path).open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def resolve_path(base_dir: str | Path, path: str | Path) -> Path:
    """Resolve a config path relative to a base directory.

    Absolute paths are returned unchanged. Relative paths are joined to
    base_dir and then resolved.
    """
    target = Path(path)
    if target.is_absolute():
        return target
    return (Path(base_dir) / target).resolve()
