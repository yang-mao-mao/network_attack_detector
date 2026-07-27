from __future__ import annotations

import copy
import logging
import logging.config
from pathlib import Path
from typing import Any

from ..utils.file_utils import ensure_parent_dir, read_yaml, resolve_path


DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"


def setup_logging(
    config_path: str | Path | None = None,
    project_root: str | Path | None = None,
) -> None:
    """Configure logging from a YAML dictConfig file.

    If config_path is not provided, a basic console logger is configured.
    File handler paths in the YAML file are resolved relative to project_root.
    """
    if config_path is None:
        logging.basicConfig(level=logging.INFO, format=DEFAULT_LOG_FORMAT)
        return

    path = Path(config_path)
    config = read_yaml(path)
    #isinstance()函数检查传入的实例是不是传入的类或者是传入的类的子类，比type更灵活，因为考虑到了继承关系
    if not isinstance(config, dict):
        raise ValueError(f"Logging config must be a mapping: {path}")

    root = Path(project_root) if project_root is not None else path.resolve().parents[1]
    prepared_config = _prepare_logging_config(config, root)
    logging.config.dictConfig(prepared_config)


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger using the project's configured logging settings."""
    return logging.getLogger(name)


def _prepare_logging_config(config: dict[str, Any], project_root: Path) -> dict[str, Any]:
    prepared = copy.deepcopy(config)
    handlers = prepared.get("handlers", {})

    for handler_config in handlers.values():
        if not isinstance(handler_config, dict):
            continue
        filename = handler_config.get("filename")
        if not filename:
            continue
        resolved = resolve_path(project_root, filename)
        ensure_parent_dir(resolved)
        handler_config["filename"] = str(resolved)

    return prepared
