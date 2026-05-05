from __future__ import annotations

import json
from pathlib import Path

import structlog

from app.config import settings

logger = structlog.get_logger()

_attck_data: dict | None = None
_technique_index: dict[str, dict] = {}
_group_index: dict[str, dict] = {}
_software_index: dict[str, dict] = {}


def load_attck() -> dict:
    global _attck_data
    if _attck_data is not None:
        return _attck_data

    path = settings.attck_bundle_file
    if not path.exists():
        logger.warning("attck_bundle_not_found", path=str(path))
        _attck_data = {"objects": []}
        return _attck_data

    raw = json.loads(path.read_text(encoding="utf-8"))
    _attck_data = raw
    _build_indexes(raw)
    logger.info("attck_loaded", objects=len(raw.get("objects", [])))
    return raw


def _build_indexes(raw: dict) -> None:
    global _technique_index, _group_index, _software_index
    _technique_index.clear()
    _group_index.clear()
    _software_index.clear()

    for obj in raw.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id", "")
                    if tid:
                        _technique_index[tid] = obj
        elif obj_type == "intrusion-set":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    gid = ref.get("external_id", "")
                    if gid:
                        _group_index[gid] = obj
                        # Also index by alias
                        for alias in obj.get("aliases", []):
                            _group_index[alias.upper()] = obj
        elif obj_type == "malware":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    sid = ref.get("external_id", "")
                    if sid:
                        _software_index[sid] = obj
                        for alias in obj.get("aliases", []):
                            _software_index[alias.upper()] = obj


def get_technique(technique_id: str) -> dict | None:
    load_attck()
    return _technique_index.get(technique_id)


def get_group(group_id: str) -> dict | None:
    load_attck()
    return _group_index.get(group_id) or _group_index.get(group_id.upper())


def get_software(software_id: str) -> dict | None:
    load_attck()
    return _software_index.get(software_id) or _software_index.get(software_id.upper())


def validate_technique_id(technique_id: str) -> bool:
    load_attck()
    return technique_id in _technique_index


def get_all_techniques() -> dict[str, dict]:
    load_attck()
    return dict(_technique_index)
