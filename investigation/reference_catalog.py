
"""Local lookups for MITRE ATT&CK Enterprise and D3FEND reference data.

ATT&CK techniques are validated against the local MITRE Enterprise STIX
catalogue. D3FEND relationships are taken only from the supplied official
mapping CSV. A D3FEND catalogue ID is returned only when its display name
matches a catalogue entry exactly, ignoring letter case.
"""

import csv
import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF_DIR = ROOT / "data" / "reference"


@lru_cache(maxsize=1)
def _catalogues():
    """Load and cache local ATT&CK, D3FEND, and mapping catalogues."""
    attack_path = REF_DIR / "enterprise-attack.json"
    d3fend_path = REF_DIR / "d3fend.csv"
    mappings_path = REF_DIR / "d3fend-full-mappings.csv"

    for path in (attack_path, d3fend_path, mappings_path):
        if not path.is_file():
            raise FileNotFoundError(
                f"Reference catalogue missing: {path}"
            )

    # Load non-revoked, non-deprecated ATT&CK techniques.
    bundle = json.loads(attack_path.read_text(encoding="utf-8"))
    attack = {}

    for obj in bundle.get("objects", []):
        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked", False)
            or obj.get("x_mitre_deprecated", False)
        ):
            continue

        for ref in obj.get("external_references", []):
            if (
                ref.get("source_name") != "mitre-attack"
                or not ref.get("external_id")
            ):
                continue

            technique_id = ref["external_id"]

            attack[technique_id] = {
                "id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "url": ref.get("url"),
                "source": "MITRE ATT&CK Enterprise STIX",
            }

    # Load D3FEND catalogue entries.
    d3fend = {}

    with d3fend_path.open(
        encoding="utf-8-sig", newline=""
    ) as f:
        for row in csv.DictReader(f):
            technique_id = (row.get("ID") or "").strip()

            if not technique_id.startswith("D3-"):
                continue

            d3fend[technique_id] = {
                "id": technique_id,
                "name": (
                    row.get("D3FEND Technique") or ""
                ).strip(),
                "level0": (
                    row.get("D3FEND Technique Level 0") or ""
                ).strip(),
                "level1": (
                    row.get("D3FEND Technique Level 1") or ""
                ).strip(),
                "tactic": (
                    row.get("D3FEND Tactic") or ""
                ).strip(),
                "definition": (
                    row.get("Definition") or ""
                ).strip(),
                "source": "MITRE D3FEND catalogue",
            }

    # Index catalogue names for exact, case-insensitive matching.
    d3fend_by_name = {}

    # Index primary names first, then Level 0 and Level 1 names.
    for item in d3fend.values():
        for field in ("name", "level0", "level1"):
            name = (item.get(field) or "").strip()
            if name:
                d3fend_by_name.setdefault(name.casefold(), item)

    # Preserve explicit relationships from the supplied mapping CSV.
    # Keep the official URI even when no exact catalogue ID is available.
    mappings = {}

    with mappings_path.open(
        encoding="utf-8-sig", newline=""
    ) as f:
        for row in csv.DictReader(f):
            attack_id = (row.get("off_tech_id") or "").strip()
            defensive_name = (
                row.get("def_tech_label") or ""
            ).strip()

            if attack_id not in attack or not defensive_name:
                continue

            defensive_uri = (
                row.get("def_tech") or ""
            ).strip() or None

            matched = d3fend_by_name.get(
                defensive_name.casefold()
            )

            entry = {
                "id": matched["id"] if matched else None,
                "name": defensive_name,
                "uri": defensive_uri,
                "tactic": (
                    row.get("def_tactic_label") or ""
                ).strip(),
                "relationship": (
                    row.get("def_tactic_rel_label") or ""
                ).strip(),
                "source": "MITRE D3FEND full mappings",
                "official_catalogue_match": matched is not None,
                "query_defensive_technique": (
                    row.get("query_def_tech_label") or ""
                ).strip() or None,
                "top_defensive_technique": (
                    row.get("top_def_tech_label") or ""
                ).strip() or None,
            }

            mappings.setdefault(attack_id, [])

            if entry not in mappings[attack_id]:
                mappings[attack_id].append(entry)

    return attack, d3fend, mappings


def get_attack_technique(technique_id):
    """Return a catalogue-backed ATT&CK technique, or None."""
    if not isinstance(technique_id, str):
        return None

    attack, _, _ = _catalogues()
    return attack.get(technique_id.strip())


def get_d3fend_mappings(technique_id):
    """Return explicit D3FEND mappings for a valid ATT&CK ID."""
    if not isinstance(technique_id, str):
        return []

    attack, _, mappings = _catalogues()
    technique_id = technique_id.strip()

    if technique_id not in attack:
        return []

    return mappings.get(technique_id, [])


def catalogue_status():
    """Return summary counts for the loaded local catalogues."""
    attack, d3fend, mappings = _catalogues()

    return {
        "attack_techniques": len(attack),
        "d3fend_techniques": len(d3fend),
        "attack_techniques_with_mappings": len(mappings),
        "mapping_rows_for_T1021": len(mappings.get("T1021", [])),
        "mapping_rows_for_T1078": len(mappings.get("T1078", [])),
        "catalogue_directory": str(REF_DIR),
    }


def get_d3fend_technique(technique_id):
    """Return a catalogue-backed D3FEND technique, or None."""
    if not isinstance(technique_id, str):
        return None

    _, d3fend, _ = _catalogues()
    return d3fend.get(technique_id.strip())
