from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

try:
    import pyogrio  # type: ignore
except Exception:  # pragma: no cover
    pyogrio = None  # type: ignore


def require_pyogrio() -> None:
    if pyogrio is None:
        raise RuntimeError("Missing dependency: pyogrio. Install with: pip install pyogrio")


def sanitize_filename(name: str, max_len: int = 180) -> str:
    """
    Safe output filename for common filesystems (used for GeoJSON outputs).
    """
    name = (name or "").strip()
    name = re.sub(r"[\\/:\*\?\"<>\|]+", "_", name)  # Windows-illegal
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"_+", "_", name)
    name = name.strip("._")
    if not name:
        name = "layer"
    return name[:max_len]


def sanitize_fc_name(name: str, max_len: int = 120) -> str:
    """
    FileGDB-friendly layer name:
    - letters/numbers/underscore only
    - must start with a letter (prefix 'fc_' if not)
    """
    n = (name or "").strip()
    n = re.sub(r"\s+", "_", n)
    n = re.sub(r"[^A-Za-z0-9_]+", "_", n)
    n = re.sub(r"_+", "_", n).strip("_")
    if not n:
        n = "fc"
    if not re.match(r"^[A-Za-z]", n):
        n = f"fc_{n}"
    return n[:max_len]


def unique_name(base: str, used: set[str]) -> str:
    """
    Ensure unique names within a single run.
    """
    if base not in used:
        used.add(base)
        return base
    i = 2
    while f"{base}_{i}" in used:
        i += 1
    out = f"{base}_{i}"
    used.add(out)
    return out


def parse_pyogrio_list_layers(raw: Any) -> List[Dict[str, Any]]:
    """
    Normalize pyogrio.list_layers() output to:
      [{"name": <str>, "geometry_type": <str|None>}, ...]

    pyogrio.list_layers() can appear as:
      - shape (n, 2) rows
      - shape (2, n) needs transpose
    """
    if raw is None:
        return []

    if hasattr(raw, "tolist"):
        raw_list = raw.tolist()
    else:
        raw_list = list(raw)

    if not raw_list:
        return []

    if isinstance(raw_list[0], list) and len(raw_list[0]) == 2:
        rows = raw_list
    elif (
        isinstance(raw_list[0], list)
        and len(raw_list) == 2
        and all(isinstance(x, list) for x in raw_list)
        and len(raw_list[0]) == len(raw_list[1])
    ):
        rows = list(zip(raw_list[0], raw_list[1]))
    else:
        rows = [(x, None) for x in raw_list]

    meta: List[Dict[str, Any]] = []
    for name, gtype in rows:
        meta.append({"name": None if name is None else str(name), "geometry_type": gtype})
    return meta


def ensure_out_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path



from fnmatch import fnmatch


SUPPORTED_EXPORT_FORMATS = {"geojson", "shp", "kml"}


def normalize_format(fmt: str) -> str:
    f = (fmt or "").strip().lower()
    if f in ("geojson", "json"):
        return "geojson"
    if f in ("shp", "shapefile", "shape"):
        return "shp"
    if f in ("kml",):
        return "kml"
    raise ValueError(f"Unsupported format: {fmt!r}. Choose from: geojson, shp, kml")


def list_write_drivers() -> Dict[str, Any]:
    require_pyogrio()
    return pyogrio.list_drivers(write=True)


def driver_supported_for_write(driver_name: str) -> bool:
    try:
        d = list_write_drivers()
        mode = d.get(driver_name)
        if mode is None:
            return False
        return "w" in str(mode)
    except Exception:
        return False


def pick_kml_driver() -> str:
    # GDAL sometimes exposes KML or LIBKML.
    if driver_supported_for_write("KML"):
        return "KML"
    if driver_supported_for_write("LIBKML"):
        return "LIBKML"
    raise RuntimeError(
        "KML export is not supported by your GDAL/pyogrio build (no writable KML/LIBKML driver)."
    )


def export_driver_for(fmt: str) -> str:
    f = normalize_format(fmt)
    if f == "geojson":
        return "GeoJSON"
    if f == "shp":
        return "ESRI Shapefile"
    if f == "kml":
        return pick_kml_driver()
    raise ValueError(f"Unsupported format: {fmt!r}")


def export_extension_for(fmt: str) -> str:
    f = normalize_format(fmt)
    return {"geojson": ".geojson", "shp": ".shp", "kml": ".kml"}[f]


def filter_layers(all_layers: List[Dict[str, Any]], include: List[str] | None = None, pattern: str | None = None) -> List[Dict[str, Any]]:
    layers = all_layers
    if include:
        include_set = {x.strip() for x in include if x and x.strip()}
        layers = [rec for rec in layers if (rec.get("name") or "") in include_set]
    if pattern:
        pat = pattern.strip()
        layers = [rec for rec in layers if fnmatch(str(rec.get("name") or ""), pat)]
    return layers
