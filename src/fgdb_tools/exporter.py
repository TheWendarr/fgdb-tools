from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import geopandas as gpd

from .common import (
    ensure_out_dir,
    export_driver_for,
    export_extension_for,
    filter_layers,
    parse_pyogrio_list_layers,
    require_pyogrio,
    sanitize_filename,
)

try:
    import pyogrio  # type: ignore
except Exception:  # pragma: no cover
    pyogrio = None  # type: ignore


@dataclass(frozen=True)
class ExportOptions:
    gdb_path: Path
    out_dir: Path
    fmt: str = "geojson"  # geojson | shp | kml
    epsg: Optional[int] = None
    overwrite: bool = False
    use_arrow: bool = True
    names_only: bool = False
    layers: List[str] = field(default_factory=list)  # explicit include list
    pattern: Optional[str] = None  # wildcard pattern (e.g., "*roads*")
    max_layers: Optional[int] = None
    debug: bool = False


def list_layers_meta(gdb_path: Path) -> List[Dict[str, Any]]:
    require_pyogrio()
    raw = pyogrio.list_layers(str(gdb_path))
    return parse_pyogrio_list_layers(raw)


def read_layer_fast(gdb_path: Path, layer_name: str, use_arrow: bool) -> gpd.GeoDataFrame:
    require_pyogrio()
    if use_arrow:
        try:
            return pyogrio.read_dataframe(str(gdb_path), layer=layer_name, use_arrow=True)
        except TypeError:
            return pyogrio.read_dataframe(str(gdb_path), layer=layer_name)
        except Exception:
            return pyogrio.read_dataframe(str(gdb_path), layer=layer_name)
    return pyogrio.read_dataframe(str(gdb_path), layer=layer_name)


def write_vector_fast(gdf: gpd.GeoDataFrame, out_path: Path, driver: str, use_arrow: bool) -> None:
    """Write a single-layer vector file."""
    require_pyogrio()
    try:
        if use_arrow:
            try:
                pyogrio.write_dataframe(gdf, str(out_path), driver=driver, use_arrow=True)
                return
            except TypeError:
                pyogrio.write_dataframe(gdf, str(out_path), driver=driver)
                return
            except Exception:
                pyogrio.write_dataframe(gdf, str(out_path), driver=driver)
                return

        pyogrio.write_dataframe(gdf, str(out_path), driver=driver)
        return
    except Exception:
        # Fiona fallback
        gdf.to_file(str(out_path), driver=driver)


def make_unique_out_path(out_dir: Path, base_name: str, ext: str, overwrite: bool) -> Path:
    out = out_dir / f"{base_name}{ext}"
    if overwrite or not out.exists():
        return out
    i = 2
    while True:
        cand = out_dir / f"{base_name}_{i}{ext}"
        if not cand.exists():
            return cand
        i += 1


def export_layer(
    gdb_path: Path,
    layer_name: str,
    geometry_type: Any,
    out_dir: Path,
    fmt: str,
    epsg: Optional[int],
    overwrite: bool,
    use_arrow: bool,
    debug: bool = False,
) -> Tuple[bool, str]:
    if geometry_type in (None, "", "None"):
        return False, f"SKIP (non-spatial): {layer_name}"

    driver = export_driver_for(fmt)
    ext = export_extension_for(fmt)

    safe = sanitize_filename(layer_name)
    out_path = make_unique_out_path(out_dir, safe, ext=ext, overwrite=overwrite)

    if out_path.exists() and not overwrite:
        return False, f"SKIP (exists): {out_path.name}"

    try:
        gdf = read_layer_fast(gdb_path, layer_name, use_arrow=use_arrow)
    except Exception as e:
        return False, f"SKIP (read failed): {layer_name} :: {e}"

    if gdf.empty:
        return False, f"SKIP (0 features): {layer_name}"

    # KML should be WGS84. If user didn't specify epsg, enforce 4326.
    effective_epsg = epsg
    if fmt.lower() == "kml":
        effective_epsg = 4326

    if effective_epsg is not None:
        if gdf.crs is None:
            return False, f"SKIP (no CRS; cannot reproject): {layer_name}"
        try:
            gdf = gdf.to_crs(epsg=effective_epsg)
        except Exception as e:
            return False, f"SKIP (reproject failed): {layer_name} :: {e}"

    if debug and fmt.lower() == "kml" and epsg not in (None, 4326):
        print(f"[DEBUG] KML forces EPSG:4326 (ignored requested epsg={epsg})")

    try:
        write_vector_fast(gdf, out_path, driver=driver, use_arrow=use_arrow)
    except Exception as e:
        return False, f"SKIP (write failed): {layer_name} -> {out_path.name} :: {e}"

    return True, f"OK: {layer_name} -> {out_path.name} ({len(gdf)} features)"


def run_export(opts: ExportOptions) -> int:
    gdb_path = opts.gdb_path.expanduser().resolve()
    out_dir = opts.out_dir.expanduser().resolve()

    if not gdb_path.exists():
        print(f"[ERROR] Path not found: {gdb_path}", file=sys.stderr)
        return 2
    if gdb_path.suffix.lower() != ".gdb":
        print(f"[ERROR] Not a .gdb path: {gdb_path}", file=sys.stderr)
        return 2
    if pyogrio is None:
        print("[ERROR] Missing dependency: pyogrio. Install with: pip install pyogrio", file=sys.stderr)
        return 2

    try:
        layers_all = list_layers_meta(gdb_path)
    except Exception as e:
        print(f"[ERROR] Failed to list layers: {e}", file=sys.stderr)
        return 1

    # Apply selection filters
    layers = filter_layers(layers_all, include=opts.layers or None, pattern=opts.pattern)

    if opts.layers:
        found = {str(rec.get("name") or "") for rec in layers}
        missing = [x for x in opts.layers if x not in found]
        if missing:
            print(f"[ERROR] Requested layer(s) not found: {missing}", file=sys.stderr)
            return 2

    if opts.max_layers is not None:
        layers = layers[: max(opts.max_layers, 0)]

    if opts.debug:
        print(
            f"[DEBUG] layers_listed={len(layers_all)} layers_selected={len(layers)} "
            f"fmt={opts.fmt} use_arrow={opts.use_arrow} epsg={opts.epsg} pattern={opts.pattern}"
        )

    if opts.names_only:
        for rec in layers:
            name = str(rec.get("name") or "").strip()
            if name:
                print(name)
        return 0

    ensure_out_dir(out_dir)

    ok = 0
    skipped = 0

    for rec in layers:
        layer_name = str(rec.get("name") or "").strip()
        if not layer_name:
            skipped += 1
            continue

        success, msg = export_layer(
            gdb_path=gdb_path,
            layer_name=layer_name,
            geometry_type=rec.get("geometry_type"),
            out_dir=out_dir,
            fmt=opts.fmt,
            epsg=opts.epsg,
            overwrite=opts.overwrite,
            use_arrow=opts.use_arrow,
            debug=opts.debug,
        )
        print(msg)
        if success:
            ok += 1
        else:
            skipped += 1

    summary = {
        "exported": ok,
        "skipped": skipped,
        "layers_listed": len(layers_all),
        "layers_selected": len(layers),
        "format": opts.fmt,
        "use_arrow": opts.use_arrow,
        "epsg": opts.epsg,
        "overwrite": opts.overwrite,
        "out_dir": str(out_dir),
        "gdb": str(gdb_path),
        "pattern": opts.pattern,
        "layers": opts.layers,
    }
    print("\n[SUMMARY]")
    print(json.dumps(summary, indent=2))
    return 0 if ok > 0 else 1
