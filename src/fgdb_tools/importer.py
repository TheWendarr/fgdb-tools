from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import geopandas as gpd

from .common import (
    parse_pyogrio_list_layers,
    require_pyogrio,
    sanitize_fc_name,
    unique_name,
)

try:
    import pyogrio  # type: ignore
except Exception:  # pragma: no cover
    pyogrio = None  # type: ignore

SUPPORTED_EXTS = {".geojson", ".json", ".shp", ".kml"}
IF_EXISTS_CHOICES = {"unique", "skip", "fail"}


@dataclass(frozen=True)
class ImportOptions:
    out_gdb: Path
    in_dir: Optional[Path] = None
    in_paths: List[Path] = field(default_factory=list)  # individual files (repeatable)
    recursive: bool = False

    overwrite_gdb: bool = False
    append_gdb: bool = False  # write into an existing GDB without deleting it

    epsg: Optional[int] = None

    # KML handling
    kml_all_layers: bool = False
    kml_layers: List[str] = field(default_factory=list)  # if set, only import these KML layers

    use_arrow: bool = True
    force_2d: bool = False
    debug: bool = False

    driver: str = "OpenFileGDB"
    if_exists: str = "unique"  # unique|skip|fail (behavior when FC name already exists)


def check_openfilegdb_write_support() -> None:
    require_pyogrio()
    drivers = pyogrio.list_drivers(write=True)
    mode = drivers.get("OpenFileGDB")
    if mode is None or "w" not in str(mode):
        gdal_ver = getattr(pyogrio, "__gdal_version__", "unknown")
        raise RuntimeError(
            "Your GDAL build does not expose OpenFileGDB with write support.\n"
            f"Detected pyogrio GDAL version: {gdal_ver}\n"
            "Fix options:\n"
            "  - Use a Python environment that ships GDAL with OpenFileGDB write/create support.\n"
            "  - Conda-forge environments are often the most reliable for this.\n"
            "  - Confirm that `pyogrio.list_drivers(write=True)` includes 'OpenFileGDB': 'rw' or similar.\n"
        )


def iter_supported_files_from_dir(in_dir: Path, recursive: bool) -> Iterable[Path]:
    globber = in_dir.rglob if recursive else in_dir.glob
    for p in globber("*"):
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS:
            yield p


def collect_inputs(in_dir: Optional[Path], in_paths: List[Path], recursive: bool) -> List[Path]:
    out: List[Path] = []

    # 1) directory
    if in_dir is not None:
        d = in_dir.expanduser().resolve()
        if d.exists() and d.is_dir():
            out.extend(list(iter_supported_files_from_dir(d, recursive=recursive)))
        else:
            raise ValueError(f"--in-dir is not a directory: {d}")

    # 2) individual paths (files or directories)
    for p in in_paths:
        pp = p.expanduser().resolve()
        if pp.is_dir():
            out.extend(list(iter_supported_files_from_dir(pp, recursive=recursive)))
        elif pp.is_file():
            if pp.suffix.lower() in SUPPORTED_EXTS:
                out.append(pp)
        else:
            raise ValueError(f"Input path not found: {pp}")

    # de-dup while preserving order
    seen: set[str] = set()
    dedup: List[Path] = []
    for p in out:
        key = str(p)
        if key not in seen:
            seen.add(key)
            dedup.append(p)
    return dedup


def list_layers_meta(path: Path) -> List[Dict[str, Any]]:
    require_pyogrio()
    raw = pyogrio.list_layers(str(path))
    return parse_pyogrio_list_layers(raw)


def read_any_to_gdf(path: Path, layer: Optional[str], use_arrow: bool, force_2d: bool) -> gpd.GeoDataFrame:
    require_pyogrio()
    kwargs: Dict[str, Any] = {}
    if layer is not None:
        kwargs["layer"] = layer
    if force_2d:
        kwargs["force_2d"] = True

    if use_arrow:
        try:
            return pyogrio.read_dataframe(str(path), use_arrow=True, **kwargs)
        except TypeError:
            return pyogrio.read_dataframe(str(path), **kwargs)
        except Exception:
            return pyogrio.read_dataframe(str(path), **kwargs)

    return pyogrio.read_dataframe(str(path), **kwargs)


def write_layer_to_gdb(
    gdf: gpd.GeoDataFrame,
    out_gdb: Path,
    layer_name: str,
    driver: str,
    use_arrow: bool,
) -> None:
    require_pyogrio()
    if use_arrow:
        try:
            pyogrio.write_dataframe(
                gdf,
                str(out_gdb),
                layer=layer_name,
                driver=driver,
                use_arrow=True,
                append=False,  # create a new FC
            )
            return
        except TypeError:
            pyogrio.write_dataframe(gdf, str(out_gdb), layer=layer_name, driver=driver, append=False)
            return
        except Exception:
            pyogrio.write_dataframe(gdf, str(out_gdb), layer=layer_name, driver=driver, append=False)
            return

    pyogrio.write_dataframe(gdf, str(out_gdb), layer=layer_name, driver=driver, append=False)


def choose_kml_layers(available: List[str], opts: ImportOptions) -> List[str]:
    if not available:
        return []
    if opts.kml_layers:
        missing = [x for x in opts.kml_layers if x not in available]
        if missing:
            raise ValueError(f"Requested KML layer(s) not found: {missing}")
        return list(opts.kml_layers)
    if opts.kml_all_layers:
        return list(available)
    # default: first layer
    return [available[0]]


def run_import(opts: ImportOptions) -> int:
    out_gdb = opts.out_gdb.expanduser().resolve()

    if opts.if_exists not in IF_EXISTS_CHOICES:
        print(f"[ERROR] Invalid --if-exists: {opts.if_exists}. Choose from: {sorted(IF_EXISTS_CHOICES)}", file=sys.stderr)
        return 2

    if out_gdb.suffix.lower() != ".gdb":
        print(f"[ERROR] --out-gdb must end with .gdb: {out_gdb}", file=sys.stderr)
        return 2

    if opts.in_dir is None and not opts.in_paths:
        print("[ERROR] Provide at least one input source: --in-dir and/or --in-path", file=sys.stderr)
        return 2

    try:
        inputs = collect_inputs(opts.in_dir, opts.in_paths, recursive=opts.recursive)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2

    if not inputs:
        print("[ERROR] No supported inputs found.", file=sys.stderr)
        return 2

    try:
        check_openfilegdb_write_support()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2

    # Handle output GDB
    if out_gdb.exists() and not opts.append_gdb:
        if not opts.overwrite_gdb:
            print(f"[ERROR] Output GDB exists (use --overwrite-gdb or --append-gdb): {out_gdb}", file=sys.stderr)
            return 2
        shutil.rmtree(out_gdb)

    out_gdb.parent.mkdir(parents=True, exist_ok=True)

    # Track existing layers (for collision + if-exists policies)
    used_layer_names: set[str] = set()
    existing_layers: set[str] = set()
    if out_gdb.exists():
        try:
            meta = list_layers_meta(out_gdb)
            for rec in meta:
                n = str(rec.get("name") or "").strip()
                if n:
                    existing_layers.add(n)
                    used_layer_names.add(n)
        except Exception:
            # If listing fails, still proceed; collisions will error during write.
            pass

    imported = 0
    skipped = 0
    errors = 0

    if opts.debug:
        gdal_ver = getattr(pyogrio, "__gdal_version__", "unknown")
        print(
            f"[DEBUG] GDAL={gdal_ver} use_arrow={opts.use_arrow} force_2d={opts.force_2d} "
            f"epsg={opts.epsg} append_gdb={opts.append_gdb} if_exists={opts.if_exists}"
        )
        print(f"[DEBUG] inputs_found={len(inputs)} out_gdb={out_gdb}")

    for src in inputs:
        try:
            ext = src.suffix.lower()
            base = sanitize_fc_name(src.stem)

            if ext == ".kml":
                # KML may have multiple layers
                meta = list_layers_meta(src)
                avail_layers = [str(rec.get("name") or "").strip() for rec in meta if str(rec.get("name") or "").strip()]
                layer_names = choose_kml_layers(avail_layers, opts)
            else:
                layer_names = [None]  # read without specifying layer

            for lname in layer_names:
                # Determine feature class name
                if lname is None:
                    fc_base = base
                    read_layer = None
                    label = src.name
                else:
                    fc_base = sanitize_fc_name(f"{base}_{lname}") if (opts.kml_all_layers or opts.kml_layers) else base
                    read_layer = lname
                    label = f"{src.name} :: {lname}"

                # if-exists policy (against existing layers only)
                if fc_base in existing_layers:
                    if opts.if_exists == "skip":
                        skipped += 1
                        print(f"SKIP (exists): {label} -> {fc_base}")
                        continue
                    if opts.if_exists == "fail":
                        raise RuntimeError(f"Feature class already exists in GDB: {fc_base}")

                # ensure unique output name for this run (and against existing layers)
                fc_name = fc_base if opts.if_exists != "unique" else unique_name(fc_base, used_layer_names)
                if fc_name in existing_layers and opts.if_exists == "unique":
                    # unique_name already checks used_layer_names, which includes existing_layers,
                    # but keep this guard in case list_layers failed.
                    fc_name = unique_name(fc_name, used_layer_names)

                gdf = read_any_to_gdf(src, layer=read_layer, use_arrow=opts.use_arrow, force_2d=opts.force_2d)
                if gdf.empty:
                    skipped += 1
                    print(f"SKIP (0 features): {label}")
                    continue

                if opts.epsg is not None:
                    if gdf.crs is None:
                        skipped += 1
                        print(f"SKIP (no CRS; cannot reproject): {label}")
                        continue
                    gdf = gdf.to_crs(epsg=opts.epsg)

                write_layer_to_gdb(
                    gdf,
                    out_gdb,
                    layer_name=fc_name,
                    driver=opts.driver,
                    use_arrow=opts.use_arrow,
                )
                imported += 1
                used_layer_names.add(fc_name)
                existing_layers.add(fc_name)
                print(f"OK: {label} -> {fc_name}")

        except Exception as e:
            errors += 1
            print(f"ERROR: {src} :: {e}", file=sys.stderr)

    summary = {
        "imported_layers": imported,
        "skipped": skipped,
        "errors": errors,
        "inputs_found": len(inputs),
        "out_gdb": str(out_gdb),
        "use_arrow": opts.use_arrow,
        "epsg": opts.epsg,
        "force_2d": opts.force_2d,
        "recursive": opts.recursive,
        "kml_all_layers": opts.kml_all_layers,
        "kml_layers": opts.kml_layers,
        "append_gdb": opts.append_gdb,
        "if_exists": opts.if_exists,
    }
    print("\n[SUMMARY]")
    print(json.dumps(summary, indent=2))
    return 0 if imported > 0 and errors == 0 else (1 if imported > 0 else 2)
