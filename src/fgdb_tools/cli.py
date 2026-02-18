from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from .exporter import ExportOptions, run_export
from .importer import ImportOptions, run_import


def build_parser_export() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Export FileGDB feature classes (layers) to GeoJSON, Shapefile, or KML.")
    p.add_argument("--gdb", required=True, help="Path to the .gdb folder")
    p.add_argument("--out-dir", required=True, help="Output directory for exported files")
    p.add_argument(
        "--format",
        default="geojson",
        choices=["geojson", "shp", "kml"],
        help="Output format (geojson | shp | kml)",
    )
    p.add_argument("--layer", action="append", default=[], help="Export only this layer (repeatable)")
    p.add_argument("--pattern", default=None, help='Wildcard filter for layer names, e.g. "*Road*"')
    p.add_argument("--epsg", type=int, default=None, help="Optional: reproject outputs to this EPSG (e.g., 4326). KML forces 4326.")
    p.add_argument("--overwrite", action="store_true", help="Overwrite existing outputs")
    p.add_argument("--names-only", action="store_true", help="List selected layer names and exit (no export)")
    p.add_argument("--no-arrow", action="store_true", help="Disable Arrow acceleration")
    p.add_argument("--max-layers", type=int, default=None, help="Only process first N selected layers")
    p.add_argument("--debug", action="store_true", help="Print debug diagnostics")
    return p


def build_parser_import() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Import vector files into an Esri File Geodatabase (.gdb).")
    p.add_argument("--out-gdb", required=True, help="Output .gdb path (directory ending in .gdb)")
    p.add_argument("--in-dir", default=None, help="Directory containing input vectors (.geojson/.shp/.kml). Optional if --in-path is used.")
    p.add_argument("--in-path", action="append", default=[], help="Input file OR directory (repeatable). Supports .geojson/.shp/.kml")
    p.add_argument("--recursive", action="store_true", help="Recurse into subdirectories when a directory is provided")
    p.add_argument("--overwrite-gdb", action="store_true", help="Delete and recreate output .gdb if it exists")
    p.add_argument("--append-gdb", action="store_true", help="Write into an existing .gdb (do not delete it)")
    p.add_argument("--if-exists", default="unique", choices=["unique", "skip", "fail"], help="If output FC already exists in GDB")
    p.add_argument("--epsg", type=int, default=None, help="Optional: reproject all imported data to EPSG:<code> before writing")
    p.add_argument("--kml-all-layers", action="store_true", help="For KML inputs, import all layers")
    p.add_argument("--kml-layer", action="append", default=[], help="For KML inputs, import only this layer name (repeatable)")
    p.add_argument("--no-arrow", action="store_true", help="Disable Arrow acceleration (if available)")
    p.add_argument("--force-2d", action="store_true", help="Drop Z values (2D geometries only)")
    p.add_argument("--debug", action="store_true", help="Print extra diagnostics")
    return p


def main_export(argv: Optional[List[str]] = None) -> int:
    args = build_parser_export().parse_args(argv)
    opts = ExportOptions(
        gdb_path=Path(args.gdb),
        out_dir=Path(args.out_dir),
        fmt=args.format,
        epsg=args.epsg,
        overwrite=args.overwrite,
        use_arrow=not args.no_arrow,
        names_only=args.names_only,
        layers=list(args.layer or []),
        pattern=args.pattern,
        max_layers=args.max_layers,
        debug=args.debug,
    )
    return run_export(opts)


def main_import(argv: Optional[List[str]] = None) -> int:
    args = build_parser_import().parse_args(argv)
    in_dir = Path(args.in_dir) if args.in_dir else None
    opts = ImportOptions(
        out_gdb=Path(args.out_gdb),
        in_dir=in_dir,
        in_paths=[Path(p) for p in (args.in_path or [])],
        recursive=args.recursive,
        overwrite_gdb=args.overwrite_gdb,
        append_gdb=args.append_gdb,
        if_exists=args.if_exists,
        epsg=args.epsg,
        kml_all_layers=args.kml_all_layers,
        kml_layers=list(args.kml_layer or []),
        use_arrow=not args.no_arrow,
        force_2d=args.force_2d,
        debug=args.debug,
    )
    return run_import(opts)
