from __future__ import annotations

import contextlib
import io
import os
import sys
import queue
import subprocess
import threading
import traceback
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog
    from tkinter import ttk
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "Tkinter is required for the GUI but is not available in this Python installation."
    ) from e

from .common import normalize_format, parse_pyogrio_list_layers, require_pyogrio
from .exporter import ExportOptions, run_export
from .importer import ImportOptions, run_import

try:
    import pyogrio  # type: ignore
except Exception:  # pragma: no cover
    pyogrio = None  # type: ignore


SUPPORTED_FILE_EXTS = {".geojson", ".json", ".shp", ".kml"}

FILETYPES_IMPORT = [
    ("Geospatial", "*.geojson *.json *.shp *.kml"),
    ("GeoJSON", "*.geojson *.json"),
    ("Shapefile", "*.shp"),
    ("KML", "*.kml"),
    ("All files", "*.*"),
]


class _StreamToQueue(io.TextIOBase):
    def __init__(self, q: "queue.Queue[str]"):
        self.q = q
        self._buf = ""

    def write(self, s: str) -> int:  # type: ignore[override]
        if not s:
            return 0
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self.q.put(line)
        return len(s)

    def flush(self) -> None:  # pragma: no cover
        if self._buf.strip():
            self.q.put(self._buf.strip())
        self._buf = ""


def _is_gdb_path(p: Path) -> bool:
    return p.exists() and p.is_dir() and p.suffix.lower() == ".gdb"


def _safe_int(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(s)
    except Exception:
        return None


def _open_in_file_explorer(path: Path) -> None:
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
            return
        if sys.platform == "darwin":  # pragma: no cover
            subprocess.run(["open", str(path)], check=False)
            return
        subprocess.run(["xdg-open", str(path)], check=False)  # pragma: no cover
    except Exception:
        # best-effort only
        return


def _list_roots() -> List[Path]:
    # Windows drive letters
    if os.name == "nt":
        roots: List[Path] = []
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            p = Path(f"{c}:/")
            if p.exists():
                roots.append(p)
        return roots
    # POSIX
    return [Path("/")]


def _driver_for_format(fmt: str) -> str:
    fmt = normalize_format(fmt)
    if fmt == "geojson":
        return "GeoJSON"
    if fmt == "shp":
        return "ESRI Shapefile"
    if fmt == "kml":
        return "KML"
    raise ValueError(f"Unsupported format: {fmt}")


class FGDBToolsApp(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.master = master
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.busy_q: "queue.Queue[bool]" = queue.Queue()

        self._build_ui()
        self._poll_queues()

    # ---------------- UI shell ----------------

    def _build_ui(self) -> None:
        self.master.title("FGDB Tools")
        self.master.geometry("1100x720")
        self.master.minsize(980, 640)

        self.nb = ttk.Notebook(self.master)
        self.nb.pack(fill="both", expand=True)

        self.tab_home = ttk.Frame(self.nb)
        self.tab_view = ttk.Frame(self.nb)
        self.tab_data = ttk.Frame(self.nb)

        self.nb.add(self.tab_home, text="Home")
        self.nb.add(self.tab_view, text="View")
        self.nb.add(self.tab_data, text="Data")

        self._build_home(self.tab_home)
        self._build_view(self.tab_view)
        self._build_data(self.tab_data)

        # Bottom: progress only
        self.progress = ttk.Progressbar(self.master, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

    # ---------------- Home tab ----------------

    def _build_home(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        header = ttk.Frame(parent)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        header.columnconfigure(2, weight=1)

        ttk.Label(header, text="Action:").grid(row=0, column=0, sticky="w")

        self.home_action_var = tk.StringVar(value="View data")
        self.home_action = ttk.Combobox(
            header,
            textvariable=self.home_action_var,
            state="readonly",
            values=[
                "Create FGDB",
                "Import FGDB",
                "Export Geospatial Files",
                "View data",
            ],
            width=28,
        )
        self.home_action.grid(row=0, column=1, sticky="w", padx=8)

        ttk.Button(header, text="Go", command=self._home_go, width=10).grid(
            row=0, column=2, sticky="w"
        )

        hint = (
            "Notes: The GUI uses pyogrio/GDAL OpenFileGDB for FGDB read/write. "
            "KML export depends on your GDAL build supporting KML write."
        )
        ttk.Label(parent, text=hint, justify="left").grid(
            row=1, column=0, sticky="ew", padx=14, pady=(0, 8)
        )

        # Log box lives on Home tab
        log_frame = ttk.LabelFrame(parent, text="Command Log")
        log_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=18, wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")

        sb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=sb.set)

        btn_row = ttk.Frame(log_frame)
        btn_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(btn_row, text="Clear Log", command=self._clear_log).pack(
            side="left"
        )

    def _home_go(self) -> None:
        sel = (self.home_action_var.get() or "").strip()
        if sel == "View data":
            self.nb.select(self.tab_view)
            return
        self.nb.select(self.tab_data)
        if sel == "Create FGDB":
            self._set_data_mode("Create FGDB")
        elif sel == "Import FGDB":
            self._set_data_mode("Import")
        elif sel == "Export Geospatial Files":
            self._set_data_mode("Export")

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", "end")

    # ---------------- Logging / threading ----------------

    def log(self, msg: str) -> None:
        self.log_q.put(msg)

    def _append_log(self, msg: str) -> None:
        self.log_text.insert("end", msg.rstrip() + "\n")
        self.log_text.see("end")

    def _set_busy(self, busy: bool) -> None:
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _poll_queues(self) -> None:
        try:
            while True:
                msg = self.log_q.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass

        try:
            while True:
                busy = self.busy_q.get_nowait()
                self._set_busy(busy)
        except queue.Empty:
            pass

        self.master.after(120, self._poll_queues)

    def _run_in_thread(self, target, *args) -> None:
        def runner():
            stream = _StreamToQueue(self.log_q)
            self.busy_q.put(True)
            try:
                with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                    target(*args)
            except Exception:
                tb = traceback.format_exc()
                self.log_q.put("[ERROR] Unhandled exception:")
                for line in tb.splitlines():
                    self.log_q.put(line)
            finally:
                self.busy_q.put(False)

        threading.Thread(target=runner, daemon=True).start()

    # ---------------- View tab ----------------

    def _build_view(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        pw = ttk.Panedwindow(parent, orient="horizontal")
        pw.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        left = ttk.Frame(pw)
        right = ttk.Frame(pw)
        pw.add(left, weight=2)
        pw.add(right, weight=3)

        # Left: file tree
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)

        tool_row = ttk.Frame(left)
        tool_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.view_show_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tool_row,
            text="Show all files",
            variable=self.view_show_all_var,
            command=self._view_refresh_current_node,
        ).pack(side="left")

        ttk.Button(tool_row, text="Refresh", command=self._view_rebuild_tree).pack(
            side="left", padx=8
        )
        ttk.Button(tool_row, text="Jump to Home (log)", command=lambda: self.nb.select(self.tab_home)).pack(
            side="right"
        )

        self.view_tree = ttk.Treeview(left, selectmode="browse")
        self.view_tree.grid(row=1, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.view_tree.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        hsb = ttk.Scrollbar(left, orient="horizontal", command=self.view_tree.xview)
        hsb.grid(row=2, column=0, sticky="ew")
        self.view_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # hidden data columns
        self.view_tree["columns"] = ("path", "kind", "layer")
        self.view_tree.column("path", width=0, stretch=False)
        self.view_tree.column("kind", width=0, stretch=False)
        self.view_tree.column("layer", width=0, stretch=False)

        self.view_tree.bind("<<TreeviewOpen>>", self._view_on_open)
        self.view_tree.bind("<<TreeviewSelect>>", self._view_on_select)
        self.view_tree.bind("<Button-3>", self._view_on_right_click)

        # Right: preview
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        ttk.Label(right, text="Preview", font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, sticky="w"
        )

        self.preview_text = tk.Text(right, wrap="none")
        self.preview_text.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        psb = ttk.Scrollbar(right, orient="vertical", command=self.preview_text.yview)
        psb.grid(row=1, column=1, sticky="ns", pady=(6, 0))
        self.preview_text.configure(yscrollcommand=psb.set)

        self._view_ctx_menu = tk.Menu(self.master, tearoff=0)

        self._view_rebuild_tree()

    def _view_rebuild_tree(self) -> None:
        self.view_tree.delete(*self.view_tree.get_children(""))
        roots = _list_roots()
        for r in roots:
            iid = self.view_tree.insert("", "end", text=str(r), values=(str(r), "dir", ""))
            self._view_insert_dummy(iid)
        self.log(f"[VIEW] Loaded roots: {', '.join(str(r) for r in roots)}")

    def _view_insert_dummy(self, iid: str) -> None:
        # dummy child so it shows an expand arrow
        self.view_tree.insert(iid, "end", text="…", values=("", "dummy", ""))

    def _view_get_item_meta(self, iid: str) -> Tuple[Path, str, str]:
        p = Path(self.view_tree.set(iid, "path") or ".").expanduser()
        kind = self.view_tree.set(iid, "kind") or ""
        layer = self.view_tree.set(iid, "layer") or ""
        return p, kind, layer

    def _view_on_open(self, _evt=None) -> None:
        iid = self.view_tree.focus()
        if not iid:
            return
        # Only populate if dummy exists
        kids = self.view_tree.get_children(iid)
        if len(kids) == 1 and self.view_tree.set(kids[0], "kind") == "dummy":
            self.view_tree.delete(kids[0])
            p, kind, _layer = self._view_get_item_meta(iid)
            if kind in ("dir", "gdb"):
                self._view_populate_dir(iid, p)

    def _view_refresh_current_node(self) -> None:
        iid = self.view_tree.focus()
        if not iid:
            return
        p, kind, _ = self._view_get_item_meta(iid)
        if kind not in ("dir", "gdb"):
            return
        self.view_tree.delete(*self.view_tree.get_children(iid))
        self._view_populate_dir(iid, p)

    def _view_populate_dir(self, parent_iid: str, d: Path) -> None:
        if not d.exists() or not d.is_dir():
            return

        # Treat FGDB as a special container
        if d.suffix.lower() == ".gdb":
            self.view_tree.set(parent_iid, "kind", "gdb")
            if pyogrio is None:
                self.view_tree.insert(parent_iid, "end", text="(pyogrio not available)", values=(str(d), "info", ""))
                return
            try:
                meta = parse_pyogrio_list_layers(pyogrio.list_layers(str(d)))
                for rec in meta:
                    name = str(rec.get("name") or "").strip()
                    if not name:
                        continue
                    gt = rec.get("geometry_type")
                    tag = "table" if gt in (None, "", "None") else str(gt)
                    text = f"{name}  [{tag}]"
                    self.view_tree.insert(parent_iid, "end", text=text, values=(str(d), "gdb_layer", name))
                self.log(f"[VIEW] {d.name}: {len(meta)} layer(s)")
            except Exception as e:
                self.view_tree.insert(parent_iid, "end", text=f"(error listing layers: {e})", values=(str(d), "info", ""))
            return

        # Normal directory
        show_all = bool(self.view_show_all_var.get())

        try:
            entries = sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        except Exception:
            return

        for p in entries:
            try:
                if p.is_dir():
                    kind = "gdb" if p.suffix.lower() == ".gdb" else "dir"
                    iid = self.view_tree.insert(parent_iid, "end", text=p.name, values=(str(p), kind, ""))
                    self._view_insert_dummy(iid)
                else:
                    ext = p.suffix.lower()
                    if show_all or ext in SUPPORTED_FILE_EXTS:
                        self.view_tree.insert(parent_iid, "end", text=p.name, values=(str(p), "file", ""))
            except Exception:
                continue

    def _view_on_select(self, _evt=None) -> None:
        iid = self.view_tree.focus()
        if not iid:
            return
        p, kind, layer = self._view_get_item_meta(iid)
        self._view_preview(p, kind, layer)

    def _view_preview(self, p: Path, kind: str, layer: str) -> None:
        self.preview_text.delete("1.0", "end")

        if kind == "gdb":
            self.preview_text.insert("end", f"FGDB: {p}\n")
            if pyogrio is None:
                self.preview_text.insert("end", "pyogrio not available.\n")
                return
            try:
                meta = parse_pyogrio_list_layers(pyogrio.list_layers(str(p)))
                self.preview_text.insert("end", f"Layers: {len(meta)}\n\n")
                for rec in meta:
                    name = str(rec.get("name") or "").strip()
                    gt = rec.get("geometry_type")
                    tag = "table" if gt in (None, "", "None") else str(gt)
                    if name:
                        self.preview_text.insert("end", f"- {name} [{tag}]\n")
            except Exception as e:
                self.preview_text.insert("end", f"Error listing layers: {e}\n")
            return

        if kind == "gdb_layer":
            self.preview_text.insert("end", f"FGDB Layer\nGDB: {p}\nLayer: {layer}\n\n")
            try:
                text = self._read_sample_text(path=p, kind=kind, layer=layer)
                self.preview_text.insert("end", text)
            except Exception as e:
                self.preview_text.insert("end", f"Preview error: {e}\n")
            return

        if kind == "file":
            self.preview_text.insert("end", f"File: {p}\n\n")
            try:
                text = self._read_sample_text(path=p, kind=kind, layer=None)
                self.preview_text.insert("end", text)
            except Exception as e:
                self.preview_text.insert("end", f"Preview error: {e}\n")
            return

        # fallback
        self.preview_text.insert("end", f"{kind}: {p}\n")

    def _read_sample_text(self, path: Path, kind: str, layer: Optional[str], n: int = 25) -> str:
        """Best-effort small preview without assuming pyogrio API details."""
        import inspect

        # Prefer pyogrio for speed when available
        if pyogrio is not None:
            try:
                kwargs = {}
                if layer:
                    kwargs["layer"] = layer

                sig = inspect.signature(pyogrio.read_dataframe)
                if "max_features" in sig.parameters:
                    kwargs["max_features"] = n
                elif "rows" in sig.parameters:
                    kwargs["rows"] = n
                elif "skip_features" in sig.parameters and "max_features" in sig.parameters:
                    kwargs["skip_features"] = 0
                    kwargs["max_features"] = n

                gdf = pyogrio.read_dataframe(str(path), **kwargs)
                return self._format_gdf_preview(gdf)
            except Exception:
                pass

        # Fallback to geopandas (may read full dataset)
        import geopandas as gpd
        try:
            if layer and kind == "gdb_layer":
                gdf = gpd.read_file(str(path), layer=layer)
            else:
                gdf = gpd.read_file(str(path))
        except Exception as e:
            return f"Unable to read dataset for preview: {e}\n"

        return self._format_gdf_preview(gdf, head_n=min(10, len(gdf)))

    def _format_gdf_preview(self, gdf, head_n: int = 10) -> str:
        import pandas as pd

        lines: List[str] = []
        try:
            lines.append(f"Features loaded (preview): {len(gdf)}")
        except Exception:
            pass

        try:
            crs = getattr(gdf, "crs", None)
            if crs:
                lines.append(f"CRS: {crs}")
        except Exception:
            pass

        try:
            geom = getattr(gdf, "geometry", None)
            if geom is not None and len(geom) > 0:
                gt = getattr(geom, "geom_type", None)
                if gt is not None:
                    # geom_type is a Series
                    lines.append(f"Geometry types: {', '.join(sorted(set(gt.astype(str).tolist())))}")
        except Exception:
            pass

        lines.append("")

        # Show attribute sample
        try:
            df = pd.DataFrame(gdf)
            if "geometry" in df.columns:
                df = df.drop(columns=["geometry"], errors="ignore")
            df = df.head(head_n)
            if df.shape[1] == 0:
                lines.append("(No attribute columns to display)")
            else:
                lines.append(df.to_string(index=False))
        except Exception as e:
            lines.append(f"(Preview formatting error: {e})")

        return "\n".join(lines) + "\n"

    def _view_on_right_click(self, event) -> None:
        iid = self.view_tree.identify_row(event.y)
        if not iid:
            return
        self.view_tree.selection_set(iid)
        self.view_tree.focus(iid)

        p, kind, layer = self._view_get_item_meta(iid)

        self._view_ctx_menu.delete(0, "end")

        # Always available
        self._view_ctx_menu.add_command(
            label="Open in File Explorer",
            command=lambda: _open_in_file_explorer(p if kind != "gdb_layer" else p),
        )

        # Convert/export options
        if kind == "file" and p.suffix.lower() in SUPPORTED_FILE_EXTS:
            self._view_ctx_menu.add_separator()
            self._view_ctx_menu.add_command(
                label="Export to FGDB",
                command=lambda: self._ctx_import_file_to_gdb(p),
            )
            self._view_ctx_menu.add_separator()
            self._view_ctx_menu.add_command(
                label="Export to GeoJSON",
                command=lambda: self._ctx_convert_file(p, "geojson"),
            )
            self._view_ctx_menu.add_command(
                label="Export to SHP",
                command=lambda: self._ctx_convert_file(p, "shp"),
            )
            self._view_ctx_menu.add_command(
                label="Export to KML",
                command=lambda: self._ctx_convert_file(p, "kml"),
            )

        if kind == "gdb_layer":
            self._view_ctx_menu.add_separator()
            self._view_ctx_menu.add_command(
                label="Export to GeoJSON",
                command=lambda: self._ctx_export_layer(p, layer, "geojson"),
            )
            self._view_ctx_menu.add_command(
                label="Export to SHP",
                command=lambda: self._ctx_export_layer(p, layer, "shp"),
            )
            self._view_ctx_menu.add_command(
                label="Export to KML",
                command=lambda: self._ctx_export_layer(p, layer, "kml"),
            )

        if kind == "gdb":
            self._view_ctx_menu.add_separator()
            self._view_ctx_menu.add_command(
                label="Export from this FGDB (Data tab)",
                command=lambda: self._ctx_open_data_export(gdb=p),
            )

        self._view_ctx_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_open_data_export(self, gdb: Path) -> None:
        self.nb.select(self.tab_data)
        self._set_data_mode("Export")
        self.exp_gdb_var.set(str(gdb))
        self._exp_load_layers()

    def _ctx_import_file_to_gdb(self, in_path: Path) -> None:
        out = filedialog.askdirectory(title="Select output .gdb (existing or new)")
        if not out:
            return
        out_gdb = Path(out).expanduser()
        if out_gdb.suffix.lower() != ".gdb":
            # allow selecting parent folder; prompt for gdb name
            name = simpledialog.askstring("FGDB name", "Enter FGDB name (without extension):")
            if not name:
                return
            out_gdb = out_gdb / f"{name}.gdb"

        epsg = simpledialog.askstring("EPSG (optional)", "EPSG integer (blank for none):")
        epsg_i = _safe_int(epsg or "")
        if (epsg or "").strip() and epsg_i is None:
            messagebox.showerror("Invalid EPSG", "EPSG must be an integer.")
            return

        opts = ImportOptions(
            out_gdb=out_gdb,
            in_dir=None,
            in_paths=[in_path],
            recursive=False,
            overwrite_gdb=False,
            append_gdb=True,
            epsg=epsg_i,
            kml_all_layers=False,
            kml_layers=[],
            force_2d=False,
            if_exists="unique",
            debug=True,
        )

        self.log(f"[CTX][IMPORT] {in_path.name} -> {out_gdb}")
        self._run_in_thread(self._imp_worker, opts)

    def _ctx_export_layer(self, gdb: Path, layer: str, fmt: str) -> None:
        outdir = filedialog.askdirectory(title="Select output folder")
        if not outdir:
            return
        out_dir = Path(outdir).expanduser()

        epsg = simpledialog.askstring("EPSG (optional)", "EPSG integer (blank for none):")
        epsg_i = _safe_int(epsg or "")
        if (epsg or "").strip() and epsg_i is None:
            messagebox.showerror("Invalid EPSG", "EPSG must be an integer.")
            return

        overwrite = messagebox.askyesno("Overwrite", "Overwrite outputs if they exist?")

        opts = ExportOptions(
            gdb_path=gdb,
            out_dir=out_dir,
            fmt=normalize_format(fmt),
            epsg=epsg_i,
            overwrite=overwrite,
            layers=[layer],
            pattern=None,
            debug=True,
        )

        self.log(f"[CTX][EXPORT] {gdb.name}:{layer} -> {out_dir} ({fmt})")
        self._run_in_thread(self._exp_worker, opts)

    def _ctx_convert_file(self, in_path: Path, fmt: str) -> None:
        outdir = filedialog.askdirectory(title="Select output folder")
        if not outdir:
            return
        out_dir = Path(outdir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)

        fmt = normalize_format(fmt)
        out_path = out_dir / f"{in_path.stem}.{fmt if fmt != 'shp' else 'shp'}"

        overwrite = messagebox.askyesno("Overwrite", "Overwrite output if it exists?")
        if out_path.exists() and not overwrite:
            return

        self.log(f"[CTX][CONVERT] {in_path.name} -> {out_path.name}")
        self._run_in_thread(self._convert_worker, in_path, out_path, fmt)

    def _convert_worker(self, in_path: Path, out_path: Path, fmt: str) -> None:
        import geopandas as gpd

        gdf = gpd.read_file(str(in_path))
        driver = _driver_for_format(fmt)

        # KML should be WGS84
        if fmt == "kml":
            try:
                gdf = gdf.to_crs("EPSG:4326")
            except Exception:
                pass

        # Prefer pyogrio write when present
        if pyogrio is not None:
            try:
                pyogrio.write_dataframe(gdf, str(out_path), driver=driver)
                self.log_q.put("[CONVERT] OK")
                return
            except Exception as e:
                self.log_q.put(f"[CONVERT] pyogrio write failed; falling back to GeoPandas: {e}")

        # GeoPandas fallback
        gdf.to_file(str(out_path), driver=driver)
        self.log_q.put("[CONVERT] OK")

    # ---------------- Data tab ----------------

    def _build_data(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        top = ttk.Frame(parent)
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=12)
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Mode:").grid(row=0, column=0, sticky="w")
        self.data_mode_var = tk.StringVar(value="Import")
        self.data_mode = ttk.Combobox(
            top,
            textvariable=self.data_mode_var,
            state="readonly",
            values=["Import", "Export", "Create FGDB"],
            width=18,
        )
        self.data_mode.grid(row=0, column=1, sticky="w", padx=8)
        self.data_mode.bind("<<ComboboxSelected>>", lambda e: self._data_show_mode())

        ttk.Button(top, text="View tab", command=lambda: self.nb.select(self.tab_view)).grid(
            row=0, column=2, padx=6
        )

        # Stacked frames
        self.data_stack = ttk.Frame(parent)
        self.data_stack.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.data_stack.columnconfigure(0, weight=1)
        self.data_stack.rowconfigure(0, weight=1)

        self.data_import = ttk.Frame(self.data_stack)
        self.data_export = ttk.Frame(self.data_stack)
        self.data_create = ttk.Frame(self.data_stack)

        for f in (self.data_import, self.data_export, self.data_create):
            f.grid(row=0, column=0, sticky="nsew")

        self._build_import(self.data_import)
        self._build_export(self.data_export)
        self._build_create(self.data_create)

        self._data_show_mode()

    def _set_data_mode(self, mode: str) -> None:
        self.data_mode_var.set(mode)
        self._data_show_mode()

    def _data_show_mode(self) -> None:
        mode = (self.data_mode_var.get() or "").strip()
        if mode == "Import":
            self.data_import.tkraise()
        elif mode == "Export":
            self.data_export.tkraise()
        else:
            self.data_create.tkraise()

    # ---------------- Import UI (Data tab) ----------------

    def _build_import(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        out_box = ttk.LabelFrame(parent, text="Output FGDB")
        out_box.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        out_box.columnconfigure(1, weight=1)

        ttk.Label(out_box, text="FGDB (.gdb):").grid(row=0, column=0, sticky="w")
        self.imp_out_gdb_var = tk.StringVar()
        ttk.Entry(out_box, textvariable=self.imp_out_gdb_var).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(out_box, text="Browse", command=self._imp_pick_out_gdb).grid(
            row=0, column=2, padx=6
        )

        mode_row = ttk.Frame(out_box)
        mode_row.grid(row=1, column=1, sticky="w", pady=(6, 0))
        self.imp_mode_var = tk.StringVar(value="append")
        ttk.Radiobutton(
            mode_row, text="Append to existing", value="append", variable=self.imp_mode_var
        ).grid(row=0, column=0, padx=(0, 12))
        ttk.Radiobutton(
            mode_row,
            text="Overwrite (delete/recreate)",
            value="overwrite",
            variable=self.imp_mode_var,
        ).grid(row=0, column=1)

        in_box = ttk.LabelFrame(parent, text="Inputs (files and/or folders)")
        in_box.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        in_box.columnconfigure(0, weight=1)

        btn_row = ttk.Frame(in_box)
        btn_row.grid(row=0, column=0, sticky="w", pady=6)
        ttk.Button(btn_row, text="Add Files...", command=self._imp_add_files).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(btn_row, text="Add Folder...", command=self._imp_add_dir).grid(
            row=0, column=1, padx=6
        )
        ttk.Button(
            btn_row, text="Remove Selected", command=self._imp_remove_selected
        ).grid(row=0, column=2, padx=6)
        ttk.Button(btn_row, text="Clear", command=self._imp_clear).grid(
            row=0, column=3, padx=6
        )

        self.imp_recursive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            in_box, text="Recursive (for folders)", variable=self.imp_recursive_var
        ).grid(row=1, column=0, sticky="w", padx=6)

        list_frame = ttk.Frame(parent)
        list_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.imp_in_list = tk.Listbox(list_frame, selectmode="extended")
        self.imp_in_list.grid(row=0, column=0, sticky="nsew")

        sb = ttk.Scrollbar(list_frame, command=self.imp_in_list.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.imp_in_list.configure(yscrollcommand=sb.set)

        opts = ttk.LabelFrame(parent, text="Import Options")
        opts.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        for i in range(6):
            opts.columnconfigure(i, weight=1)

        ttk.Label(opts, text="EPSG (optional):").grid(
            row=0, column=0, sticky="w", padx=6, pady=4
        )
        self.imp_epsg_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.imp_epsg_var, width=10).grid(
            row=0, column=1, sticky="w", padx=6, pady=4
        )

        ttk.Label(opts, text="If FC exists:").grid(
            row=0, column=2, sticky="w", padx=6, pady=4
        )
        self.imp_ifexists_var = tk.StringVar(value="unique")
        ttk.Combobox(
            opts,
            textvariable=self.imp_ifexists_var,
            values=["unique", "skip", "fail"],
            width=10,
            state="readonly",
        ).grid(row=0, column=3, sticky="w", padx=6, pady=4)

        self.imp_force2d_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Force 2D", variable=self.imp_force2d_var).grid(
            row=0, column=4, sticky="w", padx=6, pady=4
        )

        self.imp_kml_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts, text="KML: import all layers", variable=self.imp_kml_all_var
        ).grid(row=1, column=0, sticky="w", padx=6, pady=4)

        ttk.Label(opts, text="KML layers (comma):").grid(
            row=1, column=2, sticky="w", padx=6, pady=4
        )
        self.imp_kml_layers_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.imp_kml_layers_var).grid(
            row=1, column=3, sticky="ew", padx=6, pady=4
        )

        run_row = ttk.Frame(parent)
        run_row.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(run_row, text="Run Import", command=self._imp_run).pack(side="left")

        self._imp_inputs: List[Path] = []

    def _imp_pick_out_gdb(self) -> None:
        d = filedialog.askdirectory(title="Select or create output .gdb folder")
        if d:
            self.imp_out_gdb_var.set(str(Path(d)))

    def _imp_add_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select input geospatial files", filetypes=FILETYPES_IMPORT
        )
        for p in paths:
            self._imp_inputs.append(Path(p))
        self._imp_refresh_list()

    def _imp_add_dir(self) -> None:
        d = filedialog.askdirectory(title="Select a folder of input geospatial files")
        if d:
            self._imp_inputs.append(Path(d))
            self._imp_refresh_list()

    def _imp_remove_selected(self) -> None:
        sel = list(self.imp_in_list.curselection())
        if not sel:
            return
        sel_set = set(sel)
        self._imp_inputs = [p for i, p in enumerate(self._imp_inputs) if i not in sel_set]
        self._imp_refresh_list()

    def _imp_clear(self) -> None:
        self._imp_inputs = []
        self._imp_refresh_list()

    def _imp_refresh_list(self) -> None:
        self.imp_in_list.delete(0, "end")
        for p in self._imp_inputs:
            self.imp_in_list.insert("end", str(p))

    def _imp_run(self) -> None:
        out_raw = (self.imp_out_gdb_var.get() or "").strip()
        if not out_raw:
            messagebox.showerror("Missing output", "Select an output .gdb folder.")
            return

        out_gdb = Path(out_raw).expanduser()
        if out_gdb.suffix.lower() != ".gdb":
            out_gdb = out_gdb.with_suffix(".gdb")

        if not self._imp_inputs:
            messagebox.showerror("Missing inputs", "Add at least one file or folder.")
            return

        epsg = _safe_int(self.imp_epsg_var.get())
        if self.imp_epsg_var.get().strip() and epsg is None:
            messagebox.showerror("Invalid EPSG", "EPSG must be an integer.")
            return

        mode = self.imp_mode_var.get()
        overwrite_gdb = mode == "overwrite"
        append_gdb = mode == "append"

        kml_layers = [
            x.strip()
            for x in (self.imp_kml_layers_var.get() or "").split(",")
            if x.strip()
        ]

        opts = ImportOptions(
            out_gdb=out_gdb,
            in_dir=None,
            in_paths=list(self._imp_inputs),
            recursive=bool(self.imp_recursive_var.get()),
            overwrite_gdb=overwrite_gdb,
            append_gdb=append_gdb,
            epsg=epsg,
            kml_all_layers=bool(self.imp_kml_all_var.get()),
            kml_layers=kml_layers,
            force_2d=bool(self.imp_force2d_var.get()),
            if_exists=self.imp_ifexists_var.get(),
            debug=True,
        )

        self.log(f"[IMPORT] out_gdb={out_gdb} inputs={len(self._imp_inputs)} mode={mode}")
        self._run_in_thread(self._imp_worker, opts)

    def _imp_worker(self, opts: ImportOptions) -> None:
        require_pyogrio()
        rc = run_import(opts)
        self.log_q.put(f"[IMPORT] finished exit_code={rc}")

    # ---------------- Export UI (Data tab) ----------------

    def _build_export(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        gdb_box = ttk.LabelFrame(parent, text="Source FGDB")
        gdb_box.grid(row=0, column=0, sticky="ew")
        gdb_box.columnconfigure(1, weight=1)

        ttk.Label(gdb_box, text="FGDB (.gdb):").grid(row=0, column=0, sticky="w")
        self.exp_gdb_var = tk.StringVar()
        ttk.Entry(gdb_box, textvariable=self.exp_gdb_var).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(gdb_box, text="Browse", command=self._exp_pick_gdb).grid(
            row=0, column=2, padx=6
        )
        ttk.Button(gdb_box, text="Load Layers", command=self._exp_load_layers).grid(
            row=0, column=3
        )

        sel_box = ttk.LabelFrame(parent, text="Layers (multi-select)")
        sel_box.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        sel_box.columnconfigure(0, weight=1)

        tools = ttk.Frame(sel_box)
        tools.grid(row=0, column=0, sticky="w", pady=6)
        ttk.Button(tools, text="Select All", command=lambda: self._exp_select_all(True)).grid(
            row=0, column=0, padx=6
        )
        ttk.Button(tools, text="Select None", command=lambda: self._exp_select_all(False)).grid(
            row=0, column=1, padx=6
        )

        ttk.Label(tools, text="Pattern (optional):").grid(row=0, column=2, padx=(18, 6))
        self.exp_pattern_var = tk.StringVar()
        ttk.Entry(tools, textvariable=self.exp_pattern_var, width=24).grid(
            row=0, column=3, padx=6
        )
        ttk.Button(tools, text="Apply Pattern", command=self._exp_apply_pattern).grid(
            row=0, column=4, padx=6
        )

        list_frame = ttk.Frame(parent)
        list_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.exp_layer_list = tk.Listbox(list_frame, selectmode="extended")
        self.exp_layer_list.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(list_frame, command=self.exp_layer_list.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.exp_layer_list.configure(yscrollcommand=sb.set)

        out_box = ttk.LabelFrame(parent, text="Export Options")
        out_box.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        for i in range(8):
            out_box.columnconfigure(i, weight=1)

        ttk.Label(out_box, text="Format:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.exp_fmt_var = tk.StringVar(value="geojson")
        ttk.Combobox(
            out_box,
            textvariable=self.exp_fmt_var,
            values=["geojson", "shp", "kml"],
            width=10,
            state="readonly",
        ).grid(row=0, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(out_box, text="EPSG (optional):").grid(row=0, column=2, sticky="w", padx=6, pady=4)
        self.exp_epsg_var = tk.StringVar()
        ttk.Entry(out_box, textvariable=self.exp_epsg_var, width=10).grid(
            row=0, column=3, sticky="w", padx=6, pady=4
        )

        self.exp_overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            out_box, text="Overwrite outputs", variable=self.exp_overwrite_var
        ).grid(row=0, column=4, sticky="w", padx=6, pady=4)

        ttk.Label(out_box, text="Out folder:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.exp_outdir_var = tk.StringVar()
        ttk.Entry(out_box, textvariable=self.exp_outdir_var).grid(
            row=1, column=1, columnspan=3, sticky="ew", padx=6, pady=4
        )
        ttk.Button(out_box, text="Browse", command=self._exp_pick_outdir).grid(
            row=1, column=4, padx=6, pady=4
        )

        run_row = ttk.Frame(parent)
        run_row.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Button(run_row, text="Run Export", command=self._exp_run).pack(side="left")

        self._exp_layers_cache: List[str] = []

    def _exp_pick_gdb(self) -> None:
        d = filedialog.askdirectory(title="Select a .gdb directory")
        if d:
            self.exp_gdb_var.set(d)

    def _exp_load_layers(self) -> None:
        p = Path((self.exp_gdb_var.get() or "").strip()).expanduser()
        if not p or p.suffix.lower() != ".gdb":
            messagebox.showerror("Invalid FGDB", "Select a valid .gdb directory.")
            return
        if pyogrio is None:
            messagebox.showerror("Missing dependency", "pyogrio is required to list FGDB layers.")
            return
        try:
            meta = parse_pyogrio_list_layers(pyogrio.list_layers(str(p)))
            names: List[str] = []
            for rec in meta:
                nm = str(rec.get("name") or "").strip()
                if not nm:
                    continue
                gt = rec.get("geometry_type")
                if gt in (None, "", "None"):
                    continue
                names.append(nm)
            self._exp_layers_cache = names
            self.exp_layer_list.delete(0, "end")
            for n in names:
                self.exp_layer_list.insert("end", n)
            self.log(f"[EXPORT] Loaded {len(names)} spatial layer(s) from {p.name}")
        except Exception as e:
            self.log(f"[EXPORT][ERROR] {p} :: {e}")

    def _exp_apply_pattern(self) -> None:
        pat = (self.exp_pattern_var.get() or "").strip()
        if not pat:
            self.exp_layer_list.delete(0, "end")
            for n in self._exp_layers_cache:
                self.exp_layer_list.insert("end", n)
            return
        import fnmatch

        filt = [n for n in self._exp_layers_cache if fnmatch.fnmatch(n, pat)]
        self.exp_layer_list.delete(0, "end")
        for n in filt:
            self.exp_layer_list.insert("end", n)
        self.log(f"[EXPORT] Pattern '{pat}' matched {len(filt)} layer(s)")

    def _exp_select_all(self, yes: bool) -> None:
        self.exp_layer_list.selection_clear(0, "end")
        if yes:
            self.exp_layer_list.selection_set(0, "end")

    def _exp_pick_outdir(self) -> None:
        d = filedialog.askdirectory(title="Select output folder")
        if d:
            self.exp_outdir_var.set(d)

    def _exp_run(self) -> None:
        gdb = Path((self.exp_gdb_var.get() or "").strip()).expanduser()
        if not gdb or gdb.suffix.lower() != ".gdb":
            messagebox.showerror("Invalid FGDB", "Select a valid .gdb directory.")
            return
        outdir = Path((self.exp_outdir_var.get() or "").strip()).expanduser()
        if not outdir:
            messagebox.showerror("Missing output folder", "Select an output folder.")
            return

        fmt = normalize_format(self.exp_fmt_var.get())
        epsg = _safe_int(self.exp_epsg_var.get())
        if self.exp_epsg_var.get().strip() and epsg is None:
            messagebox.showerror("Invalid EPSG", "EPSG must be an integer.")
            return

        sel_idx = list(self.exp_layer_list.curselection())
        layers = [self.exp_layer_list.get(i) for i in sel_idx] if sel_idx else []
        pat = (self.exp_pattern_var.get() or "").strip() or None

        opts = ExportOptions(
            gdb_path=gdb,
            out_dir=outdir,
            fmt=fmt,
            epsg=epsg,
            overwrite=bool(self.exp_overwrite_var.get()),
            layers=layers,
            pattern=pat if not layers else None,
            debug=True,
        )

        self.log(
            f"[EXPORT] gdb={gdb} out={outdir} fmt={fmt} layers={len(layers)} pattern={pat or ''}"
        )
        self._run_in_thread(self._exp_worker, opts)

    def _exp_worker(self, opts: ExportOptions) -> None:
        require_pyogrio()
        rc = run_export(opts)
        self.log_q.put(f"[EXPORT] finished exit_code={rc}")

    # ---------------- Create FGDB UI (Data tab) ----------------

    def _build_create(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)

        box = ttk.LabelFrame(parent, text="Create a new FGDB")
        box.grid(row=0, column=0, sticky="ew")
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="New FGDB (.gdb):").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.new_gdb_var = tk.StringVar()
        ttk.Entry(box, textvariable=self.new_gdb_var).grid(row=0, column=1, sticky="ew", padx=6, pady=6)
        ttk.Button(box, text="Browse", command=self._create_pick_path).grid(row=0, column=2, padx=6, pady=6)

        ttk.Label(box, text="Placeholder layer:").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        self.new_layer_var = tk.StringVar(value="__init__")
        ttk.Entry(box, textvariable=self.new_layer_var, width=20).grid(row=1, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(box, text="EPSG:").grid(row=1, column=2, sticky="w", padx=6, pady=6)
        self.new_epsg_var = tk.StringVar(value="4326")
        ttk.Entry(box, textvariable=self.new_epsg_var, width=10).grid(row=1, column=3, sticky="w", padx=6, pady=6)

        ttk.Button(box, text="Create FGDB", command=self._create_run).grid(row=2, column=0, padx=6, pady=10, sticky="w")

        note = (
            "Creates a FGDB by writing a placeholder feature class. "
            "If you want a truly empty FGDB, delete the placeholder in ArcGIS Pro."
        )
        ttk.Label(parent, text=note, justify="left").grid(row=1, column=0, sticky="w", pady=(10, 0))

    def _create_pick_path(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Choose FGDB path (ends with .gdb)",
            defaultextension=".gdb",
            filetypes=[("File Geodatabase", "*.gdb"), ("All files", "*.*")],
        )
        if p:
            self.new_gdb_var.set(p)

    def _create_run(self) -> None:
        p = Path((self.new_gdb_var.get() or "").strip()).expanduser()
        if not p:
            messagebox.showerror("Missing path", "Choose a .gdb path to create.")
            return
        if p.suffix.lower() != ".gdb":
            p = p.with_suffix(".gdb")

        layer = (self.new_layer_var.get() or "").strip() or "__init__"
        epsg = _safe_int(self.new_epsg_var.get())
        if epsg is None:
            messagebox.showerror("Invalid EPSG", "EPSG must be an integer.")
            return

        self.log(f"[CREATE] creating {p} (placeholder '{layer}', EPSG:{epsg})")
        self._run_in_thread(self._create_worker, p, layer, epsg)

    def _create_worker(self, p: Path, layer: str, epsg: int) -> None:
        require_pyogrio()
        import geopandas as gpd
        import pandas as pd
        from shapely.geometry import Point

        p.parent.mkdir(parents=True, exist_ok=True)

        gdf0 = gpd.GeoDataFrame(
            {"_placeholder": pd.Series([], dtype="int64")},
            geometry=gpd.GeoSeries([], crs=f"EPSG:{epsg}"),
        )
        try:
            pyogrio.write_dataframe(gdf0, str(p), layer=layer, driver="OpenFileGDB", append=False)
            self.log_q.put("[CREATE] OK (0-row placeholder layer created)")
            return
        except Exception as e0:
            self.log_q.put(f"[CREATE] 0-row create failed; falling back to 1-row placeholder: {e0}")

        gdf1 = gpd.GeoDataFrame(
            {"_placeholder": [1]},
            geometry=[Point(0, 0)],
            crs=f"EPSG:{epsg}",
        )
        pyogrio.write_dataframe(gdf1, str(p), layer=layer, driver="OpenFileGDB", append=False)
        self.log_q.put("[CREATE] OK (1-row placeholder layer created)")


def main() -> int:
    root = tk.Tk()
    app = FGDBToolsApp(root)
    app.pack(fill="both", expand=True)
    root.mainloop()
    return 0
