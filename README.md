##HEAVILY VIBE CODED
# fgdb-tools

Two CLI tools:

- `fgdb-import`: import one or more vector datasets into an Esri File Geodatabase (`.gdb`) as feature classes.
- `fgdb-export`: export one or more FileGDB feature classes (layers) to GeoJSON, Shapefile, or KML.

Supported file types:

- **Import**: GeoJSON (`.geojson` / `.json`), Shapefile (`.shp`), KML (`.kml`)
- **Export**: GeoJSON, Shapefile, KML (one output file per layer)

## Install (editable)

```bash
python -m pip install -e .
```

## Usage

### Import (single file)

```bash
fgdb-import --out-gdb "X:\path\out.gdb" --in-path "X:\data\roads.shp"
```

### Import (multiple files)

```bash
fgdb-import --out-gdb "X:\path\out.gdb" --in-path "X:\data\roads.shp" --in-path "X:\data\lakes.geojson"
```

### Import (directory bulk)

```bash
fgdb-import --out-gdb "X:\path\out.gdb" --in-dir "X:\data\vectors" --recursive
```

### Import (KML layer selection)

```bash
# import only specific KML layers
fgdb-import --out-gdb "X:\path\out.gdb" --in-path "X:\data\my.kml" --kml-layer "Parcels" --kml-layer "Roads"

# import all KML layers
fgdb-import --out-gdb "X:\path\out.gdb" --in-path "X:\data\my.kml" --kml-all-layers
```

### Export (all layers to GeoJSON)

```bash
fgdb-export --gdb "X:\path\out.gdb" --out-dir "X:\exports" --format geojson
```

### Export (one layer)

```bash
fgdb-export --gdb "X:\path\out.gdb" --out-dir "X:\exports" --format shp --layer "roads"
```

### Export (multiple layers)

```bash
fgdb-export --gdb "X:\path\out.gdb" --out-dir "X:\exports" --format kml --layer "roads" --layer "lakes"
```

### Export (pattern filter)

```bash
fgdb-export --gdb "X:\path\out.gdb" --out-dir "X:\exports" --format geojson --pattern "*Road*"
```

### List layers (optionally filtered)

```bash
fgdb-export --gdb "X:\path\out.gdb" --out-dir "." --names-only
fgdb-export --gdb "X:\path\out.gdb" --out-dir "." --names-only --pattern "*Road*"
```

## Notes / limitations

- These tools use **pyogrio** (GDAL) for reading/writing.
- Creating a FileGDB requires `OpenFileGDB` **write** support.
- Some GDAL builds do **not** support writing KML; if so, `fgdb-export --format kml` will raise an error.
- Updating/replacing an existing feature class inside a `.gdb` is not implemented here (pyogrio can *create* FCs, but deletion/replace semantics are backend-dependent). Current behavior is controlled by `--if-exists`:
  - `unique` (default): write a new feature class name with suffixes
  - `skip`: skip if the feature class already exists
  - `fail`: stop with an error if it already exists


## GUI

Install editable and run:

```bash
python -m pip install -e .
fgdb-gui
```

Or:

```bash
python -m fgdb_tools
```

GUI layout:
- **Home**: command log + action selector
- **View**: file-system browser with FGDB expand (layers) and right-click export/import actions
- **Data**: Import / Export / Create FGDB tools in one tab (mode selector at top)
