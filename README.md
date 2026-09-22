# IL2CPP GAME DATA & OFFSET ANALYZER

A browser-based reverse-engineering **analysis and research dashboard** for IL2CPP applications that you own or are authorized to inspect.

The tool provides automated ingestion of IL2CPP metadata dumps and native shared libraries, reconstructs classes and hierarchies, discovers verified address information (field offsets, method RVAs, virtual addresses, file offsets, and static data), scores potential gameplay-relevant elements with transparent heuristic scoring, and generates searchable dossiers and reports.

> **IMPORTANT SECURITY & RESEARCH NOTICE**  
> This tool is an **analysis-only application**. It does **NOT** provide anti-cheat bypasses, binary patching, code injection, exploit generation, DRM circumvention, or licensing manipulation. Offsets, RVAs, and class definitions are strictly extracted from supplied files and are never fabricated.

---

## 1. Features

- **Strict Address Separation**:
  - `FIELD_OFFSET`: Byte displacement from instance object pointer in memory (e.g. `+0x120`).
  - `METHOD_RVA`: Relative Virtual Address from preferred ImageBase.
  - `VIRTUAL_ADDRESS`: Runtime virtual memory address (`ImageBase + RVA`).
  - `FILE_OFFSET`: Physical disk byte offset within ELF / PE binary.
  - `STATIC_ADDRESS`: Data section memory pointer for static class fields.
- **Automated Platform & Architecture Detection**:
  - Android (`libil2cpp.so`) & Windows (`GameAssembly.dll`).
  - ARM64, ARMv7, x86, and x64 machine ABIs.
  - Metadata versions (v16 to v31).
- **Multi-Format Ingestion**:
  - `dump.cs` (Il2CppDumper text dumps).
  - `global-metadata.dat` (binary metadata tables).
  - Native binaries (`libil2cpp.so` ELF & `GameAssembly.dll` PE).
  - `ZIP` & `APK` archives with automated path discovery.
  - JSON / CSV schema dumps.
- **Smart Semantic Scoring**:
  - 0–100 heuristic scores across 24 analytical categories (`HEALTH`, `DAMAGE`, `COMBAT`, `CURRENCY`, etc.).
  - False-positive reduction (`HealthBar` UI element vs `currentHealth` state field).
  - Independent confidence engine (`HIGH`, `MEDIUM`, `LOW`).
- **Modern Responsive Dark Theme**:
  - Optimized for desktop and mobile (Android browsers).
  - Dedicated **Offset Center** with real-time category filtering.
  - Interactive Canvas force-directed **Relationship Graph**.
  - Read-only C# **Dump Viewer** with syntax highlighting.
  - **Build Comparison** (diff changes between two versions).
- **Export & Reports**:
  - `ImportantData.md` & `ImportantOffsets.md`.
  - `offsets.json` & `field_offsets.csv`.
  - `method_rvas.csv` & `static_data.csv`.
  - RESTful JSON API endpoints.

---

## 2. Technology Stack

- Python 3.11+
- Django (Web framework)
- SQLite (Development) / PostgreSQL-ready models
- HTML5, CSS3, JavaScript
- Bootstrap 5 & Chart.js

---

## 3. Installation & Quick Start

### 1. Clone or Open Project
```bash
cd d:/project/fc/il2cpp_analyzer
```

### 2. Set Up Python Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux / macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Migrations
```bash
python manage.py makemigrations analyzer
python manage.py migrate
```

### 5. Create Superuser (Admin Access)
```bash
python manage.py createsuperuser
```

### 6. Load Synthetic Reference Project (Synthetic Test Data)
```bash
python manage.py load_sample_data
```

### 7. Start Local Development Server
```bash
python manage.py runserver 127.0.0.1:8000
```
Open your browser and navigate to: **`http://127.0.0.1:8000`**

---

## 4. Command-Line Interface (CLI)

In addition to the web dashboard, you can execute analysis jobs directly from the CLI:

### Analyze a Dump or Binary
```bash
python manage.py analyze_dump /path/to/dump.cs --name="MyGame_v1.0"
```

### Recalculate Heuristic Scores
```bash
python manage.py rebuild_scores <PROJECT_ID>
```

### Export Reports to Directory
```bash
python manage.py export_project <PROJECT_ID> --outdir=./exports
```

### Run Full Test Suite
```bash
python manage.py test analyzer.tests --verbosity=2
```

---

## 5. Understanding Memory Addresses & Offsets

This application strictly differentiates address representations:

```
[ Object Instance Pointer (Heap) ]
   ├── +0x00: Il2CppObject header (vtable, monitor)
   └── +0x120: currentHealth (FIELD OFFSET = 0x120)

[ Native Executable Binary ]
   ├── Preferred Image Base: 0x00000000 (ELF) or 0x180000000 (PE)
   ├── Relative Virtual Address: 0x004A81F0 (METHOD RVA)
   ├── Virtual Address (VA): ImageBase + RVA = 0x1804A81F0
   └── File Offset: Byte position on disk = 0x002A81F0 (FILE OFFSET)
```

- **Field Offset**: The byte distance from the start of an instantiated class instance in the heap to the variable's value. It is **never** a code address.
- **Method RVA**: The Relative Virtual Address of the native compiled function code relative to the base address of the module.
- **Virtual Address (VA)**: The runtime virtual memory location where the method code resides when mapped by the OS loader.
- **File Offset**: The raw byte index of the method's machine code inside the file stored on disk.
- **Static Address**: The absolute memory address of global static variables, residing in `.bss` or `.data` sections.

---

## 6. Heuristic Scoring & Confidence

Every class, field, and method is assigned a score from **0 to 100** based on transparent factors:

| Factor | Weight | Description |
|---|---|---|
| **Keyword Match** | `+25` | Exact match with category vocabulary (e.g. `health`, `attack`, `gold`). |
| **Primitive Type** | `+20` | Numeric or boolean types (`float`, `int32`, `double`, `bool`). |
| **Class Relevance** | `+18` | Declared within a high-scoring class context (e.g. `PlayerStats`). |
| **Sibling Context** | `+15` | Co-located with counterpart fields (e.g. `maxHealth` next to `currentHealth`). |
| **Namespace Hint** | `+10` | Declared in a gameplay-related namespace (e.g. `Game.Combat`). |
| **False-Positive Penalty** | `-30` | Negative penalty for UI, VFX, audio, animation, or rendering context (`HealthBar`, `AttackVFX`). |

Scores are accompanied by an independent **Confidence Rating**:
- **HIGH**: Semantic match verified with concrete structural offsets/RVAs in a state/data context.
- **MEDIUM**: Strong semantic match but offset is unresolved or structural proof is partial.
- **LOW**: Substring or weak match with insufficient evidence.

---

## 7. RESTful JSON API

JSON endpoints are available for programmatic inspection:

- `GET /api/projects/` &mdash; List all projects.
- `GET /api/projects/<id>/` &mdash; Project metadata and summary stats.
- `GET /api/classes/?project_id=<id>` &mdash; Filtered class definitions.
- `GET /api/classes/<id>/` &mdash; Detailed class members.
- `GET /api/fields/?project_id=<id>` &mdash; Discovered fields and offsets.
- `GET /api/methods/?project_id=<id>` &mdash; Discovered methods and RVAs.
- `GET /api/offsets/?project_id=<id>&type=FIELD_OFFSET` &mdash; Normalized address records.
- `GET /api/search/?q=health` &mdash; Multi-table global search results.
- `GET /api/graph/?project_id=<id>` &mdash; Node-edge graph layout.

---

## 8. Limitations & Guidelines

1. **Stripped Binaries**: When native binaries are completely stripped of symbol tables and metadata token tables are obfuscated, RVAs without code registration pointers cannot be verified and are labeled `UNRESOLVED`.
2. **Analysis Candidates**: Heuristic classifications identify candidate game mechanics based on naming conventions and types; they do not constitute mathematical proof of in-game effect.
3. **Authorized Use Only**: Ensure you have authorization to inspect any dumps or binaries loaded into this application.
