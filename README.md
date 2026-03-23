# Static Analysis Android-Malware-Detection (AMD)

Web demo + notebooks for static Android malware detection with two independent pipelines:

- `Drebin v1` (binary: Benign/Malware)
- `CIC-MalDroid 2020 Static` (multiclass family classification)

## 1) Project Layout

- `webapp/` Flask app and UI
- `src/feature_extraction/` lightweight APK static extractors
- `models/` trained artifacts grouped by dataset + algorithm
- `datasets/` Drebin + MalDroid2020 source files used in experiments
- `notebooks/` experiment notebooks used in the thesis workflow
- `scripts/load_models.py` refresh artifacts from `../exp-maldroid2020`

## 2) Quick Start

### Create environment

```bash
uv venv .venv
.venv\Scripts\activate
uv pip install -r requirements.txt
```

### Run web app

```bash
python run_webapp.py
```

Open: `http://localhost:5001`

### Logging (terminal)

Logs go to **stdout**. Tune verbosity with:

- `AMD_LOG_LEVEL` — root / app (`INFO`, `DEBUG`, …). Default: `INFO`.
- `AMD_ANDROGUARD_LOG_LEVEL` — androguard internals. Default: `INFO` (use `WARNING` for less noise, `DEBUG` for full trace).

> **Note:** Androguard 4 logs internally via **Loguru** (not stdlib `logging`). The app reconfigures Loguru on startup to redirect those logs to `stdout` with the same timestamp format. You will see lines like:
> ```
> 2026-03-24 01:12:48 | INFO | androguard.core.apk:_apk_analysis:415 - APK file was successfully validated!
> ```
> when an APK is analyzed.

Example (PowerShell):

```powershell
$env:AMD_LOG_LEVEL="DEBUG"; $env:AMD_ANDROGUARD_LOG_LEVEL="DEBUG"; python run_webapp.py
```

**Analyze / APK lâu:** Dòng access log của Werkzeug (`POST /api/analyze …`) chỉ xuất hiện **khi request xong**. Trong lúc xử lý, xem log `static-analysis-amd`: có dòng `>>> POST /api/analyze` ngay khi bấm Analyze, rồi từng bước `[req_id] Step: …` (đã flush ra terminal).

### Caching & Performance

The web app uses **smart caching** to dramatically improve performance:

**Cache System:**
- **Bundle Cache (LRU + mtime)**: Caches models, scalers, features per dataset/algorithm. Auto-invalidates if files change.
- **Registry Cache (TTL-based)**: Caches model registry for 5 minutes (configurable).
- **~95% performance improvement**: First request takes normal time; subsequent requests are 95%+ faster.

**Environment Variables:**
- `AMD_CACHE_ENABLED` — Enable/disable cache. Default: `true`
- `AMD_CACHE_MAX_BUNDLES` — Max models in LRU cache. Default: `10`
- `AMD_CACHE_TTL_SECONDS` — Registry cache time-to-live. Default: `300` (5 min)
- `AMD_CACHE_WARMUP` — Warm up cache on startup. Default: `false`

Example (PowerShell):

```powershell
# Enable debugging + disable cache
$env:AMD_LOG_LEVEL="DEBUG"; $env:AMD_CACHE_ENABLED="false"; python run_webapp.py

# Enable warmup for faster first request
$env:AMD_CACHE_WARMUP="true"; python run_webapp.py
```

**Monitor Cache Performance:**
- GET `/api/cache/stats` — View cache hit ratios, bundle count, TTL status
- POST `/api/cache/clear` — Clear all caches (admin endpoint)

Example:
```bash
curl http://localhost:5001/api/cache/stats | python -m json.tool
```

Expected output includes cache statistics in analyze response (`cache_info` field).

## 3) Web App Flow

1. Choose dataset (`drebin` or `maldroid2020`)
2. Choose model (`rf`, `svm`, `knn`, `nb`, `mlp`, `xgb`)
3. Upload APK
4. App runs:
   - static info extraction (`ApkAnalyzer.py`)
   - token extraction (`FeatureExtraction.py`)
   - map APK tokens into the full pre-scaler feature space
   - apply the saved scaler from training
   - reduce to the final selected feature space used by the model
   - model prediction and probability output

## 4) Refresh Model Artifacts

If you retrain notebooks in `../exp-maldroid2020`, run:

```bash
python scripts/load_models.py
```

This copies latest artifacts into this repo's `models/` structure.

## 5) Notes

- This repo uses two separate model spaces by design (no unified schema).
- Web app is for dashboard/inference/reporting only, not for training.
- Training logic remains in notebooks for reproducibility and security.

