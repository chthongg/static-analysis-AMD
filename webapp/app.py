import csv
import hashlib
import json
import logging
import os
import pickle
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from difflib import SequenceMatcher
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Loguru must be configured BEFORE importing Androguard (pulls loguru at import time).


def _parse_log_level(env_name: str, default: int) -> int:
    raw = os.environ.get(env_name, "").strip().upper()
    if not raw:
        return default
    return getattr(logging, raw, default)


def _configure_logging() -> logging.Logger:
    """
    Configure stdlib logging + Loguru (Androguard 4 uses Loguru only).

    Import order: call this before `from androguard...` / feature modules that import APK.
    Uses sys.__stdout__ with explicit flush so IDE / Flask threaded server still shows lines.
    """
    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    root_level = _parse_log_level("AMD_LOG_LEVEL", logging.INFO)
    ag_level_int = _parse_log_level("AMD_ANDROGUARD_LOG_LEVEL", logging.INFO)

    kwargs = dict(level=root_level, format=fmt, datefmt=datefmt, stream=sys.__stdout__)
    try:
        logging.basicConfig(**kwargs, force=True)
    except TypeError:
        if not logging.root.handlers:
            logging.basicConfig(**kwargs)

    logging.getLogger("werkzeug").setLevel(logging.INFO)

    log = logging.getLogger("static-analysis-amd")
    log.setLevel(root_level)
    log.handlers.clear()
    log.propagate = True

    _level_map = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARNING",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "CRITICAL",
    }
    loguru_level = _level_map.get(ag_level_int, "INFO")

    try:
        from loguru import logger as _loguru_logger

        _loguru_logger.remove()

        _log_fmt = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} - {message}\n"

        def _loguru_sink(message):
            try:
                sys.__stdout__.write(str(message))
                sys.__stdout__.flush()
            except Exception:
                pass

        _loguru_logger.add(
            _loguru_sink,
            level=loguru_level,
            format=_log_fmt,
            colorize=False,
            enqueue=False,
        )
    except Exception as _e:
        log.warning("Loguru not available; Androguard internal logs may not appear: %s", _e)

    return log


logger = _configure_logging()

import joblib
import numpy as np
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from src.feature_extraction.ApkAnalyzer import extract_apk_info
from src.feature_extraction.FeatureExtraction import extract_apk_strings
from webapp.cache_manager import CacheManager

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
# Keep template updates visible even when debug=False.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True


def _flush_logs() -> None:
    """Force handlers + stdout to flush so long-running /api/analyze steps show in the IDE terminal."""
    try:
        for handler in logging.root.handlers:
            if hasattr(handler, "flush"):
                handler.flush()
        sys.__stdout__.flush()
        sys.__stderr__.flush()
    except Exception:
        pass


# Initialize cache manager
_cache_enabled = os.environ.get("AMD_CACHE_ENABLED", "true").lower() in ("true", "1", "yes")
_cache_max_bundles = int(os.environ.get("AMD_CACHE_MAX_BUNDLES", "10"))
_cache_registry_ttl = int(os.environ.get("AMD_CACHE_TTL_SECONDS", "300"))

cache_manager = CacheManager(
    max_bundles=_cache_max_bundles,
    registry_ttl_seconds=_cache_registry_ttl,
    enabled=_cache_enabled,
)

logger.info(
    f"Cache system initialized: enabled={_cache_enabled}, "
    f"max_bundles={_cache_max_bundles}, registry_ttl={_cache_registry_ttl}s"
)

_apk_cache_max_entries = int(os.environ.get("AMD_APK_CACHE_MAX", "8"))
_apk_cache_lock = threading.RLock()
_apk_cache: OrderedDict[str, dict] = OrderedDict()
_apk_cache_stats = {"hits": 0, "misses": 0, "evictions": 0}
_analyze_session_max_entries = int(os.environ.get("AMD_ANALYZE_SESSION_MAX", "12"))
_analyze_session_ttl_seconds = int(os.environ.get("AMD_ANALYZE_SESSION_TTL_SECONDS", "7200"))
_analyze_session_lock = threading.RLock()
_analyze_sessions: OrderedDict[str, dict] = OrderedDict()
_analyze_session_stats = {
    "created": 0,
    "reused": 0,
    "expired": 0,
    "evictions": 0,
    "misses": 0,
}


def _hash_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _apk_cache_get(apk_sha256: str):
    with _apk_cache_lock:
        item = _apk_cache.get(apk_sha256)
        if item is None:
            _apk_cache_stats["misses"] += 1
            return None
        _apk_cache.move_to_end(apk_sha256)
        _apk_cache_stats["hits"] += 1
        return item


def _apk_cache_set(apk_sha256: str, static_info: dict, extracted_strings: list[str]) -> None:
    with _apk_cache_lock:
        _apk_cache[apk_sha256] = {
            "static_info": static_info,
            "extracted_strings": extracted_strings,
            "updated_at": time.time(),
        }
        _apk_cache.move_to_end(apk_sha256)
        while len(_apk_cache) > _apk_cache_max_entries:
            _apk_cache.popitem(last=False)
            _apk_cache_stats["evictions"] += 1


def _apk_cache_clear() -> None:
    with _apk_cache_lock:
        _apk_cache.clear()


def _apk_cache_get_stats() -> dict:
    with _apk_cache_lock:
        total = _apk_cache_stats["hits"] + _apk_cache_stats["misses"]
        hit_ratio = (_apk_cache_stats["hits"] / total * 100) if total > 0 else 0.0
        return {
            "hits": _apk_cache_stats["hits"],
            "misses": _apk_cache_stats["misses"],
            "evictions": _apk_cache_stats["evictions"],
            "hit_ratio_pct": round(hit_ratio, 1),
            "cached_apks": len(_apk_cache),
            "max_cached_apks": _apk_cache_max_entries,
        }


def _cleanup_session_file(path: str) -> None:
    try:
        if os.path.exists(path):
            os.unlink(path)
    except Exception:
        pass


def _prune_analyze_sessions(now: float | None = None) -> None:
    now = time.time() if now is None else now
    expired_ids = []
    for sid, item in list(_analyze_sessions.items()):
        age = now - float(item.get("last_used_at", item.get("created_at", now)))
        if age > _analyze_session_ttl_seconds:
            expired_ids.append(sid)
    for sid in expired_ids:
        item = _analyze_sessions.pop(sid, None)
        if item:
            _cleanup_session_file(item.get("tmp_path", ""))
            _analyze_session_stats["expired"] += 1

    while len(_analyze_sessions) > _analyze_session_max_entries:
        sid, item = _analyze_sessions.popitem(last=False)
        _cleanup_session_file(item.get("tmp_path", ""))
        _analyze_session_stats["evictions"] += 1
        logger.info("Analyze session evicted: %s", sid)


def _create_analyze_session(tmp_path: str, uploaded_filename: str, apk_sha256: str) -> str:
    with _analyze_session_lock:
        _prune_analyze_sessions()
        sid = uuid4().hex[:16]
        now = time.time()
        _analyze_sessions[sid] = {
            "tmp_path": tmp_path,
            "uploaded_filename": uploaded_filename,
            "apk_sha256": apk_sha256,
            "created_at": now,
            "last_used_at": now,
        }
        _analyze_sessions.move_to_end(sid)
        _analyze_session_stats["created"] += 1
        return sid


def _analyze_session_get(session_id: str) -> dict | None:
    with _analyze_session_lock:
        _prune_analyze_sessions()
        item = _analyze_sessions.get(session_id)
        if not item:
            _analyze_session_stats["misses"] += 1
            return None
        tmp_path = item.get("tmp_path", "")
        if not tmp_path or not os.path.exists(tmp_path):
            _analyze_sessions.pop(session_id, None)
            _analyze_session_stats["misses"] += 1
            return None
        item["last_used_at"] = time.time()
        _analyze_sessions.move_to_end(session_id)
        _analyze_session_stats["reused"] += 1
        return item


def _analyze_sessions_clear() -> None:
    with _analyze_session_lock:
        for item in list(_analyze_sessions.values()):
            _cleanup_session_file(item.get("tmp_path", ""))
        _analyze_sessions.clear()


def _analyze_session_get_stats() -> dict:
    with _analyze_session_lock:
        _prune_analyze_sessions()
        return {
            "created": _analyze_session_stats["created"],
            "reused": _analyze_session_stats["reused"],
            "misses": _analyze_session_stats["misses"],
            "expired": _analyze_session_stats["expired"],
            "evictions": _analyze_session_stats["evictions"],
            "active_sessions": len(_analyze_sessions),
            "max_sessions": _analyze_session_max_entries,
            "ttl_seconds": _analyze_session_ttl_seconds,
        }

DATASETS = {
    "drebin": {
        "label": "Drebin v1 (15036 APKs)",
        "task": "binary (Benign/Malware)",
        "models_dir": ROOT / "models" / "drebin",
        "dataset_dir": ROOT / "datasets",
        "dataset_files": [
            "Drebin_v1.csv",
            "Dataset-features-categories.csv",
        ],
        "algorithms": {
            "rf": "Random Forest",
            "svm": "SVM (Linear)",
            "knn": "k-NN",
            "nb": "Naive Bayes",
            "mlp": "MLP (Neural Net)",
            "xgb": "XGBoost",
        },
    },
    "maldroid2020": {
        "label": "CIC-MalDroid 2020 Static (11598 APKs)",
        "task": "multiclass (Adware, Banking, SMS, Riskware, Benign)",
        "models_dir": ROOT / "models" / "maldroid2020",
        "dataset_dir": ROOT / "datasets" / "maldroid2020",
        "dataset_files": [
            "feature_vectors_static.csv",
            "feature_vectors_static.parquet",
            "feature_vectors_syscalls_frequency_5_Cat.csv",
        ],
        "algorithms": {
            "rf": "Random Forest",
            "svm": "SVM (Linear)",
            "knn": "k-NN",
            "nb": "Naive Bayes",
            "mlp": "MLP (Neural Net)",
            "xgb": "XGBoost",
        },
    },
}


def _safe_float(v):
    try:
        return float(v)
    except Exception:
        return None


def _load_json(path: Path, default=None):
    if not path.exists():
        return {} if default is None else default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_artifact(path: Path):
    """
    Load artifact saved by either pickle.dump(...) or joblib.dump(...).
    Some pipeline artifacts (e.g. MalDroid label_encoder.pkl) are joblib files
    despite the .pkl extension.
    """
    try:
        with path.open("rb") as f:
            return pickle.load(f)
    except Exception:
        return joblib.load(path)


def _reverse_algorithms(dataset_key: str) -> dict:
    return {v: k for k, v in DATASETS[dataset_key]["algorithms"].items()}


def _load_metrics_from_csv(dataset_key: str) -> dict:
    ds_dir = DATASETS[dataset_key]["models_dir"]
    csv_path = ds_dir / "model_comparison.csv"
    if not csv_path.exists():
        return {}

    reverse_map = _reverse_algorithms(dataset_key)
    metrics = {}
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            algo_label = row.get("") or next(iter(row.values()), "")
            algo_key = reverse_map.get(algo_label)
            if not algo_key:
                continue
            metrics[algo_key] = {
                "algorithm": algo_label,
                "accuracy": _safe_float(row.get("accuracy")),
                "precision_weighted": _safe_float(row.get("precision")),
                "recall_weighted": _safe_float(row.get("recall")),
                "f1_weighted": _safe_float(row.get("f1")),
                "mcc": _safe_float(row.get("mcc")),
                "roc_auc": _safe_float(row.get("roc_auc")),
                "train_time_s": _safe_float(row.get("train_time_s")),
            }
    return metrics


def _dataset_file_info(dataset_key: str) -> list[dict]:
    ds = DATASETS[dataset_key]
    out = []
    for name in ds["dataset_files"]:
        path = ds["dataset_dir"] / name
        out.append(
            {
                "name": name,
                "exists": path.exists(),
                "size_mb": round(path.stat().st_size / 1024 / 1024, 2) if path.exists() else None,
            }
        )
    return out


def _load_model_registry():
    """
    Load model registry with smart caching.
    
    Cache strategy:
    - Check registry cache (TTL-based)
    - If valid and not expired, return cached registry
    - Otherwise rebuild from disk and cache
    """
    if cache_manager.enabled:
        cached = cache_manager.registry_cache.get()
        if cached is not None:
            logger.debug("Registry cache hit")
            return cached
    
    # Cache miss or disabled — rebuild from disk
    logger.debug("Building model registry from disk")
    t_build_start = time.perf_counter()
    
    registry = {}
    for ds_key, ds in DATASETS.items():
        ds_dir = ds["models_dir"]
        shared = ds_dir / "shared"
        summary = _load_json(ds_dir / "pipeline_summary.json", {})
        meta = _load_json(ds_dir / "meta.json", {})
        csv_metrics = _load_metrics_from_csv(ds_key)

        dataset_item = {
            "dataset_key": ds_key,
            "label": ds["label"],
            "task": ds["task"],
            "best_model": summary.get("best_model") or meta.get("best_model"),
            "n_features_selected": summary.get("n_features_selected"),
            "n_features_total": summary.get("n_features_total") or summary.get("n_features_original"),
            "label_classes": summary.get("label_classes", []),
            "algorithms": [],
            "ready": False,
            "dataset_files": _dataset_file_info(ds_key),
        }

        shared_paths_ok = all(
            (shared / name).exists()
            for name in ["features.pkl", "scaler.pkl", "label_encoder.pkl"]
        )

        for algo_key, algo_label in ds["algorithms"].items():
            model_path = ds_dir / algo_key / "model.pkl"
            metrics_path = ds_dir / algo_key / "metrics.json"
            metrics = _load_json(metrics_path, {}) if metrics_path.exists() else csv_metrics.get(algo_key, {})
            model_ok = model_path.exists()
            if model_ok and shared_paths_ok:
                dataset_item["ready"] = True

            dataset_item["algorithms"].append(
                {
                    "key": algo_key,
                    "label": algo_label,
                    "ready": model_ok,
                    "metrics": metrics,
                }
            )

        registry[ds_key] = dataset_item
    
    # Store in cache if enabled
    if cache_manager.enabled:
        cache_manager.registry_cache.set(registry)
    
    build_time_ms = (time.perf_counter() - t_build_start) * 1000
    logger.debug(f"Model registry built in {build_time_ms:.1f}ms")
    
    return registry


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100


def _is_match(feature: str, extracted: str) -> bool:
    fl = feature.lower()
    el = extracted.lower()
    if fl == el:
        return True
    if fl in el or el in fl:
        return True
    return _similarity(fl, el) >= 70


def _load_runtime_bundle(dataset_key: str, algo_key: str):
    """
    Load runtime bundle (scaler, models, features) with smart caching.
    
    Cache strategy:
    - Check bundle cache keyed by (dataset_key, algo_key)
    - If valid (files not modified), return cached bundle
    - Otherwise load from disk and cache
    - Precompute feat_to_idx and sel_indices for optimization
    """
    ds = DATASETS[dataset_key]
    ds_dir = ds["models_dir"]
    cache_key = (dataset_key, algo_key)
    
    # Try cache first if enabled
    if cache_manager.enabled:
        cached = cache_manager.bundle_cache.get(cache_key, ds_dir, dataset_key)
        if cached is not None:
            return cached
    
    # Cache miss or disabled — load from disk
    shared_dir = ds_dir / "shared"
    model_path = ds_dir / algo_key / "model.pkl"
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    logger.debug(f"Loading bundle from disk: {cache_key}")
    t_load_start = time.perf_counter()
    
    selected_features = _load_artifact(shared_dir / "features.pkl")
    label_encoder = _load_artifact(shared_dir / "label_encoder.pkl")
    scaler = joblib.load(shared_dir / "scaler.pkl")
    clf = joblib.load(model_path)

    # Important: scaler was fit on the full feature space before final selection.
    if dataset_key == "maldroid2020":
        base_feature_path = shared_dir / "feature_names_after_drop.pkl"
    else:
        base_feature_path = shared_dir / "base_features.pkl"
    base_features = _load_artifact(base_feature_path)
    
    # Precompute indices for optimization in _apk_to_vector
    feat_to_idx = {f: i for i, f in enumerate(base_features)}
    sel_indices = [feat_to_idx[f] for f in selected_features if f in feat_to_idx]

    bundle = {
        "clf": clf,
        "selected_features": selected_features,
        "base_features": base_features,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "feat_to_idx": feat_to_idx,
        "sel_indices": sel_indices,
    }
    
    # Store in cache if enabled
    if cache_manager.enabled:
        cache_manager.bundle_cache.set(cache_key, bundle, ds_dir, dataset_key)
    
    load_time_ms = (time.perf_counter() - t_load_start) * 1000
    logger.debug(f"Bundle loaded in {load_time_ms:.1f}ms: {cache_key}")
    
    return bundle


def _apk_to_vector(extracted_strings: list[str], base_features: list, scaler, selected_features: list, 
                   feat_to_idx: dict = None, sel_indices: list = None):
    """
    Convert extracted APK strings to feature vector.
    
    Args:
        extracted_strings: List of tokens extracted from APK
        base_features: Full feature list (before selection)
        scaler: Fitted MinMaxScaler
        selected_features: Selected features for the model
        feat_to_idx: Optional precomputed feature→index mapping (cached optimization)
        sel_indices: Optional precomputed selected feature indices (cached optimization)
    """
    raw_vec = {f: 0.0 for f in base_features}
    matched_exact = []
    matched_fuzzy = []
    unmatched = 0

    for token in extracted_strings:
        found = False
        if token in raw_vec:
            raw_vec[token] = 1.0
            matched_exact.append(token)
            found = True
        else:
            for feat in selected_features:
                if feat in raw_vec and _is_match(str(feat), str(token)):
                    raw_vec[feat] = 1.0
                    matched_fuzzy.append((token, feat))
                    found = True
                    break
        if not found:
            unmatched += 1

    vec_all = np.array([[raw_vec.get(f, 0.0) for f in base_features]], dtype=float)
    vec_scaled = scaler.transform(vec_all)
    
    # Use precomputed indices if available, otherwise compute
    if feat_to_idx is None:
        feat_to_idx = {f: i for i, f in enumerate(base_features)}
    if sel_indices is None:
        sel_indices = [feat_to_idx[f] for f in selected_features if f in feat_to_idx]
    
    vec_final = vec_scaled[:, sel_indices]

    matched_features = [f for f in selected_features if raw_vec.get(f, 0.0) > 0]
    diagnostics = {
        "apk_tokens_total": len(extracted_strings),
        "exact_matches": len(matched_exact),
        "fuzzy_matches": len(matched_fuzzy),
        "unmatched_tokens": unmatched,
        "features_activated": len(matched_features),
        "match_ratio_pct": round(len(matched_features) / max(1, len(selected_features)) * 100, 1),
        "n_base_features": len(base_features),
        "n_selected_features": len(selected_features),
    }
    return vec_final, matched_features, diagnostics


@app.route("/")
def index():
    return render_template("index.html")


@app.before_request
def _log_analyze_request_start():
    """Werkzeug access log prints only when the response is sent; log start here for long APK jobs."""
    if request.method == "POST" and request.path == "/api/analyze":
        logger.info(
            ">>> POST /api/analyze | client=%s | content_length=%s",
            request.remote_addr,
            request.content_length,
        )
        _flush_logs()


@app.route("/api/models", methods=["GET"])
def api_models():
    registry = _load_model_registry()
    return jsonify({
        "datasets": registry,
        "cache_stats": cache_manager.get_stats(),
        "apk_cache_stats": _apk_cache_get_stats(),
        "analyze_session_stats": _analyze_session_get_stats(),
    })


@app.route("/api/datasets", methods=["GET"])
def api_datasets():
    return jsonify(
        {
            "datasets": [
                {
                    "key": key,
                    "label": item["label"],
                    "task": item["task"],
                    "best_model": item["best_model"],
                    "n_features_selected": item["n_features_selected"],
                    "n_features_total": item["n_features_total"],
                    "label_classes": item["label_classes"],
                    "files": item["dataset_files"],
                    "available": all(f["exists"] for f in item["dataset_files"]),
                }
                for key, item in _load_model_registry().items()
            ]
        }
    )


@app.route("/api/summary/<dataset_key>", methods=["GET"])
def api_summary(dataset_key: str):
    if dataset_key not in DATASETS:
        return jsonify({"error": f"Unknown dataset: {dataset_key}"}), 400
    ds_dir = DATASETS[dataset_key]["models_dir"]
    summary = _load_json(ds_dir / "pipeline_summary.json", {})
    return jsonify({"dataset": dataset_key, "summary": summary})


@app.route("/api/cache/stats", methods=["GET"])
def api_cache_stats():
    """Get cache statistics (hits/misses/performance)."""
    return jsonify({
        "cache_stats": cache_manager.get_stats(),
        "apk_cache_stats": _apk_cache_get_stats(),
        "analyze_session_stats": _analyze_session_get_stats(),
    })


@app.route("/api/cache/clear", methods=["POST"])
def api_cache_clear():
    """Clear all caches (admin endpoint)."""
    cache_manager.clear_all()
    _apk_cache_clear()
    _analyze_sessions_clear()
    logger.info("Cache cleared via admin endpoint")
    return jsonify({"status": "success", "message": "All caches cleared"})


def _analyze_apk_events(
    tmp_path: str,
    uploaded_filename: str,
    dataset_key: str,
    algo_key: str,
    apk_sha256: str | None = None,
    analyze_session_id: str | None = None,
):
    """
    Yields progress dicts {event, step, message, elapsed_ms, request_id?} then a final {event: done, data: ...}
    or {event: error, message: ...}.
    """
    req_id = uuid4().hex[:8]
    t0 = time.perf_counter()
    step_order = {
        "saved": 1,
        "bundle": 2,
        "static": 3,
        "strings": 4,
        "vector": 5,
        "registry": 6,
    }
    total_steps = 6

    def prog(step: str, message: str):
        idx = step_order.get(step, 0)
        return {
            "event": "progress",
            "request_id": req_id,
            "step": step,
            "step_index": idx,
            "total_steps": total_steps,
            "progress_pct": round((idx / total_steps) * 100, 1) if idx else 0.0,
            "message": message,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
        }

    try:
        apk_size_kb = round(os.path.getsize(tmp_path) / 1024, 1)
        yield prog(
            "saved",
            f"Đã lưu APK ({apk_size_kb} KB). Server đang xử lý — xem terminal chạy run_webapp.py để thấy log Androguard.",
        )
        logger.info(
            "[%s] Analyze start | file=%s | size=%.1fKB | dataset=%s | algo=%s",
            req_id,
            uploaded_filename,
            apk_size_kb,
            dataset_key,
            algo_key,
        )
        _flush_logs()

        yield prog("bundle", "Bước 2/6: Tải model/bundle (cache giúp lần sau nhanh hơn)…")
        t1 = time.perf_counter()
        logger.info("[%s] Step: loading model bundle (cache may make this fast)...", req_id)
        _flush_logs()
        bundle = _load_runtime_bundle(dataset_key, algo_key)
        logger.info(
            "[%s] Bundle loaded | base_features=%d | selected_features=%d",
            req_id,
            len(bundle["base_features"]),
            len(bundle["selected_features"]),
        )
        _flush_logs()

        cached_apk = _apk_cache_get(apk_sha256) if apk_sha256 else None
        apk_cache_hit = cached_apk is not None

        if apk_cache_hit:
            static_start = time.perf_counter()
            yield prog(
                "static",
                "Bước 3/6: Dùng lại kết quả phân tích tĩnh từ cache APK.",
            )
            static_info = cached_apk["static_info"]
            static_ms = round((time.perf_counter() - static_start) * 1000, 1)
            logger.info("[%s] APK static cache hit (sha=%s)", req_id, apk_sha256[:12])
            _flush_logs()

            strings_start = time.perf_counter()
            yield prog(
                "strings",
                "Bước 4/6: Dùng lại token APK từ cache (không cần trích xuất lại).",
            )
            extracted_strings = cached_apk["extracted_strings"]
            strings_ms = round((time.perf_counter() - strings_start) * 1000, 1)
            logger.info("[%s] APK strings cache hit | tokens=%d", req_id, len(extracted_strings))
            _flush_logs()
        else:
            yield prog(
                "static",
                "Bước 3/6: Phân tích tĩnh — manifest + quét DEX (Androguard). Bước này có thể rất lâu với APK lớn.",
            )
            static_start = time.perf_counter()
            logger.info(
                "[%s] Step: static APK analysis (manifest + DEX scan) — may take minutes on large APKs",
                req_id,
            )
            _flush_logs()
            static_info = extract_apk_info(tmp_path)
            static_ms = round((time.perf_counter() - static_start) * 1000, 1)
            logger.info(
                "[%s] Static analysis done | risk_score=%s | dangerous_perms=%d | sensitive_apis=%d",
                req_id,
                static_info.get("risk_score"),
                len(static_info.get("permissions", {}).get("dangerous", [])),
                len(static_info.get("api_calls", {}).get("sensitive", [])),
            )
            _flush_logs()

            yield prog(
                "strings",
                "Bước 4/6: Trích xuất chuỗi cho ML — thường là bước chậm nhất (nhiều token).",
            )
            strings_start = time.perf_counter()
            logger.info("[%s] Step: extracting APK strings for ML — often the slowest step", req_id)
            _flush_logs()
            extracted_strings = extract_apk_strings(tmp_path)
            strings_ms = round((time.perf_counter() - strings_start) * 1000, 1)
            logger.info("[%s] APK strings extracted | tokens=%d", req_id, len(extracted_strings))
            _flush_logs()

            if apk_sha256:
                _apk_cache_set(apk_sha256, static_info, extracted_strings)
                logger.info("[%s] APK analysis cached (sha=%s)", req_id, apk_sha256[:12])
                _flush_logs()

        yield prog("vector", "Bước 5/6: Map token → vector đặc trưng + dự đoán…")
        t4 = time.perf_counter()
        logger.info("[%s] Step: mapping tokens to feature vector + predict", req_id)
        _flush_logs()
        vector_final, matched_features, diagnostics = _apk_to_vector(
            extracted_strings,
            bundle["base_features"],
            bundle["scaler"],
            bundle["selected_features"],
            feat_to_idx=bundle.get("feat_to_idx"),
            sel_indices=bundle.get("sel_indices"),
        )
        logger.info(
            "[%s] Vector built | shape=%s | features_hit=%d | exact=%d | fuzzy=%d",
            req_id,
            tuple(vector_final.shape),
            diagnostics.get("features_activated"),
            diagnostics.get("exact_matches"),
            diagnostics.get("fuzzy_matches"),
        )
        _flush_logs()

        t5 = time.perf_counter()
        clf = bundle["clf"]
        label_encoder = bundle["label_encoder"]
        pred_idx = int(clf.predict(vector_final)[0])
        label_classes = [str(c) for c in getattr(label_encoder, "classes_", [])]
        pred_label = (
            label_classes[pred_idx] if 0 <= pred_idx < len(label_classes) else str(pred_idx)
        )

        proba_payload = None
        confidence = None
        if hasattr(clf, "predict_proba"):
            probs = clf.predict_proba(vector_final)[0]
            confidence = float(np.max(probs)) * 100.0
            proba_payload = [
                {"label": label_classes[i] if i < len(label_classes) else str(i), "prob": float(p)}
                for i, p in enumerate(probs)
            ]
            proba_payload = sorted(proba_payload, key=lambda x: x["prob"], reverse=True)
        logger.info(
            "[%s] Prediction done | label=%s | confidence=%s",
            req_id,
            pred_label,
            f"{confidence:.2f}%" if confidence is not None else "N/A",
        )
        _flush_logs()

        yield prog("registry", "Bước 6/6: Lấy thông tin metrics và hoàn tất…")
        t6 = time.perf_counter()
        registry = _load_model_registry()
        ds_item = registry[dataset_key]
        algo_metrics = next(
            (a["metrics"] for a in ds_item["algorithms"] if a["key"] == algo_key),
            {},
        )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        logger.info(
            "[%s] Analyze complete | total=%.1fms | bundle=%.1fms | static=%.1fms | extract=%.1fms | map=%.1fms | predict=%.1fms | registry=%.1fms",
            req_id,
            elapsed_ms,
            (static_start - t1) * 1000,
            static_ms,
            strings_ms,
            (t5 - t4) * 1000,
            (t6 - t5) * 1000,
            (time.perf_counter() - t6) * 1000,
        )
        _flush_logs()

        payload = {
            "request_id": req_id,
            "analyze_session_id": analyze_session_id,
            "dataset_key": dataset_key,
            "dataset_label": DATASETS[dataset_key]["label"],
            "algo_key": algo_key,
            "algo_label": DATASETS[dataset_key]["algorithms"][algo_key],
            "dataset_summary": {
                "best_model": ds_item.get("best_model"),
                "n_features_selected": ds_item.get("n_features_selected"),
                "n_features_total": ds_item.get("n_features_total"),
                "label_classes": ds_item.get("label_classes", []),
            },
            "model_metrics": algo_metrics,
            "prediction": {
                "encoded": pred_idx,
                "label": pred_label,
                "confidence": _safe_float(round(confidence, 2) if confidence else None),
                "probabilities": proba_payload,
            },
            "features": {
                **diagnostics,
                "matched_features": matched_features[:40],
            },
            "static_analysis": static_info,
            "timing_ms": {
                "total": elapsed_ms,
                "bundle_load": round((static_start - t1) * 1000, 1),
                "static_analysis": static_ms,
                "string_extraction": strings_ms,
                "feature_mapping": round((t5 - t4) * 1000, 1),
                "prediction": round((t6 - t5) * 1000, 1),
            },
            "cache_info": {
                "enabled": cache_manager.enabled,
                "bundle_stats": cache_manager.bundle_cache.get_stats(),
                "apk_cache_hit": apk_cache_hit,
                "apk_sha256_prefix": apk_sha256[:12] if apk_sha256 else None,
                "apk_cache_stats": _apk_cache_get_stats(),
            },
        }
        yield {"event": "done", "request_id": req_id, "data": payload}
    except Exception as exc:
        logger.exception("Analyze failed: %s", exc)
        _flush_logs()
        yield {
            "event": "error",
            "request_id": req_id,
            "message": str(exc),
        }


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    dataset_key = request.form.get("dataset_key", "").strip().lower()
    algo_key = request.form.get("algo_key", "").strip().lower()
    if dataset_key not in DATASETS:
        return jsonify({"error": f"Unknown dataset_key: {dataset_key}"}), 400
    if algo_key not in DATASETS[dataset_key]["algorithms"]:
        return jsonify({"error": f"Unknown algo_key: {algo_key}"}), 400

    use_stream = request.form.get("stream", "").lower() in ("1", "true", "yes")
    analyze_session_id = request.form.get("analyze_session_id", "").strip()

    has_file = "file" in request.files and bool(request.files["file"].filename)
    if has_file:
        uploaded = request.files["file"]
        if not uploaded.filename.lower().endswith(".apk"):
            return jsonify({"error": "Only .apk files are supported"}), 400
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".apk")
        os.close(tmp_fd)
        uploaded.save(tmp_path)
        uploaded_filename = uploaded.filename
        apk_sha256 = _hash_file_sha256(tmp_path)
        analyze_session_id = _create_analyze_session(tmp_path, uploaded_filename, apk_sha256)
    else:
        if not analyze_session_id:
            return jsonify({"error": "Missing file field or analyze_session_id"}), 400
        sess = _analyze_session_get(analyze_session_id)
        if not sess:
            return jsonify({"error": "Analyze session not found or expired. Upload APK again."}), 400
        tmp_path = sess["tmp_path"]
        uploaded_filename = sess.get("uploaded_filename", "cached.apk")
        apk_sha256 = sess.get("apk_sha256")

    if use_stream:
        def ndjson_gen():
            for evt in _analyze_apk_events(
                tmp_path,
                uploaded_filename,
                dataset_key,
                algo_key,
                apk_sha256=apk_sha256,
                analyze_session_id=analyze_session_id,
            ):
                yield json.dumps(evt, ensure_ascii=False) + "\n"
                _flush_logs()

        return Response(
            stream_with_context(ndjson_gen()),
            mimetype="application/x-ndjson; charset=utf-8",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    final = None
    for evt in _analyze_apk_events(
        tmp_path,
        uploaded_filename,
        dataset_key,
        algo_key,
        apk_sha256=apk_sha256,
        analyze_session_id=analyze_session_id,
    ):
        if evt.get("event") == "done":
            final = evt.get("data")
        elif evt.get("event") == "error":
            return jsonify({"error": evt.get("message", "Unknown error")}), 500
    if final is None:
        return jsonify({"error": "No result"}), 500
    return jsonify(final)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=True)

