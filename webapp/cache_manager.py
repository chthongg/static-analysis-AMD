"""
Smart caching system for AMD web app.

Implements:
  - BundleCacheManager: LRU cache for runtime bundles (scaler, models, features)
    with mtime-based invalidation
  - RegistryCacheManager: TTL-based cache for model registry
  - Thread-safe operations
  - Graceful fallback on cache miss/error
"""

import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class BundleCacheManager:
    """
    LRU cache for runtime bundles (scaler, models, features, encoders).
    
    Validates cache entries by comparing file mtimes. If any artifact
    file has been modified, the entry is invalidated and reloaded.
    """
    
    def __init__(self, max_bundles: int = 10):
        self.max_bundles = max_bundles
        self.cache: OrderedDict[Tuple[str, str], Dict[str, Any]] = OrderedDict()
        self.mtimes: Dict[Tuple[str, str], Dict[Path, float]] = {}
        self.lock = threading.RLock()
        self.stats = {"hits": 0, "misses": 0, "invalidations": 0}
    
    def _get_artifact_paths(self, bundle_dir: Path, dataset_key: str) -> Dict[Path, str]:
        """Get all artifact paths that should be monitored for this bundle."""
        paths = {}
        shared_dir = bundle_dir / "shared"
        
        # Common shared artifacts
        for name in ["features.pkl", "label_encoder.pkl", "scaler.pkl"]:
            p = shared_dir / name
            if p.exists():
                paths[p] = name
        
        # Dataset-specific base features
        if dataset_key == "maldroid2020":
            p = shared_dir / "feature_names_after_drop.pkl"
        else:
            p = shared_dir / "base_features.pkl"
        if p.exists():
            paths[p] = p.name
        
        return paths
    
    def _check_validity(self, key: Tuple[str, str], bundle_dir: Path, 
                       dataset_key: str) -> bool:
        """Check if cached bundle is still valid (files not modified)."""
        if key not in self.cache:
            return False
        
        artifact_paths = self._get_artifact_paths(bundle_dir, dataset_key)
        stored_mtimes = self.mtimes.get(key, {})
        
        for path, name in artifact_paths.items():
            if not path.exists():
                logger.warning(f"Artifact missing: {path}")
                return False
            
            try:
                current_mtime = path.stat().st_mtime
                stored_mtime = stored_mtimes.get(path, 0)
                
                if current_mtime != stored_mtime:
                    logger.debug(
                        f"Cache invalidated for {key}: {name} modified "
                        f"(stored={stored_mtime}, current={current_mtime})"
                    )
                    self.stats["invalidations"] += 1
                    return False
            except Exception as e:
                logger.warning(f"Failed to check mtime for {path}: {e}")
                return False
        
        return True
    
    def _store_mtimes(self, key: Tuple[str, str], bundle_dir: Path, 
                     dataset_key: str) -> None:
        """Store mtimes of all artifact files for future validation."""
        artifact_paths = self._get_artifact_paths(bundle_dir, dataset_key)
        mtimes = {}
        
        for path, name in artifact_paths.items():
            try:
                mtimes[path] = path.stat().st_mtime
            except Exception as e:
                logger.warning(f"Failed to store mtime for {path}: {e}")
        
        self.mtimes[key] = mtimes
    
    def get(self, key: Tuple[str, str], bundle_dir: Path, dataset_key: str
            ) -> Optional[Dict[str, Any]]:
        """
        Get cached bundle if valid, otherwise return None.
        
        Args:
            key: (dataset_key, algo_key) tuple
            bundle_dir: Path to the models/<dataset> directory
            dataset_key: Dataset key for artifact path selection
        
        Returns:
            Cached bundle dict or None if not cached/invalid
        """
        with self.lock:
            if key not in self.cache:
                self.stats["misses"] += 1
                return None
            
            if not self._check_validity(key, bundle_dir, dataset_key):
                del self.cache[key]
                if key in self.mtimes:
                    del self.mtimes[key]
                self.stats["misses"] += 1
                return None
            
            # Move to end (LRU)
            self.cache.move_to_end(key)
            self.stats["hits"] += 1
            logger.debug(f"Cache hit for bundle {key}")
            return self.cache[key]
    
    def set(self, key: Tuple[str, str], bundle: Dict[str, Any], 
            bundle_dir: Path, dataset_key: str) -> None:
        """
        Store bundle in cache with LRU eviction.
        
        Args:
            key: (dataset_key, algo_key) tuple
            bundle: Bundle dict with scaler, clf, features, etc.
            bundle_dir: Path to the models/<dataset> directory
            dataset_key: Dataset key for artifact path selection
        """
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            
            self.cache[key] = bundle
            self._store_mtimes(key, bundle_dir, dataset_key)
            
            # Evict oldest if over capacity
            while len(self.cache) > self.max_bundles:
                evicted_key = next(iter(self.cache))
                del self.cache[evicted_key]
                if evicted_key in self.mtimes:
                    del self.mtimes[evicted_key]
                logger.debug(f"Cache evicted: {evicted_key}")
    
    def clear(self) -> None:
        """Clear all cached bundles."""
        with self.lock:
            self.cache.clear()
            self.mtimes.clear()
            logger.info("Bundle cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total = self.stats["hits"] + self.stats["misses"]
            hit_ratio = (
                self.stats["hits"] / total * 100 if total > 0 else 0
            )
            return {
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "invalidations": self.stats["invalidations"],
                "hit_ratio_pct": round(hit_ratio, 1),
                "cached_bundles": len(self.cache),
                "max_bundles": self.max_bundles,
            }


class RegistryCacheManager:
    """
    TTL-based cache for model registry.
    
    Caches the result of _load_model_registry() with configurable TTL.
    Supports explicit invalidation and stats tracking.
    """
    
    def __init__(self, ttl_seconds: int = 300):
        """
        Args:
            ttl_seconds: Time to live for cached registry (default 5 min)
        """
        self.ttl_seconds = ttl_seconds
        self.cache: Optional[Dict[str, Any]] = None
        self.cache_time: float = 0
        self.lock = threading.RLock()
        self.stats = {"hits": 0, "misses": 0, "refreshes": 0}
    
    def get(self) -> Optional[Dict[str, Any]]:
        """
        Get cached registry if still valid (within TTL).
        
        Returns:
            Cached registry dict or None if expired/not set
        """
        with self.lock:
            if self.cache is None:
                self.stats["misses"] += 1
                return None
            
            age = time.time() - self.cache_time
            if age > self.ttl_seconds:
                logger.debug(
                    f"Registry cache expired (age={age:.1f}s, ttl={self.ttl_seconds}s)"
                )
                self.cache = None
                self.stats["misses"] += 1
                return None
            
            self.stats["hits"] += 1
            logger.debug(f"Registry cache hit (age={age:.1f}s)")
            return self.cache
    
    def set(self, registry: Dict[str, Any]) -> None:
        """
        Store registry in cache with current timestamp.
        
        Args:
            registry: Registry dict to cache
        """
        with self.lock:
            self.cache = registry
            self.cache_time = time.time()
            self.stats["refreshes"] += 1
            logger.debug(f"Registry cache refreshed")
    
    def invalidate(self) -> None:
        """Manually invalidate cache."""
        with self.lock:
            self.cache = None
            self.cache_time = 0
            logger.info("Registry cache invalidated")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total = self.stats["hits"] + self.stats["misses"]
            hit_ratio = (
                self.stats["hits"] / total * 100 if total > 0 else 0
            )
            age = (
                time.time() - self.cache_time 
                if self.cache is not None else None
            )
            return {
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "refreshes": self.stats["refreshes"],
                "hit_ratio_pct": round(hit_ratio, 1),
                "cached": self.cache is not None,
                "age_seconds": round(age, 1) if age is not None else None,
                "ttl_seconds": self.ttl_seconds,
            }


class CacheManager:
    """
    Unified cache manager combining bundle and registry caches.
    """
    
    def __init__(self, 
                 max_bundles: int = 10,
                 registry_ttl_seconds: int = 300,
                 enabled: bool = True):
        self.enabled = enabled
        self.bundle_cache = BundleCacheManager(max_bundles=max_bundles)
        self.registry_cache = RegistryCacheManager(ttl_seconds=registry_ttl_seconds)
        logger.info(
            f"CacheManager initialized: "
            f"enabled={enabled}, max_bundles={max_bundles}, "
            f"registry_ttl={registry_ttl_seconds}s"
        )
    
    def clear_all(self) -> None:
        """Clear all caches."""
        self.bundle_cache.clear()
        self.registry_cache.invalidate()
        logger.info("All caches cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get combined cache statistics."""
        return {
            "enabled": self.enabled,
            "bundle": self.bundle_cache.get_stats(),
            "registry": self.registry_cache.get_stats(),
        }
