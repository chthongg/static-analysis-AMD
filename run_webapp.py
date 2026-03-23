import os
import sys
import time
from pathlib import Path

# Line-buffer stdout/stderr so Flask + logging lines appear immediately in the IDE terminal (esp. Windows).
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
os.environ.setdefault("PYTHONUNBUFFERED", "1")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from webapp.app import app, cache_manager, _load_model_registry, DATASETS


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print("\nStatic Analysis AMD Web App")
    print(f"http://localhost:{port}\n")
    
    # Optional cache warmup on startup
    if os.environ.get("AMD_CACHE_WARMUP", "").lower() in ("true", "1", "yes"):
        print("Warming up cache...")
        warmup_start = time.time()
        
        try:
            # Warm up registry cache
            _load_model_registry()
            
            # Warm up a few bundle caches (optional, can be slow)
            # Just loading registry is usually enough
            
            warmup_ms = (time.time() - warmup_start) * 1000
            print(f"Cache warmup completed in {warmup_ms:.1f}ms\n")
        except Exception as e:
            print(f"Cache warmup failed (non-critical): {e}\n")
    
    app.run(debug=True, host="0.0.0.0", port=port)


