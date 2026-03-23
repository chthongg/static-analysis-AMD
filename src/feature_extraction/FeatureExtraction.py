"""
APK Static Feature Extraction using Androguard.

Trích xuất vector đặc trưng nhị phân từ file APK bằng cách đối chiếu
các chuỗi tĩnh (permissions, API calls, intents...) với danh sách features
được RRFS chọn lựa, sử dụng fuzzy string matching.
"""
import logging
from difflib import SequenceMatcher

import numpy as np

logger = logging.getLogger(__name__)

FUZZY_THRESHOLD = 70  # phần trăm tương đồng tối thiểu để coi là khớp


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100


def _is_match(feature: str, extracted: str) -> bool:
    """Kiểm tra xem một token APK có khớp với feature không."""
    fl = feature.lower()
    el = extracted.lower()
    if fl == el:
        return True
    if fl in el or el in fl:
        return True
    return _similarity(fl, el) >= FUZZY_THRESHOLD



def extract_apk_strings(apk_path: str) -> list[str]:
    """Phân tích APK và trả về danh sách chuỗi tĩnh đã trích xuất.

    Dùng androguard.core.apk.APK (nhẹ) cho manifest + zipfile/regex cho DEX,
    thay vì AnalyzeAPK (nặng, chậm hàng giờ).
    """
    import zipfile
    import re

    logger.info("Phân tích APK (lightweight): %s", apk_path)
    strings: list[str] = []

    # ── 1. Manifest info via APK() ────────────────────────────────────────────
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        for getter in [
            a.get_permissions,
            a.get_features,
            a.get_activities,
            a.get_services,
            a.get_receivers,
            a.get_providers,
        ]:
            try:
                strings.extend(getter() or [])
            except Exception:
                pass
        try:
            ifilters = a.get_intent_filters("activity", "") or {}
            for vals in ifilters.values():
                if isinstance(vals, list):
                    strings.extend(vals)
                elif vals:
                    strings.append(str(vals))
        except Exception:
            pass
    except Exception as e:
        logger.warning("APK() manifest parse failed: %s", e)

    # ── 2. DEX scan via zipfile + regex ───────────────────────────────────────
    _CLASS_RE  = re.compile(rb"L[\w/$]{4,80};")
    _METHOD_RE = re.compile(rb"[a-zA-Z_]\w{2,40}")
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_names = [n for n in zf.namelist() if re.match(r"classes\d*\.dex", n)]
            for dex_name in dex_names:
                data = zf.read(dex_name)
                # Class names: Lcom/example/Foo; → com.example.Foo
                for m in _CLASS_RE.findall(data):
                    try:
                        cls = m.decode("utf-8", errors="ignore").lstrip("L").rstrip(";").replace("/", ".")
                        strings.append(cls)
                    except Exception:
                        pass
                # Simple method-like tokens from string table (printable ASCII)
                printable = re.findall(rb"[ -~]{4,60}", data)
                for token in printable:
                    try:
                        decoded = token.decode("ascii", errors="ignore").strip()
                        if _METHOD_RE.fullmatch(decoded.encode()):
                            strings.append(decoded)
                    except Exception:
                        pass
    except Exception as e:
        logger.warning("DEX scan failed: %s", e)

    strings = [s for s in strings if s]
    logger.info("Trích xuất %d chuỗi từ APK (lightweight)", len(strings))
    return strings


def feature_extraction(
    apk_path: str,
    most_relevant_features: list,
    extracted_strings: list[str] | None = None,
) -> np.ndarray:
    """Tạo vector đặc trưng nhị phân từ APK.

    Với mỗi feature trong danh sách RRFS đã chọn, kiểm tra xem APK
    có chứa chuỗi khớp (exact hoặc fuzzy) không.

    Args:
        apk_path: Đường dẫn tới file .apk.
        most_relevant_features: Danh sách tên feature được RRFS chọn.
        extracted_strings: Nếu đã extract trước, truyền vào để tránh re-parse.

    Returns:
        numpy array shape (1, n_features) với giá trị 0/1.
    """
    extracted = extracted_strings if extracted_strings is not None else extract_apk_strings(apk_path)

    vector = []
    for feature in most_relevant_features:
        matched = any(_is_match(str(feature), s) for s in extracted)
        vector.append(1 if matched else 0)

    matched_count = sum(vector)
    logger.info(
        "Feature matching: %d / %d features matched",
        matched_count,
        len(most_relevant_features),
    )
    return np.array([vector])
