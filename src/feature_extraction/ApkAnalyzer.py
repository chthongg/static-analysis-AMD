"""
Rich static APK analyzer.

Extracts structured information from an APK based on the components
described in cấu-trúc-file-apk.txt:
  - AndroidManifest.xml  → permissions, activities, services, receivers, providers
  - classes.dex          → API calls, class names
  - resources.arsc       → (basic meta)
  - APK file list        → native libs, embedded files
"""

import logging
import os
import zipfile
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

# ─── Known dangerous permissions ─────────────────────────────────────────────
DANGEROUS_PERMISSIONS: dict[str, dict] = {
    "READ_SMS":                  {"severity": "high",   "desc": "Đọc tin nhắn SMS — thường dùng để đánh cắp mã OTP."},
    "SEND_SMS":                  {"severity": "high",   "desc": "Gửi tin nhắn SMS — có thể gửi SMS premium để trục lợi."},
    "RECEIVE_SMS":               {"severity": "high",   "desc": "Chặn tin nhắn SMS đến trước khi người dùng đọc."},
    "READ_CALL_LOG":             {"severity": "high",   "desc": "Đọc lịch sử cuộc gọi."},
    "WRITE_CALL_LOG":            {"severity": "high",   "desc": "Ghi/xóa lịch sử cuộc gọi."},
    "PROCESS_OUTGOING_CALLS":    {"severity": "high",   "desc": "Chặn và chuyển hướng cuộc gọi đi."},
    "CALL_PHONE":                {"severity": "high",   "desc": "Gọi điện không cần xác nhận người dùng."},
    "RECORD_AUDIO":              {"severity": "high",   "desc": "Ghi âm microphone — có thể nghe lén."},
    "CAMERA":                    {"severity": "high",   "desc": "Truy cập camera — có thể chụp ảnh bí mật."},
    "ACCESS_FINE_LOCATION":      {"severity": "high",   "desc": "Theo dõi vị trí chính xác (GPS)."},
    "ACCESS_COARSE_LOCATION":    {"severity": "medium", "desc": "Theo dõi vị trí gần đúng (Wi-Fi/Cell)."},
    "READ_CONTACTS":             {"severity": "high",   "desc": "Đọc danh bạ điện thoại."},
    "WRITE_CONTACTS":            {"severity": "medium", "desc": "Sửa/xóa danh bạ điện thoại."},
    "READ_PHONE_STATE":          {"severity": "medium", "desc": "Đọc thông tin thiết bị: IMEI, số điện thoại."},
    "READ_PHONE_NUMBERS":        {"severity": "medium", "desc": "Đọc số điện thoại của SIM."},
    "RECEIVE_BOOT_COMPLETED":    {"severity": "medium", "desc": "Tự khởi động khi máy mở lên."},
    "INSTALL_PACKAGES":          {"severity": "high",   "desc": "Cài đặt ứng dụng khác mà không cần người dùng."},
    "DELETE_PACKAGES":           {"severity": "high",   "desc": "Xóa ứng dụng trên thiết bị."},
    "SYSTEM_ALERT_WINDOW":       {"severity": "medium", "desc": "Vẽ overlay đè lên ứng dụng khác — phishing UI."},
    "BIND_ACCESSIBILITY_SERVICE": {"severity": "high",  "desc": "Truy cập Accessibility Service — đọc mọi UI trên màn hình."},
    "DEVICE_ADMIN":              {"severity": "high",   "desc": "Quyền quản trị thiết bị — có thể reset, khóa máy."},
    "CHANGE_NETWORK_STATE":      {"severity": "low",    "desc": "Bật/tắt kết nối mạng."},
    "WRITE_SETTINGS":            {"severity": "medium", "desc": "Sửa cài đặt hệ thống."},
    "GET_ACCOUNTS":              {"severity": "medium", "desc": "Liệt kê tài khoản Google và các tài khoản khác."},
    "USE_CREDENTIALS":           {"severity": "high",   "desc": "Sử dụng thông tin xác thực tài khoản."},
    "INTERNET":                  {"severity": "low",    "desc": "Kết nối Internet — cần cho hầu hết ứng dụng."},
    "RECEIVE_MMS":               {"severity": "medium", "desc": "Nhận tin nhắn MMS."},
    "WRITE_EXTERNAL_STORAGE":    {"severity": "low",    "desc": "Ghi file vào bộ nhớ ngoài."},
    "READ_EXTERNAL_STORAGE":     {"severity": "low",    "desc": "Đọc file từ bộ nhớ ngoài."},
    "BLUETOOTH":                 {"severity": "low",    "desc": "Kết nối Bluetooth."},
    "NFC":                       {"severity": "medium", "desc": "Sử dụng NFC — có thể dùng cho thanh toán."},
}

# ─── Known sensitive API patterns ────────────────────────────────────────────
SENSITIVE_APIS: dict[str, dict] = {
    # Network / C&C communication
    "HttpClient":        {"cat": "Mạng",       "severity": "low",    "desc": "Thực hiện HTTP request — có thể liên lạc C&C server."},
    "URL":               {"cat": "Mạng",       "severity": "low",    "desc": "Tạo URL connection."},
    "Socket":            {"cat": "Mạng",       "severity": "medium", "desc": "Kết nối TCP/IP trực tiếp."},
    # Telephony
    "sendTextMessage":   {"cat": "Điện thoại", "severity": "high",   "desc": "Gửi SMS bằng lệnh trực tiếp."},
    "getDeviceId":       {"cat": "Điện thoại", "severity": "high",   "desc": "Lấy IMEI của thiết bị."},
    "getSubscriberId":   {"cat": "Điện thoại", "severity": "high",   "desc": "Lấy IMSI của SIM."},
    "getLine1Number":    {"cat": "Điện thoại", "severity": "high",   "desc": "Lấy số điện thoại của SIM."},
    "getSimSerialNumber":{"cat": "Điện thoại", "severity": "high",   "desc": "Lấy serial number của SIM (ICCID)."},
    # Crypto / Obfuscation
    "Cipher":            {"cat": "Mã hoá",     "severity": "medium", "desc": "Thực hiện mã hoá/giải mã dữ liệu."},
    "MessageDigest":     {"cat": "Mã hoá",     "severity": "low",    "desc": "Tính hash MD5/SHA."},
    "SecretKey":         {"cat": "Mã hoá",     "severity": "medium", "desc": "Xử lý khóa bí mật."},
    # Reflection / Dynamic loading
    "DexClassLoader":    {"cat": "Tải động",   "severity": "high",   "desc": "Tải và thực thi DEX từ bên ngoài — dynamic code loading."},
    "PathClassLoader":   {"cat": "Tải động",   "severity": "high",   "desc": "Tải class từ đường dẫn tuỳ chỉnh."},
    "loadDex":           {"cat": "Tải động",   "severity": "high",   "desc": "Tải file DEX vào bộ nhớ."},
    "loadClass":         {"cat": "Reflection", "severity": "medium", "desc": "Nạp class theo tên — dấu hiệu reflection."},
    "forName":           {"cat": "Reflection", "severity": "medium", "desc": "Class.forName() — reflection để tránh phát hiện tĩnh."},
    "getMethod":         {"cat": "Reflection", "severity": "medium", "desc": "Gọi method qua reflection."},
    "getDeclaredMethod": {"cat": "Reflection", "severity": "medium", "desc": "Gọi private method qua reflection."},
    "invoke":            {"cat": "Reflection", "severity": "medium", "desc": "Thực thi method qua reflection."},
    # Shell / Root
    "Runtime":           {"cat": "Shell",      "severity": "high",   "desc": "Runtime.exec() — chạy lệnh shell tuỳ ý."},
    "exec":              {"cat": "Shell",      "severity": "high",   "desc": "Thực thi tiến trình ngoài (shell command)."},
    "ProcessBuilder":    {"cat": "Shell",      "severity": "high",   "desc": "Xây dựng và thực thi tiến trình."},
    # Device admin / Accessibility
    "DevicePolicyManager": {"cat": "Quyền hệ thống", "severity": "high", "desc": "Quản lý chính sách thiết bị (Device Admin)."},
    "AccessibilityService": {"cat": "Quyền hệ thống","severity": "high", "desc": "Đọc mọi sự kiện UI trên màn hình."},
    # Broadcast abuse
    "abortBroadcast":    {"cat": "Broadcast",  "severity": "high",   "desc": "Chặn Broadcast Intent trước khi ứng dụng khác nhận."},
    "sendBroadcast":     {"cat": "Broadcast",  "severity": "low",    "desc": "Gửi Broadcast Intent."},
    # Service / startup
    "startService":      {"cat": "Dịch vụ",    "severity": "low",    "desc": "Khởi động Service chạy nền."},
    "bindService":       {"cat": "Dịch vụ",    "severity": "low",    "desc": "Kết nối với Service."},
}

# ─── Intent filters of interest ──────────────────────────────────────────────
SUSPICIOUS_INTENTS = {
    "android.intent.action.BOOT_COMPLETED": "Chạy khi thiết bị khởi động",
    "android.intent.action.SMS_RECEIVED":   "Nhận SMS",
    "android.intent.action.SEND":           "Gửi dữ liệu",
    "android.telephony.action.RESPOND_VIA_MESSAGE": "Phản hồi cuộc gọi bằng SMS",
    "android.intent.action.CALL":           "Gọi điện",
    "android.intent.action.PACKAGE_ADDED":  "Theo dõi cài đặt ứng dụng mới",
}


def _short_name(full_name: str) -> str:
    """Extract readable short name from a fully-qualified component name."""
    name = full_name.split(".")[-1].replace(";", "")
    return name if name else full_name


def _permission_short(perm: str) -> str:
    """Strip android.permission. prefix."""
    for prefix in ("android.permission.", "android.Manifest.permission.", "com.android."):
        if perm.startswith(prefix):
            return perm[len(prefix):]
    return perm.split(".")[-1]


def _match_api(name: str) -> str | None:
    """Return matching sensitive API key or None."""
    for api_key in SENSITIVE_APIS:
        if api_key.lower() in name.lower():
            return api_key
    return None


def extract_apk_info(apk_path: str) -> dict:
    """Extract rich static analysis information from an APK.

    Dùng androguard.core.apk.APK (nhẹ) cho manifest info +
    zipfile + regex để scan DEX cho API calls — thay vì AnalyzeAPK chậm.

    Returns a structured dict with:
        meta, permissions, components, intents, api_calls,
        native_libs, file_list, risk_indicators
    """
    import re as _re

    logger.info("Rich APK analysis (lightweight): %s", apk_path)
    result: dict = {
        "meta": {},
        "permissions": {"dangerous": [], "normal": [], "all": []},
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        },
        "intents": [],
        "api_calls": {"sensitive": [], "all_count": 0},
        "native_libs": [],
        "file_list": [],
        "risk_indicators": [],
    }

    # ── File metadata ────────────────────────────────────────────────────────
    result["meta"]["size_kb"] = round(os.path.getsize(apk_path) / 1024, 1)
    result["meta"]["filename"] = os.path.basename(apk_path)

    # ── APK file list (from zip) ──────────────────────────────────────────────
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            result["file_list"] = sorted(names)[:80]
            result["native_libs"] = [n for n in names if n.endswith(".so")]
    except Exception as e:
        logger.warning("Could not read zip content: %s", e)

    # ── Manifest analysis via APK() ───────────────────────────────────────────
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
    except Exception as e:
        result["meta"]["error"] = str(e)
        logger.warning("APK() parse failed: %s", e)
        return result

    # Package meta
    try:
        result["meta"]["package"]      = a.get_package()
        result["meta"]["version_name"] = a.get_androidversion_name()
        result["meta"]["version_code"] = a.get_androidversion_code()
        result["meta"]["min_sdk"]      = str(a.get_min_sdk_version())
        result["meta"]["target_sdk"]   = str(a.get_target_sdk_version())
    except Exception:
        pass

    # ── Permissions ──────────────────────────────────────────────────────────
    try:
        raw_perms = a.get_permissions() or []
    except Exception:
        raw_perms = []

    seen_perms: set[str] = set()
    for p in raw_perms:
        short = _permission_short(p)
        if short in seen_perms:
            continue
        seen_perms.add(short)
        entry = {"full": p, "short": short}

        matched_key = None
        if short in DANGEROUS_PERMISSIONS:
            matched_key = short
        else:
            for key in DANGEROUS_PERMISSIONS:
                if key in p.upper() or p.upper().endswith(key):
                    matched_key = key
                    break

        if matched_key:
            info = DANGEROUS_PERMISSIONS[matched_key]
            entry.update({"severity": info["severity"], "desc": info["desc"]})
            result["permissions"]["dangerous"].append(entry)
        else:
            entry.update({"severity": "info", "desc": "Quyền thông thường."})
            result["permissions"]["normal"].append(entry)

        result["permissions"]["all"].append(entry)

    for p in result["permissions"]["dangerous"]:
        if p["severity"] == "high":
            result["risk_indicators"].append({
                "type": "permission",
                "name": p["short"],
                "severity": "high",
                "desc": p["desc"],
            })

    # ── Components ───────────────────────────────────────────────────────────
    component_map = {
        "activities": (a.get_activities, "Activity",  "Giao diện người dùng"),
        "services":   (a.get_services,   "Service",   "Tác vụ chạy ngầm"),
        "receivers":  (a.get_receivers,  "Receiver",  "Nhận sự kiện hệ thống"),
        "providers":  (a.get_providers,  "Provider",  "Chia sẻ dữ liệu"),
    }
    for key, (getter, kind, role) in component_map.items():
        try:
            items = getter() or []
        except Exception:
            items = []
        for item in items:
            result["components"][key].append({
                "full": str(item),
                "short": _short_name(str(item)),
                "kind": kind,
                "role": role,
            })

    if len(result["components"]["receivers"]) > 5:
        result["risk_indicators"].append({
            "type": "component",
            "name": f"{len(result['components']['receivers'])} Broadcast Receivers",
            "severity": "medium",
            "desc": "Nhiều Receiver → có thể nghe lén nhiều sự kiện hệ thống.",
        })

    # ── Intent filters ───────────────────────────────────────────────────────
    try:
        for comp_type in ("activity", "service", "receiver"):
            try:
                ifilters = a.get_intent_filters(comp_type, "") or {}
                for vals in ifilters.values():
                    if isinstance(vals, list):
                        result["intents"].extend(str(v) for v in vals)
                    elif vals:
                        result["intents"].append(str(vals))
            except Exception:
                pass
    except Exception:
        pass

    for intent in result["intents"]:
        if intent in SUSPICIOUS_INTENTS:
            result["risk_indicators"].append({
                "type": "intent",
                "name": intent.split(".")[-1],
                "severity": "medium",
                "desc": SUSPICIOUS_INTENTS[intent],
            })

    # ── API calls — DEX scan via zipfile + regex ─────────────────────────────
    sensitive_found: dict[str, dict] = {}
    api_count = 0
    _CLS_RE = _re.compile(rb"L[\w/$]{4,80};")

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            dex_files = [n for n in zf.namelist() if _re.match(r"classes\d*\.dex", n)]
            for dex_name in dex_files:
                data = zf.read(dex_name)
                # Extract class names from DEX bytecode
                for m in _CLS_RE.findall(data):
                    try:
                        cname = m.decode("utf-8", errors="ignore").lstrip("L").rstrip(";").replace("/", ".")
                    except Exception:
                        continue
                    api_count += 1
                    key = _match_api(cname)
                    if key and key not in sensitive_found:
                        sensitive_found[key] = {
                            "api": key,
                            "in_class": cname,
                            **SENSITIVE_APIS[key],
                        }
                # Extract printable ASCII tokens (method names etc.)
                for token in _re.findall(rb"[a-zA-Z_]\w{3,40}", data):
                    try:
                        mname = token.decode("ascii", errors="ignore")
                    except Exception:
                        continue
                    key = _match_api(mname)
                    if key and key not in sensitive_found:
                        sensitive_found[key] = {
                            "api": key,
                            "in_class": "—",
                            **SENSITIVE_APIS[key],
                        }
    except Exception as e:
        logger.warning("DEX scan failed: %s", e)

    result["api_calls"]["all_count"] = api_count
    result["api_calls"]["sensitive"] = list(sensitive_found.values())

    for api_info in result["api_calls"]["sensitive"]:
        if api_info["severity"] == "high":
            result["risk_indicators"].append({
                "type": "api",
                "name": api_info["api"],
                "severity": "high",
                "desc": api_info["desc"],
            })

    # ── Native libraries ──────────────────────────────────────────────────────
    if result["native_libs"]:
        result["risk_indicators"].append({
            "type": "native",
            "name": f"{len(result['native_libs'])} Native lib(s)",
            "severity": "medium",
            "desc": "Chứa file .so — native code có thể khó phân tích hơn.",
        })

    # ── Risk score (0-100) ────────────────────────────────────────────────────
    severity_weights = {"high": 15, "medium": 5, "low": 1}
    raw_score = sum(severity_weights.get(r["severity"], 0) for r in result["risk_indicators"])
    result["risk_score"] = min(100, raw_score)

    logger.info(
        "APK analysis done: %d permissions, %d activities, %d services, "
        "%d receivers, %d sensitive APIs, risk_score=%d",
        len(result["permissions"]["all"]),
        len(result["components"]["activities"]),
        len(result["components"]["services"]),
        len(result["components"]["receivers"]),
        len(result["api_calls"]["sensitive"]),
        result["risk_score"],
    )
    return result
