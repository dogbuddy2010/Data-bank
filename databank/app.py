from __future__ import annotations

import base64
from collections import deque
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Optional
from urllib.parse import quote

try:
    import termios
    import tty

    HAS_TERMIOS = True
except ImportError:
    termios = None
    tty = None
    HAS_TERMIOS = False

try:
    import msvcrt

    HAS_MSVCRT = True
except ImportError:
    msvcrt = None
    HAS_MSVCRT = False


DEFAULT_USERNAME = "guest"
DEFAULT_PASSWORD = "11"
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 200_000
DEFAULT_MAX_LOGIN_ATTEMPTS = 3
DEFAULT_LOCKOUT_SECONDS = 30
DEFAULT_TWO_STEP_ENABLED = False
DEFAULT_TWO_STEP_METHOD = "custom_code"
DEFAULT_SECURITY_AI_SENSITIVITY = "high"
BACKUP_CODE_COUNT = 8
MIN_LOGIN_ATTEMPTS = 1
MAX_LOGIN_ATTEMPTS = 10
MIN_LOCKOUT_SECONDS = 0
MAX_LOCKOUT_SECONDS = 300


SESSION_PASSWORD: Optional[str] = None


def is_writable_directory(directory: Path) -> bool:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe_file = directory / ".data_bank_write_test"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def resolve_storage_dir() -> Path:
    home_storage_dir = (Path.home() / ".data_bank").resolve()

    if is_writable_directory(home_storage_dir):
        return home_storage_dir

    fallback_dirs: list[Path] = [Path.cwd().resolve()]

    main_file = globals().get("__file__")
    if isinstance(main_file, str):
        fallback_dirs.append(Path(main_file).resolve().parent)

    for directory in fallback_dirs:
        if is_writable_directory(directory):
            return directory

    return Path.cwd().resolve()


STORAGE_DIR = resolve_storage_dir()
DATA_FILE = STORAGE_DIR / "vault_data.json"
CONFIG_FILE = STORAGE_DIR / "vault_config.json"
SECURITY_LOG_FILE = STORAGE_DIR / "security_events.jsonl"

SECURITY_RULE_WINDOW_SECONDS = 300
SECURITY_AI_PROFILES: dict[str, dict[str, int]] = {
    "high": {
        "failed_login_threshold": 6,
        "failed_login_user_threshold": 2,
        "single_user_failed_login_spike_threshold": 7,
        "vault_burst_seconds": 60,
        "vault_burst_threshold": 14,
        "unique_key_threshold": 10,
        "vault_alert_confirmations": 1,
    },
    "normal": {
        "failed_login_threshold": 7,
        "failed_login_user_threshold": 3,
        "single_user_failed_login_spike_threshold": 8,
        "vault_burst_seconds": 60,
        "vault_burst_threshold": 16,
        "unique_key_threshold": 12,
        "vault_alert_confirmations": 2,
    },
    "low": {
        "failed_login_threshold": 10,
        "failed_login_user_threshold": 4,
        "single_user_failed_login_spike_threshold": 12,
        "vault_burst_seconds": 60,
        "vault_burst_threshold": 22,
        "unique_key_threshold": 16,
        "vault_alert_confirmations": 3,
    },
}

CURRENT_SECURITY_AI_SENSITIVITY = DEFAULT_SECURITY_AI_SENSITIVITY

ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["failed_login_threshold"]
ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["failed_login_user_threshold"]
ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["single_user_failed_login_spike_threshold"]
ACTIVE_SECURITY_VAULT_BURST_SECONDS = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["vault_burst_seconds"]
ACTIVE_SECURITY_VAULT_BURST_THRESHOLD = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["vault_burst_threshold"]
ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["unique_key_threshold"]
ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS = SECURITY_AI_PROFILES[DEFAULT_SECURITY_AI_SENSITIVITY]["vault_alert_confirmations"]

SESSION_VAULT_ACCESS_TIMESTAMPS: deque[float] = deque()
SESSION_VAULT_KEY_EVENTS: deque[tuple[float, str]] = deque()
SECURITY_ALERT_COOLDOWNS: dict[str, float] = {}
SESSION_VAULT_BURST_COUNT = 0
SESSION_VAULT_KEY_SPIKE_COUNT = 0


def normalize_security_ai_sensitivity(value: object) -> str:
    candidate = str(value).strip().lower()
    if candidate in SECURITY_AI_PROFILES:
        return candidate
    return DEFAULT_SECURITY_AI_SENSITIVITY


def apply_security_ai_sensitivity(sensitivity: object) -> None:
    """Apply a named sensitivity profile to active Security AI thresholds."""
    global CURRENT_SECURITY_AI_SENSITIVITY
    global ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD
    global ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD
    global ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD
    global ACTIVE_SECURITY_VAULT_BURST_SECONDS
    global ACTIVE_SECURITY_VAULT_BURST_THRESHOLD
    global ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD
    global ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS

    normalized = normalize_security_ai_sensitivity(sensitivity)
    profile = SECURITY_AI_PROFILES[normalized]
    CURRENT_SECURITY_AI_SENSITIVITY = normalized
    ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD = profile["failed_login_threshold"]
    ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD = profile["failed_login_user_threshold"]
    ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD = profile[
        "single_user_failed_login_spike_threshold"
    ]
    ACTIVE_SECURITY_VAULT_BURST_SECONDS = profile["vault_burst_seconds"]
    ACTIVE_SECURITY_VAULT_BURST_THRESHOLD = profile["vault_burst_threshold"]
    ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD = profile["unique_key_threshold"]
    ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS = profile["vault_alert_confirmations"]


def prompt(message: str) -> Optional[str]:
    try:
        return input(message).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None


def log_security_event(event_name: str, details: Optional[dict[str, object]] = None) -> None:
    event = {
        "timestamp": int(time.time()),
        "event": event_name,
        "details": details or {},
    }
    try:
        with SECURITY_LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError:
        pass


def load_recent_security_events(window_seconds: int) -> list[dict[str, object]]:
    if not SECURITY_LOG_FILE.exists():
        return []

    cutoff = int(time.time()) - max(1, window_seconds)
    events: list[dict[str, object]] = []
    try:
        with SECURITY_LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                line_text = line.strip()
                if not line_text:
                    continue
                try:
                    parsed = json.loads(line_text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(parsed, dict):
                    continue
                timestamp = parsed.get("timestamp")
                if isinstance(timestamp, int) and timestamp >= cutoff:
                    events.append(parsed)
    except OSError:
        return []
    return events


def load_security_events(max_events: int = 500) -> list[dict[str, object]]:
    if not SECURITY_LOG_FILE.exists():
        return []

    events: list[dict[str, object]] = []
    try:
        with SECURITY_LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                line_text = line.strip()
                if not line_text:
                    continue
                try:
                    parsed = json.loads(line_text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(parsed, dict):
                    continue
                timestamp = parsed.get("timestamp")
                if not isinstance(timestamp, int):
                    continue
                event_name = str(parsed.get("event", "")).strip()
                if not event_name:
                    continue
                details = parsed.get("details")
                normalized_details = details if isinstance(details, dict) else {}
                events.append(
                    {
                        "timestamp": timestamp,
                        "event": event_name,
                        "details": normalized_details,
                    }
                )
    except OSError:
        return []

    if max_events <= 0:
        return events
    return events[-max_events:]


def format_event_timestamp(timestamp_value: object) -> str:
    if isinstance(timestamp_value, int):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp_value))
    return "unknown-time"


def security_ai_alert(alert_key: str, message: str, cooldown_seconds: int = 120) -> None:
    now = time.time()
    last_alert = SECURITY_ALERT_COOLDOWNS.get(alert_key, 0.0)
    if now - last_alert < cooldown_seconds:
        return

    SECURITY_ALERT_COOLDOWNS[alert_key] = now
    print(f"[Security AI] {message}")
    log_security_event("security_alert", {"key": alert_key, "message": message})


def monitor_failed_login_activity(username: str) -> None:
    """Track failed logins and trigger anomaly alerts based on active thresholds."""
    normalized_username = username.strip()
    log_security_event("failed_login", {"username": normalized_username})

    recent_events = load_recent_security_events(SECURITY_RULE_WINDOW_SECONDS)
    failed_events = [
        event
        for event in recent_events
        if event.get("event") == "failed_login"
    ]
    by_username: dict[str, int] = {}
    for event in failed_events:
        details = event.get("details")
        candidate = "unknown"
        if isinstance(details, dict):
            parsed = str(details.get("username", "")).strip()
            if parsed:
                candidate = parsed
        by_username[candidate] = by_username.get(candidate, 0) + 1

    distinct_usernames = {
        user
        for user in by_username
        if user and user != "unknown"
    }
    max_single_user_attempts = max(by_username.values(), default=0)

    if (
        len(failed_events) >= ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD
        and len(distinct_usernames) >= 2
    ):
        security_ai_alert(
            "failed_login_burst",
            "High failed-login volume detected in the last 5 minutes.",
        )

    if max_single_user_attempts >= ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD:
        security_ai_alert(
            "failed_login_single_user_spike",
            "A single account is seeing repeated failed login attempts.",
        )

    if len(distinct_usernames) >= ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD:
        security_ai_alert(
            "failed_login_multi_user",
            "Multiple usernames are failing login attempts in a short window.",
        )


def monitor_vault_access_activity(action: str, key: Optional[str] = None) -> None:
    """Track vault access behavior and alert on unusual session patterns."""
    global SESSION_VAULT_BURST_COUNT
    global SESSION_VAULT_KEY_SPIKE_COUNT

    now = time.time()
    log_security_event("vault_access", {"action": action, "key": key or ""})

    if action == "list_keys":
        return

    SESSION_VAULT_ACCESS_TIMESTAMPS.append(now)
    while (
        SESSION_VAULT_ACCESS_TIMESTAMPS
        and now - SESSION_VAULT_ACCESS_TIMESTAMPS[0] > ACTIVE_SECURITY_VAULT_BURST_SECONDS
    ):
        SESSION_VAULT_ACCESS_TIMESTAMPS.popleft()

    if len(SESSION_VAULT_ACCESS_TIMESTAMPS) >= ACTIVE_SECURITY_VAULT_BURST_THRESHOLD:
        SESSION_VAULT_BURST_COUNT += 1
    else:
        SESSION_VAULT_BURST_COUNT = 0

    if SESSION_VAULT_BURST_COUNT >= ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS:
        security_ai_alert(
            "vault_access_burst",
            "Unusual vault access rate detected in the current session.",
            cooldown_seconds=90,
        )
        SESSION_VAULT_BURST_COUNT = 0

    if key:
        normalized_key = key.strip()
        if normalized_key:
            SESSION_VAULT_KEY_EVENTS.append((now, normalized_key))
            while SESSION_VAULT_KEY_EVENTS and now - SESSION_VAULT_KEY_EVENTS[0][0] > ACTIVE_SECURITY_VAULT_BURST_SECONDS:
                SESSION_VAULT_KEY_EVENTS.popleft()

            unique_keys = {event_key for _, event_key in SESSION_VAULT_KEY_EVENTS}
            if len(unique_keys) >= ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD:
                SESSION_VAULT_KEY_SPIKE_COUNT += 1
            else:
                SESSION_VAULT_KEY_SPIKE_COUNT = 0

            if SESSION_VAULT_KEY_SPIKE_COUNT >= ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS:
                security_ai_alert(
                    "vault_unique_key_spike",
                    "Many different vault keys were accessed quickly. Review for unusual activity.",
                    cooldown_seconds=120,
                )
                SESSION_VAULT_KEY_SPIKE_COUNT = 0


def monitor_sensitive_action_failure(event_name: str) -> None:
    log_security_event(event_name)
    security_ai_alert(
        f"{event_name}_alert",
        "Sensitive action failed verification and was blocked.",
        cooldown_seconds=45,
    )


def prompt_password_masked(message: str, mask_char: str = "#") -> Optional[str]:
    """Read sensitive input with masked terminal feedback and safe fallbacks."""
    if not sys.stdin.isatty():
        return prompt(message)

    if not HAS_TERMIOS and HAS_MSVCRT:
        print(message, end="", flush=True)
        chars: list[str] = []
        try:
            while True:
                char = msvcrt.getwch()
                if char in {"\r", "\n"}:
                    print()
                    return "".join(chars).strip()
                if char == "\x03":
                    raise KeyboardInterrupt
                if char == "\x04":
                    raise EOFError
                if char in {"\x08", "\x7f"}:
                    if chars:
                        chars.pop()
                        print("\b \b", end="", flush=True)
                    continue
                if char in {"\x00", "\xe0"}:
                    msvcrt.getwch()
                    continue
                if char.isprintable():
                    chars.append(char)
                    print(mask_char, end="", flush=True)
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled.")
            return None

    if not HAS_TERMIOS:
        try:
            return getpass.getpass(message).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled.")
            return None

    print(message, end="", flush=True)
    chars: list[str] = []
    file_descriptor = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(file_descriptor)
    except (termios.error, OSError):
        try:
            return getpass.getpass(message).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled.")
            return None

    try:
        tty.setraw(file_descriptor)
        while True:
            char = sys.stdin.read(1)
            if char in {"\n", "\r"}:
                print()
                return "".join(chars).strip()
            if char == "\x03":
                raise KeyboardInterrupt
            if char == "\x04":
                raise EOFError
            if char in {"\x7f", "\b"}:
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
                continue

            if char.isprintable():
                chars.append(char)
                print(mask_char, end="", flush=True)
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None
    finally:
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, old_settings)


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash a password using PBKDF2-SHA256 with per-password salt."""
    password_bytes = password.encode("utf-8")
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return f"{PASSWORD_HASH_PREFIX}${PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash string."""
    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_HASH_PREFIX:
        return False

    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])
    except ValueError:
        return False

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def is_valid_hash_format(stored_hash: str) -> bool:
    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_HASH_PREFIX:
        return False
    try:
        int(parts[1])
        bytes.fromhex(parts[2])
        bytes.fromhex(parts[3])
    except ValueError:
        return False
    return True


def default_credentials() -> dict[str, object]:
    return {
        "username": DEFAULT_USERNAME,
        "password_hash": hash_password(DEFAULT_PASSWORD),
        "vault_salt": os.urandom(16).hex(),
        "max_login_attempts": DEFAULT_MAX_LOGIN_ATTEMPTS,
        "lockout_seconds": DEFAULT_LOCKOUT_SECONDS,
        "two_step_enabled": DEFAULT_TWO_STEP_ENABLED,
        "two_step_method": DEFAULT_TWO_STEP_METHOD,
        "security_ai_sensitivity": DEFAULT_SECURITY_AI_SENSITIVITY,
        "two_step_secret_encrypted": "",
        "two_step_custom_hash": "",
        "backup_code_hashes": [],
    }


def clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def to_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    return default


def is_two_step_enabled(credentials: dict[str, object]) -> bool:
    return to_bool(
        credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED),
        DEFAULT_TWO_STEP_ENABLED,
    )


def configured_two_step_method(credentials: dict[str, object]) -> str:
    return normalize_two_step_method(
        credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD)
    )


def set_session_password(password: Optional[str]) -> None:
    global SESSION_PASSWORD
    global SESSION_VAULT_BURST_COUNT
    global SESSION_VAULT_KEY_SPIKE_COUNT

    SESSION_PASSWORD = password
    if password is None:
        SESSION_VAULT_ACCESS_TIMESTAMPS.clear()
        SESSION_VAULT_KEY_EVENTS.clear()
        SESSION_VAULT_BURST_COUNT = 0
        SESSION_VAULT_KEY_SPIKE_COUNT = 0


def get_session_password() -> Optional[str]:
    return SESSION_PASSWORD


def normalize_vault_salt(salt: object) -> str:
    candidate = str(salt).strip().lower()
    if len(candidate) == 32 and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return os.urandom(16).hex()


def derive_encryption_keys(password: str, vault_salt_hex: str) -> tuple[bytes, bytes]:
    """Derive encryption and MAC keys from the session password and vault salt."""
    salt = bytes.fromhex(vault_salt_hex)
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
        dklen=64,
    )
    return key_material[:32], key_material[32:]


def xor_keystream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(value ^ output[index] for index, value in enumerate(data))


def encrypt_text_with_password(plain_text: str, password: str, vault_salt_hex: str) -> str:
    """Encrypt and authenticate plaintext using derived keys and random nonce."""
    encryption_key, mac_key = derive_encryption_keys(password, vault_salt_hex)
    nonce = os.urandom(16)
    plain_bytes = plain_text.encode("utf-8")
    cipher_bytes = xor_keystream(plain_bytes, encryption_key, nonce)
    tag = hmac.new(mac_key, nonce + cipher_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(nonce + cipher_bytes + tag)
    return token.decode("utf-8")


def decrypt_text_with_password(cipher_text: str, password: str, vault_salt_hex: str) -> Optional[str]:
    """Decrypt and verify ciphertext integrity with password-derived keys."""
    encryption_key, mac_key = derive_encryption_keys(password, vault_salt_hex)
    try:
        token_bytes = base64.urlsafe_b64decode(cipher_text.encode("utf-8"))
    except (ValueError, TypeError):
        return None

    if len(token_bytes) < 16 + 32:
        return None

    nonce = token_bytes[:16]
    tag = token_bytes[-32:]
    cipher_bytes = token_bytes[16:-32]
    expected_tag = hmac.new(mac_key, nonce + cipher_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        return None

    plain_bytes = xor_keystream(cipher_bytes, encryption_key, nonce)
    try:
        return plain_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def password_strength_issues(password: str) -> list[str]:
    issues: list[str] = []
    if len(password) < 8:
        issues.append("at least 8 characters")
    if not any(ch.islower() for ch in password):
        issues.append("one lowercase letter")
    if not any(ch.isupper() for ch in password):
        issues.append("one uppercase letter")
    if not any(ch.isdigit() for ch in password):
        issues.append("one number")
    if not any(not ch.isalnum() for ch in password):
        issues.append("one symbol")
    return issues


def is_deprecated_default_login(credentials: dict[str, object]) -> bool:
    username = str(credentials.get("username", "")).strip()
    password_hash = str(credentials.get("password_hash", "")).strip()
    return username == DEFAULT_USERNAME and verify_password(DEFAULT_PASSWORD, password_hash)


def decrypt_two_step_secret_for_password(credentials: dict[str, object], password: str) -> Optional[str]:
    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    encrypted_secret = str(credentials.get("two_step_secret_encrypted", "")).strip()
    if encrypted_secret:
        return decrypt_text_with_password(encrypted_secret, password, vault_salt)

    legacy_plain_secret = normalize_two_step_secret(credentials.get("_legacy_two_step_secret", ""))
    if legacy_plain_secret:
        return legacy_plain_secret
    return ""


def encrypt_two_step_secret_for_password(credentials: dict[str, object], plain_secret: str, password: str) -> str:
    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    credentials["vault_salt"] = vault_salt
    return encrypt_text_with_password(plain_secret, password, vault_salt)


def normalize_recovery_code(code: str) -> str:
    return code.strip().replace("-", "").replace(" ", "").upper()


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def generate_backup_recovery_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes: list[str] = []
    while len(codes) < count:
        first = "".join(alphabet[b % len(alphabet)] for b in os.urandom(4))
        second = "".join(alphabet[b % len(alphabet)] for b in os.urandom(4))
        candidate = f"{first}-{second}"
        if candidate not in codes:
            codes.append(candidate)
    return codes


def normalize_backup_code_hashes(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    for value in values:
        text = str(value).strip().lower()
        if len(text) == 64 and all(ch in "0123456789abcdef" for ch in text):
            normalized.append(text)
    return normalized


def normalize_two_step_secret(secret: object) -> str:
    candidate = str(secret).strip().replace(" ", "").upper()
    if not candidate:
        return ""
    padding = "=" * ((8 - len(candidate) % 8) % 8)
    try:
        base64.b32decode(candidate + padding, casefold=True)
    except (ValueError, TypeError):
        return ""
    return candidate


def normalize_two_step_method(method: object) -> str:
    candidate = str(method).strip().lower()
    if candidate in {"totp", "custom_code"}:
        return candidate
    return DEFAULT_TWO_STEP_METHOD


def generate_two_step_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def provisioning_uri(username: str, secret: str) -> str:
    issuer = "Data Bank"
    label = quote(f"{issuer}:{username}")
    issuer_q = quote(issuer)
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer_q}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def generate_totp_code(secret: str, for_time: Optional[int] = None) -> str:
    normalized_secret = normalize_two_step_secret(secret)
    if not normalized_secret:
        return ""
    if for_time is None:
        for_time = int(time.time())

    padding = "=" * ((8 - len(normalized_secret) % 8) % 8)
    key = base64.b32decode(normalized_secret + padding, casefold=True)
    counter = int(for_time // 30)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    candidate = code.strip()
    if len(candidate) != 6 or not candidate.isdigit():
        return False

    now = int(time.time())
    for delta in range(-window, window + 1):
        if hmac.compare_digest(generate_totp_code(secret, now + delta * 30), candidate):
            return True
    return False


def setup_two_step_verification(credentials: dict[str, object]) -> bool:
    print("\nTwo-Step Verification Setup")
    print("1) Use your own custom verification code (recommended)")
    print("2) Use authenticator app (TOTP)")
    method_choice = prompt("Choose method (1/2, default 1): ")
    method = "totp" if method_choice == "2" else "custom_code"

    username = str(credentials.get("username", DEFAULT_USERNAME)).strip() or DEFAULT_USERNAME
    secret = ""
    custom_hash = ""
    session_password = get_session_password()

    if session_password is None:
        print("Two-step setup requires an active authenticated session.")
        return False

    if method == "totp":
        secret = generate_two_step_secret()

        print("Add this secret to your authenticator app:")
        print(secret)
        print("Or use this manual URI:")
        print(provisioning_uri(username, secret))

        verification_code = prompt("Enter the current 6-digit code from your app: ")
        if verification_code is None:
            print("Two-step setup cancelled.")
            return False
        if not verify_totp_code(secret, verification_code):
            print("Invalid verification code. Two-step was not enabled.")
            return False
    else:
        print("Set a custom 2-step verification code (letters/numbers, at least 6 chars).")
        first_code = prompt("Enter custom 2-step code: ")
        if first_code is None:
            print("Two-step setup cancelled.")
            return False
        second_code = prompt("Confirm custom 2-step code: ")
        if second_code is None:
            print("Two-step setup cancelled.")
            return False

        normalized_first = first_code.strip()
        normalized_second = second_code.strip()
        if len(normalized_first) < 6:
            print("Custom 2-step code must be at least 6 characters.")
            return False
        if normalized_first != normalized_second:
            print("Custom 2-step code confirmation did not match.")
            return False

        custom_hash = hash_password(normalized_first)

    backup_codes = generate_backup_recovery_codes()
    backup_code_hashes = [hash_recovery_code(code) for code in backup_codes]

    credentials["two_step_enabled"] = True
    credentials["two_step_method"] = method
    if method == "totp":
        credentials["two_step_secret_encrypted"] = encrypt_two_step_secret_for_password(
            credentials,
            secret,
            session_password,
        )
    else:
        credentials["two_step_secret_encrypted"] = ""
    credentials["two_step_custom_hash"] = custom_hash
    credentials["backup_code_hashes"] = backup_code_hashes
    credentials.pop("_legacy_two_step_secret", None)
    if save_credentials(credentials):
        print("Two-step verification enabled.")
        print("Backup recovery codes (shown once, save them now):")
        for index, code in enumerate(backup_codes, start=1):
            print(f"{index}. {code}")
        return True

    print("Could not save two-step verification settings.")
    return False


def authorize_sensitive_security_action(credentials: dict[str, object]) -> bool:
    """Require strong re-authentication for sensitive security operations."""
    current_password = prompt_password_masked("Confirm current password: ")
    if current_password is None:
        print("Security action cancelled.")
        return False
    if not verify_password(current_password, str(credentials.get("password_hash", ""))):
        print("Password confirmation failed.")
        return False

    if is_two_step_enabled(credentials):
        method = configured_two_step_method(credentials)
        two_step_code = prompt("Enter current 2-step verification code: ")
        if two_step_code is None:
            print("Security action cancelled.")
            return False

        if method == "totp":
            two_step_secret = decrypt_two_step_secret_for_password(credentials, current_password)
            if not two_step_secret:
                print("Two-step configuration is invalid.")
                return False
            if not verify_totp_code(two_step_secret, two_step_code):
                print("Two-step verification failed.")
                return False
        else:
            custom_hash = str(credentials.get("two_step_custom_hash", "")).strip()
            if not is_valid_hash_format(custom_hash):
                print("Two-step configuration is invalid.")
                return False
            if not verify_password(two_step_code, custom_hash):
                print("Two-step verification failed.")
                return False

    return True


def regenerate_backup_recovery_codes(credentials: dict[str, object]) -> bool:
    if not is_two_step_enabled(credentials):
        print("Two-step verification is not enabled.")
        return False

    if not authorize_sensitive_security_action(credentials):
        return False

    backup_codes = generate_backup_recovery_codes()
    credentials["backup_code_hashes"] = [hash_recovery_code(code) for code in backup_codes]

    if save_credentials(credentials):
        print("Backup recovery codes regenerated.")
        print("New backup recovery codes (shown once, save them now):")
        for index, code in enumerate(backup_codes, start=1):
            print(f"{index}. {code}")
        return True

    print("Could not save regenerated backup recovery codes.")
    return False


def load_credentials() -> dict[str, object]:
    """Load and normalize credentials/config, including legacy migration paths."""
    if not CONFIG_FILE.exists():
        defaults = default_credentials()
        save_credentials(defaults)
        return defaults

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                legacy_device_field_present = "device_fingerprint" in data
                username = str(data.get("username", "")).strip()
                password_hash = str(data.get("password_hash", "")).strip()
                legacy_password = str(data.get("password", "")).strip()
                max_login_attempts = clamp_int(
                    data.get("max_login_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS),
                    DEFAULT_MAX_LOGIN_ATTEMPTS,
                    MIN_LOGIN_ATTEMPTS,
                    MAX_LOGIN_ATTEMPTS,
                )
                lockout_seconds = clamp_int(
                    data.get("lockout_seconds", DEFAULT_LOCKOUT_SECONDS),
                    DEFAULT_LOCKOUT_SECONDS,
                    MIN_LOCKOUT_SECONDS,
                    MAX_LOCKOUT_SECONDS,
                )
                two_step_enabled = to_bool(
                    data.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED),
                    DEFAULT_TWO_STEP_ENABLED,
                )
                two_step_method = normalize_two_step_method(
                    data.get("two_step_method", DEFAULT_TWO_STEP_METHOD)
                )
                security_ai_sensitivity = normalize_security_ai_sensitivity(
                    data.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
                )
                vault_salt = normalize_vault_salt(data.get("vault_salt", ""))
                two_step_secret_encrypted = str(data.get("two_step_secret_encrypted", "")).strip()
                legacy_two_step_secret = normalize_two_step_secret(data.get("two_step_secret", ""))
                two_step_custom_hash = str(data.get("two_step_custom_hash", "")).strip()
                backup_code_hashes = normalize_backup_code_hashes(data.get("backup_code_hashes", []))
                if two_step_method == "custom_code" and not is_valid_hash_format(two_step_custom_hash):
                    two_step_enabled = False

                if username and password_hash and is_valid_hash_format(password_hash):
                    credentials = {
                        "username": username,
                        "password_hash": password_hash,
                        "vault_salt": vault_salt,
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
                        "security_ai_sensitivity": security_ai_sensitivity,
                        "two_step_secret_encrypted": two_step_secret_encrypted,
                        "two_step_custom_hash": two_step_custom_hash,
                        "backup_code_hashes": backup_code_hashes,
                    }
                    if legacy_two_step_secret:
                        credentials["_legacy_two_step_secret"] = legacy_two_step_secret
                    if legacy_device_field_present:
                        save_credentials(credentials)
                    return credentials

                if username and legacy_password:
                    migrated = {
                        "username": username,
                        "password_hash": hash_password(legacy_password),
                        "vault_salt": vault_salt,
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
                        "security_ai_sensitivity": security_ai_sensitivity,
                        "two_step_secret_encrypted": two_step_secret_encrypted,
                        "two_step_custom_hash": two_step_custom_hash,
                        "backup_code_hashes": backup_code_hashes,
                    }
                    if legacy_two_step_secret:
                        migrated["_legacy_two_step_secret"] = legacy_two_step_secret
                    save_credentials(migrated)
                    print("Credentials migrated to hashed password format.")
                    return migrated
    except (json.JSONDecodeError, OSError):
        pass

    defaults = default_credentials()
    save_credentials(defaults)
    return defaults


def save_credentials(credentials: dict[str, object]) -> bool:
    """Persist normalized credentials and security configuration safely."""
    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    normalized = {
        "username": str(credentials.get("username", "")).strip() or DEFAULT_USERNAME,
        "password_hash": str(credentials.get("password_hash", "")).strip(),
        "vault_salt": vault_salt,
        "max_login_attempts": clamp_int(
            credentials.get("max_login_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS),
            DEFAULT_MAX_LOGIN_ATTEMPTS,
            MIN_LOGIN_ATTEMPTS,
            MAX_LOGIN_ATTEMPTS,
        ),
        "lockout_seconds": clamp_int(
            credentials.get("lockout_seconds", DEFAULT_LOCKOUT_SECONDS),
            DEFAULT_LOCKOUT_SECONDS,
            MIN_LOCKOUT_SECONDS,
            MAX_LOCKOUT_SECONDS,
        ),
        "two_step_enabled": to_bool(
            credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED),
            DEFAULT_TWO_STEP_ENABLED,
        ),
        "two_step_method": normalize_two_step_method(
            credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD)
        ),
        "security_ai_sensitivity": normalize_security_ai_sensitivity(
            credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
        ),
        "two_step_secret_encrypted": str(credentials.get("two_step_secret_encrypted", "")).strip(),
        "two_step_custom_hash": str(credentials.get("two_step_custom_hash", "")).strip(),
        "backup_code_hashes": normalize_backup_code_hashes(credentials.get("backup_code_hashes", [])),
    }
    if not is_valid_hash_format(normalized["password_hash"]):
        normalized["password_hash"] = hash_password(DEFAULT_PASSWORD)
    if normalized["two_step_method"] == "totp" and normalized["two_step_enabled"]:
        if not normalized["two_step_secret_encrypted"]:
            legacy_plain_secret = normalize_two_step_secret(credentials.get("_legacy_two_step_secret", ""))
            session_password = get_session_password()
            if legacy_plain_secret and session_password:
                normalized["two_step_secret_encrypted"] = encrypt_text_with_password(
                    legacy_plain_secret,
                    session_password,
                    vault_salt,
                )
            else:
                normalized["two_step_enabled"] = False
                normalized["backup_code_hashes"] = []
    if (
        normalized["two_step_method"] == "custom_code"
        and normalized["two_step_enabled"]
        and not is_valid_hash_format(normalized["two_step_custom_hash"])
    ):
        normalized["two_step_enabled"] = False
        normalized["backup_code_hashes"] = []
    if not normalized["two_step_enabled"]:
        normalized["two_step_secret_encrypted"] = ""
        normalized["two_step_custom_hash"] = ""
        normalized["backup_code_hashes"] = []

    try:
        with CONFIG_FILE.open("w", encoding="utf-8") as file:
            json.dump(normalized, file, indent=2)
        return True
    except OSError as error:
        print(f"Could not save credentials to '{CONFIG_FILE}': {error}")
        return False


def load_vault(credentials: dict[str, object]) -> dict[str, str]:
    """Load encrypted vault data for the authenticated session password."""
    if not DATA_FILE.exists():
        return {}

    session_password = get_session_password()
    if session_password is None:
        print("Vault cannot be loaded before authentication.")
        return {}

    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))

    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                ciphertext = data.get("ciphertext")
                if isinstance(ciphertext, str) and ciphertext:
                    decrypted = decrypt_text_with_password(ciphertext, session_password, vault_salt)
                    if decrypted is None:
                        print("Vault could not be decrypted with the current session password.")
                        return {}
                    decoded = json.loads(decrypted)
                    if isinstance(decoded, dict):
                        return {str(key): str(value) for key, value in decoded.items()}
                    return {}

                legacy_vault = {str(key): str(value) for key, value in data.items()}
                save_vault(legacy_vault, credentials)
                return legacy_vault
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_vault(vault: dict[str, str], credentials: dict[str, object]) -> bool:
    """Encrypt and persist the current vault state to disk."""
    session_password = get_session_password()
    if session_password is None:
        print("Vault could not be saved: no authenticated session password is available.")
        return False

    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    credentials["vault_salt"] = vault_salt
    plain_payload = json.dumps(vault, indent=2)
    ciphertext = encrypt_text_with_password(plain_payload, session_password, vault_salt)

    try:
        with DATA_FILE.open("w", encoding="utf-8") as file:
            json.dump({"version": 1, "ciphertext": ciphertext}, file, indent=2)
        return True
    except OSError as error:
        print(f"Could not save vault data to '{DATA_FILE}': {error}")
        return False


def login(credentials: dict[str, object]) -> bool:
    """Authenticate user identity and enforce optional 2-step verification."""
    set_session_password(None)
    print("=== DATA BANK ===")
    print("Please log in to continue.")
    max_attempts = clamp_int(
        credentials.get("max_login_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS),
        DEFAULT_MAX_LOGIN_ATTEMPTS,
        MIN_LOGIN_ATTEMPTS,
        MAX_LOGIN_ATTEMPTS,
    )
    lockout_seconds = clamp_int(
        credentials.get("lockout_seconds", DEFAULT_LOCKOUT_SECONDS),
        DEFAULT_LOCKOUT_SECONDS,
        MIN_LOCKOUT_SECONDS,
        MAX_LOCKOUT_SECONDS,
    )

    for attempt in range(1, max_attempts + 1):
        entered_username = prompt("Username: ")
        if entered_username is None:
            return False
        entered_password = prompt_password_masked("Password: ")
        if entered_password is None:
            return False

        is_logged_in = (
            entered_username == credentials["username"]
            and verify_password(entered_password, credentials["password_hash"])
        )
        if is_logged_in:
            log_security_event("login_success", {"username": entered_username.strip()})
            set_session_password(entered_password)
            if is_two_step_enabled(credentials):
                method = configured_two_step_method(credentials)
                two_step_code = prompt("Enter 2-step verification code: ")
                if two_step_code is None:
                    set_session_password(None)
                    return False

                verified = False
                if method == "totp":
                    two_step_secret = decrypt_two_step_secret_for_password(credentials, entered_password)
                    if not two_step_secret:
                        print("Two-step is enabled but setup is invalid. Please reconfigure it.")
                        is_logged_in = False
                    else:
                        verified = verify_totp_code(two_step_secret, two_step_code)
                else:
                    custom_hash = str(credentials.get("two_step_custom_hash", "")).strip()
                    if not is_valid_hash_format(custom_hash):
                        print("Two-step is enabled but setup is invalid. Please reconfigure it.")
                        is_logged_in = False
                    else:
                        verified = verify_password(two_step_code, custom_hash)

                if verified:
                    print("Two-step verification successful.")
                else:
                    input_hash = hash_recovery_code(two_step_code)
                    backup_hashes = normalize_backup_code_hashes(
                        credentials.get("backup_code_hashes", [])
                    )
                    if input_hash and input_hash in backup_hashes:
                        backup_hashes.remove(input_hash)
                        credentials["backup_code_hashes"] = backup_hashes
                        if save_credentials(credentials):
                            print("Backup recovery code accepted.")
                            print(f"Remaining backup codes: {len(backup_hashes)}")
                        else:
                            print("Backup code matched, but could not update storage safely.")
                            is_logged_in = False
                    else:
                        print("Invalid 2-step verification code.")
                        is_logged_in = False

                if (
                    is_logged_in
                    and method == "totp"
                    and credentials.get("_legacy_two_step_secret")
                ):
                    credentials["two_step_secret_encrypted"] = encrypt_two_step_secret_for_password(
                        credentials,
                        str(credentials.get("_legacy_two_step_secret", "")),
                        entered_password,
                    )
                    credentials.pop("_legacy_two_step_secret", None)
                    save_credentials(credentials)
            else:
                enable_two_step = prompt(
                    "Would you like to enable two-step verification for future logins? (y/N): "
                )
                if enable_two_step and enable_two_step.lower() in {"y", "yes"}:
                    setup_two_step_verification(credentials)
            if is_logged_in:
                print("Login successful.")
                print("Authentication completed.")
                return True
            set_session_password(None)
            monitor_sensitive_action_failure("login_second_factor_failed")
        else:
            monitor_failed_login_activity(entered_username)

        attempts_left = max_attempts - attempt
        if attempts_left > 0:
            print(
                "Login failed. Invalid username or password. "
                f"Attempts left: {attempts_left}."
            )
        else:
            if lockout_seconds > 0:
                print(
                    "Too many failed attempts. "
                    f"Please wait {lockout_seconds} seconds before trying again."
                )
                time.sleep(lockout_seconds)
            else:
                print("Too many failed attempts.")
            return False

    return False


def show_menu() -> None:
    print("\nChoose an Option:")
    print("1) Add Data")
    print("2) List all keys")
    print("3) Retrieve Data by Key")
    print("4) Delete Data by Key")
    print("5) Change Username/Password")
    print("6) Security Settings")
    print("7) Remove Data-bank Files (Data-bank files only)")
    print("8) Security AI Report (requires heavy auth)")
    print("9) Exit")


def view_security_ai_report(credentials: dict[str, object]) -> None:
    """Show a protected summary of Security AI detections and risk events."""
    print("\nSecurity AI Report")
    print("This report requires password confirmation")
    print("and 2-step verification if it is enabled.")

    if not authorize_sensitive_security_action(credentials):
        monitor_sensitive_action_failure("security_report_access_denied")
        print("Access denied: unable to verify identity for Security AI report.")
        return

    events = load_security_events(1000)
    if not events:
        print("No security events were found yet.")
        return

    now = int(time.time())
    cutoff_24h = now - 24 * 60 * 60
    recent_events = [
        event
        for event in events
        if isinstance(event.get("timestamp"), int) and event["timestamp"] >= cutoff_24h
    ]

    failed_logins = [event for event in recent_events if event.get("event") == "failed_login"]
    ai_alerts = [event for event in recent_events if event.get("event") == "security_alert"]
    blocked_sensitive = [
        event
        for event in recent_events
        if str(event.get("event", "")).endswith("_failed")
        or str(event.get("event", "")).endswith("_cancelled")
        or event.get("event") in {"login_second_factor_failed", "security_report_access_denied"}
    ]

    print("\nLast 24 hours summary:")
    print(f"- Failed login attempts: {len(failed_logins)}")
    print(f"- AI detections/alerts: {len(ai_alerts)}")
    print(f"- Blocked sensitive actions: {len(blocked_sensitive)}")

    if failed_logins:
        by_username: dict[str, int] = {}
        for event in failed_logins:
            details = event.get("details")
            username = "unknown"
            if isinstance(details, dict):
                candidate = str(details.get("username", "")).strip()
                if candidate:
                    username = candidate
            by_username[username] = by_username.get(username, 0) + 1

        print("\nFailed logins by username (last 24h):")
        for username, count in sorted(by_username.items(), key=lambda pair: pair[1], reverse=True)[:10]:
            print(f"- {username}: {count}")

    print("\nRecent AI detections (last 24h):")
    if ai_alerts:
        for event in ai_alerts[-10:]:
            details = event.get("details")
            message = "Security alert triggered."
            if isinstance(details, dict):
                candidate = str(details.get("message", "")).strip()
                if candidate:
                    message = candidate
            print(f"- {format_event_timestamp(event.get('timestamp'))}: {message}")
    else:
        print("- None")


def add_data(vault: dict[str, str], credentials: dict[str, object]) -> None:
    key = prompt("Enter key: ")
    if key is None:
        return
    value = prompt("Enter value: ")
    if value is None:
        return

    if not key:
        print("Key cannot be empty.")
        return

    vault[key] = value
    if save_vault(vault, credentials):
        print(f"Saved data for key '{key}'.")
    else:
        print("Data could not be saved.")


def list_data(vault: dict[str, str]) -> None:
    monitor_vault_access_activity("list_keys")
    if not vault:
        print("Vault is empty.")
        return

    print("Stored keys:")
    for key in sorted(vault.keys()):
        print(f"- {key}")


def retrieve_data(vault: dict[str, str]) -> None:
    key = prompt("Enter key to retrieve: ")
    if key is None:
        return
    if key in vault:
        monitor_vault_access_activity("retrieve_key", key)
        print(f"Value: {vault[key]}")
    else:
        monitor_vault_access_activity("retrieve_missing_key", key)
        print("No data found for that key.")


def delete_data(vault: dict[str, str], credentials: dict[str, object]) -> None:
    key = prompt("Enter key to delete: ")
    if key is None:
        return
    if key in vault:
        monitor_vault_access_activity("delete_key", key)
        original_value = vault[key]
        del vault[key]
        if save_vault(vault, credentials):
            print(f"Deleted key '{key}'.")
        else:
            vault[key] = original_value
            print("Delete failed because data could not be saved.")
    else:
        print("No data found for that key.")


def change_credentials(credentials: dict[str, object], vault: dict[str, str]) -> None:
    print("\nChange Credentials")
    current_password = prompt_password_masked("Enter current password: ")
    if current_password is None:
        return
    if not verify_password(current_password, credentials["password_hash"]):
        print("Current password is incorrect.")
        return

    new_username = prompt("New username: ")
    if new_username is None:
        return
    new_password = prompt_password_masked("New password: ")
    if new_password is None:
        return

    if not new_username or not new_password:
        print("Username and password cannot be empty.")
        return

    strength_issues = password_strength_issues(new_password)
    if strength_issues:
        print("Password is not strong enough. Include:")
        for issue in strength_issues:
            print(f"- {issue}")
        return

    reencrypted_totp_secret = ""
    if (
        is_two_step_enabled(credentials)
        and configured_two_step_method(credentials) == "totp"
    ):
        current_totp_secret = decrypt_two_step_secret_for_password(credentials, current_password)
        if not current_totp_secret:
            print("Credentials were not changed because the TOTP secret could not be decrypted.")
            return
        reencrypted_totp_secret = encrypt_two_step_secret_for_password(
            credentials,
            current_totp_secret,
            new_password,
        )

    credentials["username"] = new_username
    credentials["password_hash"] = hash_password(new_password)
    if reencrypted_totp_secret:
        credentials["two_step_secret_encrypted"] = reencrypted_totp_secret
    set_session_password(new_password)

    saved_credentials = save_credentials(credentials)
    saved_vault = save_vault(vault, credentials)
    if saved_credentials and saved_vault:
        print("Credentials updated and saved.")
        return

    print("Credentials were only partially saved. Please verify your settings.")


def change_security_settings(credentials: dict[str, object]) -> None:
    """Update security controls and enforce auth for high-risk setting changes."""
    current_attempts = clamp_int(
        credentials.get("max_login_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS),
        DEFAULT_MAX_LOGIN_ATTEMPTS,
        MIN_LOGIN_ATTEMPTS,
        MAX_LOGIN_ATTEMPTS,
    )
    current_lockout = clamp_int(
        credentials.get("lockout_seconds", DEFAULT_LOCKOUT_SECONDS),
        DEFAULT_LOCKOUT_SECONDS,
        MIN_LOCKOUT_SECONDS,
        MAX_LOCKOUT_SECONDS,
    )

    print("\nSecurity Settings")
    print(f"Current Max Login Attempts: {current_attempts}")
    print(f"Current Lockout Seconds: {current_lockout}")
    print(
        "Current Two-Step Verification: "
        f"{'Enabled' if is_two_step_enabled(credentials) else 'Disabled'}"
    )
    print(
        "Available Backup Recovery Codes: "
        f"{len(normalize_backup_code_hashes(credentials.get('backup_code_hashes', [])))}"
    )
    current_ai_sensitivity = normalize_security_ai_sensitivity(
        credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
    )
    print(f"Current Security AI Sensitivity: {current_ai_sensitivity}")

    new_attempts_input = prompt(
        f"New max login attempts ({MIN_LOGIN_ATTEMPTS}-{MAX_LOGIN_ATTEMPTS}, blank to keep): "
    )
    if new_attempts_input is None:
        return

    new_lockout_input = prompt(
        f"New lockout seconds ({MIN_LOCKOUT_SECONDS}-{MAX_LOCKOUT_SECONDS}, blank to keep): "
    )
    if new_lockout_input is None:
        return

    two_step_choice = prompt("Two-step verification (enable/disable/keep): ")
    if two_step_choice is None:
        return

    regen_choice = prompt("Regenerate backup recovery codes? (y/N): ")
    if regen_choice is None:
        return

    sensitivity_choice = prompt("Security AI sensitivity (high/normal/low/keep): ")
    if sensitivity_choice is None:
        return

    if (
        not new_attempts_input
        and not new_lockout_input
        and not two_step_choice
        and not regen_choice
        and not sensitivity_choice
    ):
        print("No changes made.")
        return

    if new_attempts_input:
        credentials["max_login_attempts"] = clamp_int(
            new_attempts_input,
            current_attempts,
            MIN_LOGIN_ATTEMPTS,
            MAX_LOGIN_ATTEMPTS,
        )

    if new_lockout_input:
        credentials["lockout_seconds"] = clamp_int(
            new_lockout_input,
            current_lockout,
            MIN_LOCKOUT_SECONDS,
            MAX_LOCKOUT_SECONDS,
        )

    choice = two_step_choice.strip().lower()
    if choice in {"enable", "on", "yes", "y"}:
        if is_two_step_enabled(credentials):
            print("Two-step verification is already enabled.")
        else:
            setup_two_step_verification(credentials)
    elif choice in {"disable", "off", "no", "n"}:
        confirm_disable = prompt(
            "Warning: Disabling two-step will remove all backup recovery codes. Continue? (y/N): "
        )
        if confirm_disable and confirm_disable.strip().lower() in {"y", "yes"}:
            if authorize_sensitive_security_action(credentials):
                credentials["two_step_enabled"] = False
                credentials["two_step_method"] = DEFAULT_TWO_STEP_METHOD
                credentials["two_step_secret_encrypted"] = ""
                credentials["two_step_custom_hash"] = ""
                credentials["backup_code_hashes"] = []
                credentials.pop("_legacy_two_step_secret", None)
                print("Two-step verification disabled.")
            else:
                print("Two-step verification remains enabled.")
        else:
            print("Disable action cancelled. Two-step verification remains enabled.")
    elif choice in {"", "keep"}:
        pass
    else:
        print("Unknown two-step choice. Keeping current setting.")

    if regen_choice.strip().lower() in {"y", "yes"}:
        regenerate_backup_recovery_codes(credentials)

    sensitivity_normalized = sensitivity_choice.strip().lower()
    if sensitivity_normalized in {"high", "normal", "low"}:
        if sensitivity_normalized != current_ai_sensitivity:
            print("Changing Security AI sensitivity requires full verification.")
            if not authorize_sensitive_security_action(credentials):
                monitor_sensitive_action_failure("security_ai_sensitivity_change_cancelled")
                print("AI sensitivity was not changed. Verification failed.")
            else:
                credentials["security_ai_sensitivity"] = sensitivity_normalized
                apply_security_ai_sensitivity(sensitivity_normalized)
                print(f"Security AI sensitivity set to {sensitivity_normalized}.")
        else:
            print("Security AI sensitivity is already set to that value.")
    elif sensitivity_normalized in {"", "keep"}:
        pass
    else:
        print("Unknown sensitivity choice. Keeping current sensitivity.")

    if save_credentials(credentials):
        print("Security settings updated.")
    else:
        print("Security settings were not saved.")


def show_security_policy(credentials: dict[str, object]) -> None:
    max_attempts = clamp_int(
        credentials.get("max_login_attempts", DEFAULT_MAX_LOGIN_ATTEMPTS),
        DEFAULT_MAX_LOGIN_ATTEMPTS,
        MIN_LOGIN_ATTEMPTS,
        MAX_LOGIN_ATTEMPTS,
    )
    lockout_seconds = clamp_int(
        credentials.get("lockout_seconds", DEFAULT_LOCKOUT_SECONDS),
        DEFAULT_LOCKOUT_SECONDS,
        MIN_LOCKOUT_SECONDS,
        MAX_LOCKOUT_SECONDS,
    )
    lockout_display = "disabled" if lockout_seconds == 0 else f"{lockout_seconds}s"
    two_step_status = (
        "enabled"
        if is_two_step_enabled(credentials)
        else "disabled"
    )
    two_step_method = configured_two_step_method(credentials)
    backup_count = len(normalize_backup_code_hashes(credentials.get("backup_code_hashes", [])))
    ai_sensitivity = normalize_security_ai_sensitivity(
        credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
    )
    print(
        "Active security policy: "
        f"max_login_attempts={max_attempts}, "
        f"lockout={lockout_display}, "
        f"two_step={two_step_status}, "
        f"two_step_method={two_step_method}, "
        f"backup_codes={backup_count}, "
        f"security_ai_sensitivity={ai_sensitivity}"
    )


def show_storage_info() -> None:
    print(f"Storage Folder: {STORAGE_DIR}")


def ensure_local_file_state(credentials: dict[str, object]) -> bool:
    if DATA_FILE.exists():
        try:
            with DATA_FILE.open("r", encoding="utf-8") as file:
                data = json.load(file)
            if isinstance(data, dict) and "ciphertext" not in data:
                print("Legacy vault data format detected; it will be auto-updated after login.")
        except (json.JSONDecodeError, OSError):
            print("Vault data file could not be validated at startup.")

    return True


def first_launch_account_setup(credentials: dict[str, object]) -> bool:
    print("\nFirst-Launch Account Setup")
    print("Create your Data-bank login now.")
    print("A custom username and password are required.")

    while True:
        new_username = prompt("New username: ")
        if new_username is None:
            print("Account setup cancelled.")
            return False

        if not new_username:
            print("Username cannot be empty.")
            continue

        new_password = prompt_password_masked("New password: ")
        if new_password is None:
            print("Account setup cancelled.")
            return False

        confirm_password = prompt_password_masked("Confirm new password: ")
        if confirm_password is None:
            print("Account setup cancelled.")
            return False

        strength_issues = password_strength_issues(new_password)
        if strength_issues:
            print("Password is not strong enough. Missing:")
            for issue in strength_issues:
                print(f"- {issue}")
            continue

        if new_password != confirm_password:
            print("Password confirmation did not match.")
            continue

        credentials["username"] = new_username
        credentials["password_hash"] = hash_password(new_password)
        if save_credentials(credentials):
            print("Account setup complete. Your new login credentials were saved.")
            return True

        print("Could not save account setup. Please try again.")


def enforce_non_default_login(credentials: dict[str, object]) -> bool:
    if not is_deprecated_default_login(credentials):
        return True

    print("\nSecurity update: default login credentials are no longer allowed.")
    print("Please create a new username and password now.")
    return first_launch_account_setup(credentials)


def remove_databank_files(credentials: dict[str, object]) -> bool:
    """Perform destructive cleanup of Data-bank files after strict verification."""
    print("\nRemove Data-bank Files")
    print("This removes only Data-bank files created by this program:")
    print(f"- {DATA_FILE}")
    print(f"- {CONFIG_FILE}")

    confirmation_phrase = "DELETE MY DATABANK DATA"
    typed_phrase = prompt(f"Type exactly '{confirmation_phrase}' to continue: ")
    if typed_phrase is None:
        monitor_sensitive_action_failure("remove_files_cancelled")
        print("Removal cancelled.")
        return False
    if typed_phrase != confirmation_phrase:
        monitor_sensitive_action_failure("remove_files_phrase_failed")
        print("Removal cancelled. Confirmation phrase did not match.")
        return False

    current_password = prompt_password_masked("Enter current password to confirm removal: ")
    if current_password is None:
        monitor_sensitive_action_failure("remove_files_password_cancelled")
        print("Removal cancelled.")
        return False
    if not verify_password(current_password, str(credentials.get("password_hash", ""))):
        monitor_sensitive_action_failure("remove_files_password_failed")
        print("Removal cancelled. Password verification failed.")
        return False

    removed_any = False
    for target in (DATA_FILE, CONFIG_FILE):
        try:
            if target.exists():
                target.unlink()
                removed_any = True
        except OSError as error:
            print(f"Could not remove '{target}': {error}")
            return False

    try:
        if STORAGE_DIR.exists() and STORAGE_DIR.is_dir() and not any(STORAGE_DIR.iterdir()):
            shutil.rmtree(STORAGE_DIR)
    except OSError:
        pass

    if removed_any:
        print("Data-bank files were removed successfully.")
    else:
        print("No Data-bank files were found to remove.")

    print("Final message: Data-bank cleanup completed. Exiting now.")
    return True


def main() -> None:
    show_storage_info()
    first_run = not CONFIG_FILE.exists()
    if first_run:
        print("First-time setup detected for Data-bank.")
        print(f"A storage folder is being used at: {STORAGE_DIR}")
        print("Data-bank will create required files for your account and vault data.")

    credentials = load_credentials()
    apply_security_ai_sensitivity(
        credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
    )
    if first_run:
        print(f"Created login/security config file: {CONFIG_FILE}")
        print(
            "Vault data file will be created automatically after your first saved entry: "
            f"{DATA_FILE}"
        )
        if not first_launch_account_setup(credentials):
            print("Data-bank requires custom credentials on first launch. Exiting.")
            try:
                CONFIG_FILE.unlink(missing_ok=True)
            except OSError:
                pass
            return

    if not enforce_non_default_login(credentials):
        print("Data-bank requires custom credentials before login. Exiting.")
        return

    if not ensure_local_file_state(credentials):
        print("Data-bank could not update required local file checks. Exiting.")
        return

    if not login(credentials):
        set_session_password(None)
        return
    show_security_policy(credentials)

    vault = load_vault(credentials)
    print(f"You currently have {len(vault)} data entr{'y' if len(vault) == 1 else 'ies'} in the vault.")

    while True:
        show_menu()
        choice = prompt("Enter your choice (1-9): ")
        if choice is None:
            print("Goodbye.")
            break

        if choice == "1":
            add_data(vault, credentials)
        elif choice == "2":
            list_data(vault)
        elif choice == "3":
            retrieve_data(vault)
        elif choice == "4":
            delete_data(vault, credentials)
        elif choice == "5":
            change_credentials(credentials, vault)
        elif choice == "6":
            change_security_settings(credentials)
        elif choice == "7":
            if remove_databank_files(credentials):
                break
        elif choice == "8":
            view_security_ai_report(credentials)
        elif choice == "9":
            print("You are being securely logged out of Data Bank. Goodbye.")
            set_session_password(None)
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, 4, 5, 6, 7, 8, or 9.")


if __name__ == "__main__":
    main()