from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
from pathlib import Path
import shutil
import time
from typing import Optional
from urllib.parse import quote


DEFAULT_USERNAME = "guest"
DEFAULT_PASSWORD = "11"
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 200_000
DEFAULT_MAX_LOGIN_ATTEMPTS = 3
DEFAULT_LOCKOUT_SECONDS = 30
DEFAULT_TWO_STEP_ENABLED = False
DEFAULT_TWO_STEP_METHOD = "custom_code"
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


def prompt(message: str) -> Optional[str]:
    try:
        return input(message).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return None


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
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


def current_device_fingerprint() -> str:
    node = platform.node().strip().lower() or "unknown-node"
    system = platform.system().strip().lower() or "unknown-system"
    release = platform.release().strip().lower() or "unknown-release"
    return f"{system}:{release}:{node}"


def default_credentials() -> dict[str, object]:
    return {
        "username": DEFAULT_USERNAME,
        "password_hash": hash_password(DEFAULT_PASSWORD),
        "device_fingerprint": current_device_fingerprint(),
        "vault_salt": os.urandom(16).hex(),
        "max_login_attempts": DEFAULT_MAX_LOGIN_ATTEMPTS,
        "lockout_seconds": DEFAULT_LOCKOUT_SECONDS,
        "two_step_enabled": DEFAULT_TWO_STEP_ENABLED,
        "two_step_method": DEFAULT_TWO_STEP_METHOD,
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


def set_session_password(password: Optional[str]) -> None:
    global SESSION_PASSWORD
    SESSION_PASSWORD = password


def get_session_password() -> Optional[str]:
    return SESSION_PASSWORD


def normalize_vault_salt(salt: object) -> str:
    candidate = str(salt).strip().lower()
    if len(candidate) == 32 and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return os.urandom(16).hex()


def derive_encryption_keys(password: str, vault_salt_hex: str) -> tuple[bytes, bytes]:
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
    encryption_key, mac_key = derive_encryption_keys(password, vault_salt_hex)
    nonce = os.urandom(16)
    plain_bytes = plain_text.encode("utf-8")
    cipher_bytes = xor_keystream(plain_bytes, encryption_key, nonce)
    tag = hmac.new(mac_key, nonce + cipher_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(nonce + cipher_bytes + tag)
    return token.decode("utf-8")


def decrypt_text_with_password(cipher_text: str, password: str, vault_salt_hex: str) -> Optional[str]:
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
    current_password = prompt("Confirm current password: ")
    if current_password is None:
        print("Security action cancelled.")
        return False
    if not verify_password(current_password, str(credentials.get("password_hash", ""))):
        print("Password confirmation failed.")
        return False

    if to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED):
        method = normalize_two_step_method(credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD))
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
    if not to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED):
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
    if not CONFIG_FILE.exists():
        defaults = default_credentials()
        save_credentials(defaults)
        return defaults

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
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
                device_fingerprint = str(data.get("device_fingerprint", "")).strip()
                two_step_method = normalize_two_step_method(
                    data.get("two_step_method", DEFAULT_TWO_STEP_METHOD)
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
                        "device_fingerprint": device_fingerprint,
                        "vault_salt": vault_salt,
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
                        "two_step_secret_encrypted": two_step_secret_encrypted,
                        "two_step_custom_hash": two_step_custom_hash,
                        "backup_code_hashes": backup_code_hashes,
                    }
                    if legacy_two_step_secret:
                        credentials["_legacy_two_step_secret"] = legacy_two_step_secret
                    return credentials

                if username and legacy_password:
                    migrated = {
                        "username": username,
                        "password_hash": hash_password(legacy_password),
                        "device_fingerprint": device_fingerprint,
                        "vault_salt": vault_salt,
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
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
    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    device_fingerprint = str(credentials.get("device_fingerprint", "")).strip() or current_device_fingerprint()
    normalized = {
        "username": str(credentials.get("username", "")).strip() or DEFAULT_USERNAME,
        "password_hash": str(credentials.get("password_hash", "")).strip(),
        "device_fingerprint": device_fingerprint,
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
        entered_password = prompt("Password: ")
        if entered_password is None:
            return False

        is_logged_in = (
            entered_username == credentials["username"]
            and verify_password(entered_password, credentials["password_hash"])
        )
        if is_logged_in:
            set_session_password(entered_password)
            if to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED):
                method = normalize_two_step_method(credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD))
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
    print("8) Exit")


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
        print(f"Value: {vault[key]}")
    else:
        print("No data found for that key.")


def delete_data(vault: dict[str, str], credentials: dict[str, object]) -> None:
    key = prompt("Enter key to delete: ")
    if key is None:
        return
    if key in vault:
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
    current_password = prompt("Enter current password: ")
    if current_password is None:
        return
    if not verify_password(current_password, credentials["password_hash"]):
        print("Current password is incorrect.")
        return

    new_username = prompt("New username: ")
    if new_username is None:
        return
    new_password = prompt("New password: ")
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
        to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED)
        and normalize_two_step_method(credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD)) == "totp"
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
        f"{'Enabled' if to_bool(credentials.get('two_step_enabled', DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED) else 'Disabled'}"
    )
    print(
        "Available Backup Recovery Codes: "
        f"{len(normalize_backup_code_hashes(credentials.get('backup_code_hashes', [])))}"
    )

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

    if not new_attempts_input and not new_lockout_input and not two_step_choice and not regen_choice:
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
        if to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED):
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
        if to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED)
        else "disabled"
    )
    two_step_method = normalize_two_step_method(credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD))
    backup_count = len(normalize_backup_code_hashes(credentials.get("backup_code_hashes", [])))
    print(
        "Active security policy: "
        f"max_login_attempts={max_attempts}, "
        f"lockout={lockout_display}, "
        f"two_step={two_step_status}, "
        f"two_step_method={two_step_method}, "
        f"backup_codes={backup_count}"
    )


def show_storage_info() -> None:
    print(f"Storage Folder: {STORAGE_DIR}")


def ensure_local_file_state(credentials: dict[str, object]) -> bool:
    expected_device = current_device_fingerprint()
    stored_device = str(credentials.get("device_fingerprint", "")).strip()
    needs_save = False

    if stored_device != expected_device:
        credentials["device_fingerprint"] = expected_device
        needs_save = True
        if stored_device:
            print("Detected device mismatch in config metadata. Updated to current device.")
        else:
            print("Added current device metadata to config.")

    if needs_save and not save_credentials(credentials):
        print("Could not update local file state in config.")
        return False

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

        new_password = prompt("New password: ")
        if new_password is None:
            print("Account setup cancelled.")
            return False

        confirm_password = prompt("Confirm new password: ")
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
    print("\nRemove Data-bank Files")
    print("This removes only Data-bank files created by this program:")
    print(f"- {DATA_FILE}")
    print(f"- {CONFIG_FILE}")

    confirmation_phrase = "DELETE MY DATABANK DATA"
    typed_phrase = prompt(f"Type exactly '{confirmation_phrase}' to continue: ")
    if typed_phrase is None:
        print("Removal cancelled.")
        return False
    if typed_phrase != confirmation_phrase:
        print("Removal cancelled. Confirmation phrase did not match.")
        return False

    current_password = prompt("Enter current password to confirm removal: ")
    if current_password is None:
        print("Removal cancelled.")
        return False
    if not verify_password(current_password, str(credentials.get("password_hash", ""))):
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
        choice = prompt("Enter your choice (1-8): ")
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
            print("You are being securely logged out of Data Bank. Goodbye.")
            set_session_password(None)
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, 4, 5, 6, 7, or 8.")


if __name__ == "__main__":
    main()