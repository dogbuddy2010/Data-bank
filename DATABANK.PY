from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
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


def default_credentials() -> dict[str, object]:
    return {
        "username": DEFAULT_USERNAME,
        "password_hash": hash_password(DEFAULT_PASSWORD),
        "max_login_attempts": DEFAULT_MAX_LOGIN_ATTEMPTS,
        "lockout_seconds": DEFAULT_LOCKOUT_SECONDS,
        "two_step_enabled": DEFAULT_TWO_STEP_ENABLED,
        "two_step_method": DEFAULT_TWO_STEP_METHOD,
        "two_step_secret": "",
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
    credentials["two_step_secret"] = secret
    credentials["two_step_custom_hash"] = custom_hash
    credentials["backup_code_hashes"] = backup_code_hashes
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
            two_step_secret = normalize_two_step_secret(credentials.get("two_step_secret", ""))
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
                two_step_method = normalize_two_step_method(
                    data.get("two_step_method", DEFAULT_TWO_STEP_METHOD)
                )
                two_step_secret = normalize_two_step_secret(data.get("two_step_secret", ""))
                two_step_custom_hash = str(data.get("two_step_custom_hash", "")).strip()
                backup_code_hashes = normalize_backup_code_hashes(data.get("backup_code_hashes", []))
                if two_step_method == "totp" and not two_step_secret:
                    two_step_enabled = False
                if two_step_method == "custom_code" and not is_valid_hash_format(two_step_custom_hash):
                    two_step_enabled = False

                if username and password_hash and is_valid_hash_format(password_hash):
                    credentials = {
                        "username": username,
                        "password_hash": password_hash,
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
                        "two_step_secret": two_step_secret,
                        "two_step_custom_hash": two_step_custom_hash,
                        "backup_code_hashes": backup_code_hashes,
                    }
                    save_credentials(credentials)
                    return credentials

                if username and legacy_password:
                    migrated = {
                        "username": username,
                        "password_hash": hash_password(legacy_password),
                        "max_login_attempts": max_login_attempts,
                        "lockout_seconds": lockout_seconds,
                        "two_step_enabled": two_step_enabled,
                        "two_step_method": two_step_method,
                        "two_step_secret": two_step_secret,
                        "two_step_custom_hash": two_step_custom_hash,
                        "backup_code_hashes": backup_code_hashes,
                    }
                    save_credentials(migrated)
                    print("Credentials migrated to hashed password format.")
                    return migrated
    except (json.JSONDecodeError, OSError):
        pass

    defaults = default_credentials()
    save_credentials(defaults)
    return defaults


def save_credentials(credentials: dict[str, object]) -> bool:
    normalized = {
        "username": str(credentials.get("username", "")).strip() or DEFAULT_USERNAME,
        "password_hash": str(credentials.get("password_hash", "")).strip(),
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
        "two_step_secret": normalize_two_step_secret(credentials.get("two_step_secret", "")),
        "two_step_custom_hash": str(credentials.get("two_step_custom_hash", "")).strip(),
        "backup_code_hashes": normalize_backup_code_hashes(credentials.get("backup_code_hashes", [])),
    }
    if not is_valid_hash_format(normalized["password_hash"]):
        normalized["password_hash"] = hash_password(DEFAULT_PASSWORD)
    if normalized["two_step_method"] == "totp" and normalized["two_step_enabled"] and not normalized["two_step_secret"]:
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
        normalized["two_step_secret"] = ""
        normalized["two_step_custom_hash"] = ""
        normalized["backup_code_hashes"] = []

    try:
        with CONFIG_FILE.open("w", encoding="utf-8") as file:
            json.dump(normalized, file, indent=2)
        return True
    except OSError as error:
        print(f"Could not save credentials to '{CONFIG_FILE}': {error}")
        return False


def load_vault() -> dict[str, str]:
    if not DATA_FILE.exists():
        return {}

    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                return {str(key): str(value) for key, value in data.items()}
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_vault(vault: dict[str, str]) -> bool:
    try:
        with DATA_FILE.open("w", encoding="utf-8") as file:
            json.dump(vault, file, indent=2)
        return True
    except OSError as error:
        print(f"Could not save vault data to '{DATA_FILE}': {error}")
        return False


def login(credentials: dict[str, object]) -> bool:
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
            if to_bool(credentials.get("two_step_enabled", DEFAULT_TWO_STEP_ENABLED), DEFAULT_TWO_STEP_ENABLED):
                method = normalize_two_step_method(credentials.get("two_step_method", DEFAULT_TWO_STEP_METHOD))
                two_step_code = prompt("Enter 2-step verification code: ")
                if two_step_code is None:
                    return False

                verified = False
                if method == "totp":
                    two_step_secret = normalize_two_step_secret(credentials.get("two_step_secret", ""))
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


def add_data(vault: dict[str, str]) -> None:
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
    if save_vault(vault):
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


def delete_data(vault: dict[str, str]) -> None:
    key = prompt("Enter key to delete: ")
    if key is None:
        return
    if key in vault:
        original_value = vault[key]
        del vault[key]
        if save_vault(vault):
            print(f"Deleted key '{key}'.")
        else:
            vault[key] = original_value
            print("Delete failed because data could not be saved.")
    else:
        print("No data found for that key.")


def change_credentials(credentials: dict[str, object]) -> None:
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

    credentials["username"] = new_username
    credentials["password_hash"] = hash_password(new_password)
    if save_credentials(credentials):
        print("Credentials updated and saved.")
    else:
        print("Credentials were not saved.")


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
                credentials["two_step_secret"] = ""
                credentials["two_step_custom_hash"] = ""
                credentials["backup_code_hashes"] = []
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
    credentials = load_credentials()
    if not login(credentials):
        return
    show_security_policy(credentials)

    vault = load_vault()
    print(f"You currently have {len(vault)} data entr{'y' if len(vault) == 1 else 'ies'} in the vault.")

    while True:
        show_menu()
        choice = prompt("Enter your choice (1-8): ")
        if choice is None:
            print("Goodbye.")
            break

        if choice == "1":
            add_data(vault)
        elif choice == "2":
            list_data(vault)
        elif choice == "3":
            retrieve_data(vault)
        elif choice == "4":
            delete_data(vault)
        elif choice == "5":
            change_credentials(credentials)
        elif choice == "6":
            change_security_settings(credentials)
        elif choice == "7":
            if remove_databank_files(credentials):
                break
        elif choice == "8":
            print("You are being securely logged out of Data Bank. Goodbye.")
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, 4, 5, 6, 7, or 8.")


if __name__ == "__main__":
    main()