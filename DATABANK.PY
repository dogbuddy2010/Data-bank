from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from typing import Optional


DEFAULT_USERNAME = "guest"
DEFAULT_PASSWORD = "11"
PASSWORD_HASH_PREFIX = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 200_000
DEFAULT_MAX_LOGIN_ATTEMPTS = 3
DEFAULT_LOCKOUT_SECONDS = 30
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
	return (
		f"{PASSWORD_HASH_PREFIX}${PASSWORD_HASH_ITERATIONS}"
		f"${salt.hex()}${digest.hex()}"
	)


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
	}


def clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
	try:
		parsed = int(value)
	except (TypeError, ValueError):
		return default
	return max(minimum, min(parsed, maximum))


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

			if username and password_hash and is_valid_hash_format(password_hash):
				credentials = {
					"username": username,
					"password_hash": password_hash,
					"max_login_attempts": max_login_attempts,
					"lockout_seconds": lockout_seconds,
				}
				save_credentials(credentials)
				return credentials

			if username and legacy_password:
				migrated = {
					"username": username,
					"password_hash": hash_password(legacy_password),
					"max_login_attempts": max_login_attempts,
					"lockout_seconds": lockout_seconds,
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
	}
	if not is_valid_hash_format(normalized["password_hash"]):
		normalized["password_hash"] = hash_password(DEFAULT_PASSWORD)

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
			print("Login successful.")
			print("Authentication completed.")
			return True

		attempts_left = max_attempts - attempt
		if attempts_left > 0:
			print(
				f"Login failed. Invalid username or password. "
				f"Attempts left: {attempts_left}."
			)
		else:
			if lockout_seconds > 0:
				print(
					f"Too many failed attempts. "
					f"Please wait {lockout_seconds} seconds before trying again."
				)
				time.sleep(lockout_seconds)
			else:
				print("Too many failed attempts.")
			return False

	return False


def show_menu() -> None:
	print("\nChoose an option:")
	print("1) Add data")
	print("2) List all keys")
	print("3) Retrieve data by key")
	print("4) Delete data by key")
	print("5) Change username/password")
	print("6) Security settings")
	print("7) Exit")


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
	print("\nChange credentials")
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

	print("\nSecurity settings")
	print(f"Current max login attempts: {current_attempts}")
	print(f"Current lockout seconds: {current_lockout}")

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

	if not new_attempts_input and not new_lockout_input:
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
	print(
		"Active security policy: "
		f"max_login_attempts={max_attempts}, "
		f"lockout={lockout_display}"
	)


def show_storage_info() -> None:
	print(f"Storage folder: {STORAGE_DIR}")


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
		choice = prompt("Enter your choice (1-7): ")
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
			print("You are being Securly Logged Out of Data bank. Goodbye.")
			break
		else:
			print("Invalid option. Please enter 1, 2, 3, 4, 5, 6, or 7.")


if __name__ == "__main__":
	main()
