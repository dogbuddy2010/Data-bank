from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


DATA_FILE = Path(__file__).with_name("vault_data.json")
CONFIG_FILE = Path(__file__).with_name("vault_config.json")
DEFAULT_CREDENTIALS = {"username": "guest", "password": "11"}


def prompt(message: str) -> Optional[str]:
	try:
		return input(message).strip()
	except (EOFError, KeyboardInterrupt):
		print("\nInput cancelled.")
		return None


def load_credentials() -> dict[str, str]:
	if not CONFIG_FILE.exists():
		save_credentials(DEFAULT_CREDENTIALS)
		return DEFAULT_CREDENTIALS.copy()

	try:
		with CONFIG_FILE.open("r", encoding="utf-8") as file:
			data = json.load(file)
		if isinstance(data, dict):
			username = str(data.get("username", "")).strip()
			password = str(data.get("password", "")).strip()
			if username and password:
				return {"username": username, "password": password}
	except (json.JSONDecodeError, OSError):
		pass

	save_credentials(DEFAULT_CREDENTIALS)
	return DEFAULT_CREDENTIALS.copy()


def save_credentials(credentials: dict[str, str]) -> None:
	with CONFIG_FILE.open("w", encoding="utf-8") as file:
		json.dump(credentials, file, indent=2)


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


def save_vault(vault: dict[str, str]) -> None:
	with DATA_FILE.open("w", encoding="utf-8") as file:
		json.dump(vault, file, indent=2)


def login(credentials: dict[str, str]) -> bool:
	print("=== DATA BANK ===")
	print("Please log in to continue.")
	entered_username = prompt("Username: ")
	if entered_username is None:
		return False
	entered_password = prompt("Password: ")
	if entered_password is None:
		return False

	is_logged_in = (
		entered_username == credentials["username"]
		and entered_password == credentials["password"]
	)
	if not is_logged_in:
		print("Login failed. Invalid username or password.")
		return False

	print("Login successful.")
	print("Authentication completed.")
	return True


def show_menu() -> None:
	print("\nChoose an option:")
	print("1) Add data")
	print("2) List all keys")
	print("3) Retrieve data by key")
	print("4) Delete data by key")
	print("5) Change username/password")
	print("6) Exit")


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
	save_vault(vault)
	print(f"Saved data for key '{key}'.")


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
		del vault[key]
		save_vault(vault)
		print(f"Deleted key '{key}'.")
	else:
		print("No data found for that key.")


def change_credentials(credentials: dict[str, str]) -> None:
	print("\nChange credentials")
	current_password = prompt("Enter current password: ")
	if current_password is None:
		return
	if current_password != credentials["password"]:
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
	credentials["password"] = new_password
	save_credentials(credentials)
	print("Credentials updated and saved.")


def main() -> None:
	credentials = load_credentials()
	if not login(credentials):
		return

	vault = load_vault()
	print(f"You currently have {len(vault)} data entr{'y' if len(vault) == 1 else 'ies'} in the vault.")

	while True:
		show_menu()
		choice = prompt("Enter your choice (1-6): ")
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
			print("Goodbye.")
			break
		else:
			print("Invalid option. Please enter 1, 2, 3, 4, 5, or 6.")


if __name__ == "__main__":
	main()
