# Data-bank

Simple for-fun Python data vault that stores and retrieves key/value data. This code is just for fun. This is being worked alongside Copilot as a team effort.

## Features
- Basic login check
- Passwords stored as PBKDF2-SHA256 hashes in config (not plaintext)
- Auto-migrates old plaintext `vault_config.json` passwords to hashed format
- Login lockout policy is configurable in `vault_config.json`
- Add Data by Key
- List Saved Keys
- Retrieve Data by Key
- Delete Data by Key
- Persistent storage in `vault_data.json` (saved in a writable app folder)
- Persistent login config in `vault_config.json` (saved in a writable app folder)
- Change Username/Password from menu option 5
- Change Security Settings from menu option 6
- Optional authenticator-app Two-Step Verification (TOTP)

## Run
From the project folder:

```bash
python3 run_databank.py
```

This launcher runs a syntax check on `DATABANK.PY` before starting the app.

## Quick Health Check
To verify storage path and file write access:

```bash
python3 health_check.py
```

Default login:
- Username: `guest`
- Password: `11`

The app stores data in your home folder under `.data_bank`.

The default login works only when `.data_bank/vault_config.json` does not yet exist or has been reset to defaults.

After first run, login credentials are saved in `.data_bank/vault_config.json` and can be changed in-app. If you changed them, use the new values from that file.

Note: `vault_config.json` now stores `password_hash` instead of `password` for security. Older plaintext configs are migrated automatically on next successful load.

Optional security settings in `vault_config.json`:
- `max_login_attempts` (default `3`, allowed range `1-10`)
- `lockout_seconds` (default `30`, allowed range `0-300`)
- `two_step_enabled` (default `false`)
- `two_step_method` (`custom_code` or `totp`)
- `two_step_secret` (base32 secret used for authenticator app codes)
- `two_step_custom_hash` (hashed custom code when using `custom_code` method)
- `backup_code_hashes` (hashed one-time recovery codes; plaintext codes are not stored)

Two-step verification notes:
- After password login, users can opt in to 2-step setup.
- Setup offers two methods:
	- `custom_code` (recommended): user creates their own verification code; no mobile app required.
	- `totp`: authenticator app mode using base32 secret and `otpauth://` URI.
- During 2-step setup, backup recovery codes are generated and shown once.
- Once enabled, login requires a valid 2-step code for the selected method.
- If TOTP is unavailable, a backup recovery code can be used once as fallback.
- Backup recovery codes can be regenerated from Security Settings, but regeneration requires current password and current 2-step code confirmation.
- Disabling two-step verification also requires an explicit warning confirmation, then current password and current 2-step code confirmation.
