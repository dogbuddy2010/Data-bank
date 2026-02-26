# Data-bank

Simple for-fun Python data vault that stores and retrieves key/value data. This code is just for fun. This is being worked alongside Copilot as a team effort.

## Features
- Basic login check
- Passwords stored as PBKDF2-SHA256 hashes in config (not plaintext)
- Auto-migrates old plaintext `vault_config.json` passwords to hashed format
- Login lockout policy is configurable in `vault_config.json`
- Save data by key
- List saved keys
- Retrieve data by key
- Delete data by key
- Persistent storage in `vault_data.json` (saved in a writable app folder)
- Persistent login config in `vault_config.json` (saved in a writable app folder)
- Change username/password from menu option 5
- Change lockout policy from menu option 6

## Run
From the project folder:

```bash
python3 DATABANK.PY
```

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
