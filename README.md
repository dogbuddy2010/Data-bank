# Data-bank

A simple Python data vault project for storing and retrieving key/value data. This project is built as a collaborative effort with Copilot.

## Features
- Login with username/password
- Passwords stored as PBKDF2-SHA256 hashes in config (not plaintext)
- Auto-migrates old plaintext `vault_config.json` passwords to hashed format
- Vault file is encrypted at rest and auto-encrypted on save
- TOTP secrets are encrypted before being stored in config
- New password updates require strength checks
- Startup checks local Data-bank files and safely handles legacy file formats
- Login lockout policy is configurable in `vault_config.json`
- Data Integrity Check validates vault hash + encrypted payload integrity
- Periodic startup integrity check runs in warning-only mode
- Add data by key
- List saved keys
- Search keys by text
- Retrieve data by key
- Delete data by key
- Persistent storage in `vault_data.json` (saved in a writable app folder)
- Persistent login config in `vault_config.json` (saved in a writable app folder)
- Change Username/Password from menu option 6
- Change Security Settings from menu option 7
- Remove Data-bank created files from menu option 8 (phrase + password required)
- Run Data Integrity Check from menu option 10
- Built-in Support Assistant chat for usage/security questions from menu option 11
- Support Assistant can optionally use an external AI API when `DATABANK_AI_API_KEY` is set
- Support Assistant adapts to each user’s question history and personalizes guidance over time
- Support Assistant scans the program’s own functions/docstrings at startup to answer broader free-form questions
- Support Assistant uses weighted natural-language intent scoring (not only exact command phrases)
- Support Assistant provides guided “Suggested next step” menu recommendations after each response
- Optional authenticator-app two-step verification (TOTP)
- Adaptive Security AI learning can tune thresholds from recent activity
- Security Analytics Report now includes learning baselines, confidence, and active thresholds

## Run
From the project folder:

```bash
python3 run_databank.py
```

Windows options:

```powershell
py -3 run_databank.py
```

Or double-click `run_databank_windows.bat` to launch without terminal commands.

### Optional: External AI API for Support Assistant
The assistant works offline by default. To enable API-backed responses, set environment variables before running:

```bash
export DATABANK_AI_API_KEY="<your-api-key>"
export DATABANK_AI_MODEL="gpt-4.1-mini"   # optional
export DATABANK_AI_API_URL="https://api.openai.com/v1/responses"   # optional
python3 run_databank.py
```

Security + wiring notes:
- API keys are loaded from `DATABANK_AI_API_KEY` (or `OPENAI_API_KEY` alias), never hardcoded in source.
- API settings can be loaded from local `.env` and optional local `ai_settings.json` with file permission hardening.
- API endpoint is HTTPS-validated at runtime; invalid/non-HTTPS values are rejected and defaulted safely.

Security note: never hardcode API keys in source files or commit them to git.

Alternative local setup (recommended):

```bash
cat > .env << 'EOF'
DATABANK_AI_API_KEY=your_api_key_here
DATABANK_AI_MODEL=gpt-4.1-mini
DATABANK_AI_API_URL=https://api.openai.com/v1/responses
EOF
# edit .env and replace your_api_key_here
python3 run_databank.py
```

Data-bank auto-loads `.env` from the project folder at startup.

This launcher runs a syntax check on `DATABANK.PY` before starting the app.

## First Launch Behavior
On first run, Data-bank shows a setup message and creates its login/security config file in the storage folder:
- `./.data_bank/vault_config.json` (inside the project folder when writable)
- fallback: `~/.data_bank/vault_config.json` only if project-local storage is not writable

First launch includes a required guided account setup where you must create a custom username/password before login.

The vault data file:
- `./.data_bank/vault_data.json` (or fallback to `~/.data_bank/vault_data.json`)

is created automatically after your first saved vault entry.

## Quick Health Check
To verify storage path and file write access:

```bash
python3 health_check.py
```

The app stores data in `.data_bank` under the project folder by default.

Safe cleanup option:
- Menu option 8 removes only Data-bank-created files (`vault_data.json` and `vault_config.json`) from the Data-bank storage folder.
- It does not delete unrelated computer files.
- It requires typing an exact confirmation phrase and your current password.

Default credentials are deprecated and blocked from login.

After first run, login credentials are saved in `.data_bank/vault_config.json` in the active project folder (with home-folder fallback only when needed) and can be changed in-app. If you change them, use the updated values.

Note: `vault_config.json` now stores `password_hash` instead of `password` for security. Older plaintext configs are migrated automatically on next successful load.

Optional security settings in `vault_config.json`:
- `max_login_attempts` (default `3`, allowed range `1-10`)
- `lockout_seconds` (default `30`, allowed range `0-300`)
- `security_ai_learning_enabled` (default `true`; enables adaptive threshold tuning)
- `two_step_enabled` (default `false`)
- `two_step_method` (`custom_code` or `totp`)
- `two_step_secret_encrypted` (encrypted TOTP secret; plaintext is not stored)
- `two_step_custom_hash` (hashed custom code when using `custom_code` method)
- `backup_code_hashes` (hashed one-time recovery codes; plaintext codes are not stored)
- `vault_salt` (random salt used with password-derived vault encryption key)
- `vault_integrity_hash` (last trusted SHA-256 hash of the encrypted vault file)

Startup file check behavior:
- On launch, Data-bank validates local file state.
- If legacy vault format is detected, Data-bank reports it and upgrades it automatically after successful login.
- On startup after login, Data-bank runs a periodic integrity verification (about every 6 hours) and warns on issues without blocking access.

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
