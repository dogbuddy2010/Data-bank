# Data-bank

Simple for-fun Python data vault that stores and retrieves key/value data. This code is just for fun.

## Features
- Basic login check
- Save data by key
- List saved keys
- Retrieve data by key
- Delete data by key
- Persistent storage in `vault_data.json` (saved in a writable app folder)
- Persistent login config in `vault_config.json` (saved in a writable app folder)
- Change username/password from menu option 5

## Run
From the project folder:

```bash
python3 DATABANK.PY
```

Default login:
- Username: `guest`
- Password: `11`

The app stores data in your home folder under `.data_bank`.

The default login works only when `.data_bank/vault_config.json` does not yet exist or has been reset to defaults.

After first run, login credentials are saved in `.data_bank/vault_config.json` and can be changed in-app. If you changed them, use the new values from that file.
