from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path


def load_databank_module():
	databank_path = Path(__file__).with_name("DATABANK.PY")
	loader = SourceFileLoader("databank_module", str(databank_path))
	spec = importlib.util.spec_from_loader("databank_module", loader)
	if spec is None or spec.loader is None:
		raise RuntimeError(f"Could not load module from {databank_path}")
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


def run_health_check() -> int:
	databank = load_databank_module()
	storage_dir = databank.STORAGE_DIR
	data_file = databank.DATA_FILE
	config_file = databank.CONFIG_FILE

	print("=== Data-bank Health Check ===")
	print(f"Storage directory: {storage_dir}")
	print(f"Data file path: {data_file}")
	print(f"Config file path: {config_file}")

	if not databank.is_writable_directory(storage_dir):
		print("FAIL: Storage directory is not writable.")
		return 1

	test_file = storage_dir / ".data_bank_health_check"
	try:
		test_file.write_text("ok", encoding="utf-8")
		if test_file.read_text(encoding="utf-8") != "ok":
			print("FAIL: Read/write verification failed.")
			return 1
	finally:
		try:
			test_file.unlink(missing_ok=True)
		except OSError:
			pass

	print(f"Credentials file exists: {config_file.exists()}")
	print(f"Vault file exists: {data_file.exists()}")
	print("PASS: Storage and file access checks succeeded.")
	return 0


if __name__ == "__main__":
	raise SystemExit(run_health_check())
