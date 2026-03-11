from __future__ import annotations

import ast
import base64
from collections import deque
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Optional
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
DEFAULT_SECURITY_AI_LEARNING_ENABLED = True
SECURITY_AI_LEARNING_ALPHA = 0.35
SECURITY_AI_MAX_ADJUSTMENT = 6
SECURITY_AI_BASELINE_WINDOW_SECONDS = 24 * 60 * 60
STARTUP_INTEGRITY_CHECK_INTERVAL_SECONDS = 6 * 60 * 60
BACKUP_CODE_COUNT = 8
MIN_LOGIN_ATTEMPTS = 1
MAX_LOGIN_ATTEMPTS = 10
MIN_LOCKOUT_SECONDS = 0
MAX_LOCKOUT_SECONDS = 300
AI_ASSISTANT_API_KEY_ENV = "DATABANK_AI_API_KEY"
AI_ASSISTANT_API_URL_ENV = "DATABANK_AI_API_URL"
AI_ASSISTANT_MODEL_ENV = "DATABANK_AI_MODEL"
AI_ASSISTANT_API_KEY_ALIASES = ("OPENAI_API_KEY", "OPENAI_KEY", "OPENAI_APIKEY")
DEFAULT_AI_ASSISTANT_API_URL = "https://api.openai.com/v1/responses"
DEFAULT_AI_ASSISTANT_MODEL = "gpt-4.1-mini"
AI_ASSISTANT_REQUEST_TIMEOUT_SECONDS = 12
AI_ASSISTANT_MAX_QUESTION_CHARS = 600
AI_ASSISTANT_ALLOW_RUNTIME_KEY_PROMPT = False


SESSION_PASSWORD: Optional[str] = None
LAST_EXTERNAL_AI_ERROR = ""
LAST_EXTERNAL_AI_USED = False
LAST_ASSISTANT_CONFIG_SOURCE = ""


def project_root_dir() -> Path:
    main_file = globals().get("__file__")
    if isinstance(main_file, str) and main_file.strip():
        try:
            return Path(main_file).resolve().parent
        except OSError:
            pass
    try:
        argv0 = Path(sys.argv[0]) if sys.argv else Path.cwd()
        if argv0.is_file():
            return argv0.resolve().parent
    except OSError:
        pass
    return Path.cwd().resolve()


PROJECT_ROOT_DIR = project_root_dir()
PRIMARY_DOTENV_FILE = PROJECT_ROOT_DIR / ".env"


def normalize_external_api_key(value: object) -> str:
    text = str(value).strip()
    if not text:
        return ""

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""

    for line in lines:
        candidate = line
        if line.startswith(f"{AI_ASSISTANT_API_KEY_ENV}="):
            candidate = line.split("=", 1)[1].strip()

        if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {'"', "'"}:
            candidate = candidate[1:-1].strip()

        match = re.search(r"sk-[^\s'\"`]{20,}", candidate)
        if match:
            return match.group(0)

    return ""


def normalize_configured_api_key(value: object) -> str:
    token = str(value).strip()
    if not token:
        return ""

    normalized = normalize_external_api_key(token)
    if normalized:
        return normalized

    # Fallback for future provider key formats: accept a long, single-token value.
    if len(token) >= 20 and not re.search(r"\s", token):
        return token
    return ""


def extract_api_key_from_text(content: str) -> str:
    parsed = normalize_configured_api_key(content)
    if parsed:
        return parsed

    for raw_line in content.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()

        if "=" in line:
            key, value = line.split("=", 1)
            key_name = key.strip().lstrip("\ufeff")
            if key_name in {AI_ASSISTANT_API_KEY_ENV, *AI_ASSISTANT_API_KEY_ALIASES}:
                candidate = normalize_configured_api_key(value.strip().strip('"').strip("'"))
                if candidate:
                    return candidate
        else:
            candidate = normalize_configured_api_key(line)
            if candidate:
                return candidate

    return ""


def load_api_key_from_file(file_path: Path) -> str:
    try:
        if not file_path.exists() or not file_path.is_file():
            return ""
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        return ""

    return extract_api_key_from_text(content)


def candidate_dotenv_paths() -> list[Path]:
    candidates: list[Path] = []

    def add_path(base: Path) -> None:
        target = (base / ".env").resolve()
        if target not in candidates:
            candidates.append(target)

    # Always check the project .env first.
    try:
        primary = PRIMARY_DOTENV_FILE.resolve()
        candidates.append(primary)
    except OSError:
        pass

    try:
        cwd = Path.cwd().resolve()
        add_path(cwd)
        for parent in cwd.parents:
            add_path(parent)
    except OSError:
        pass

    main_file = globals().get("__file__")
    if isinstance(main_file, str) and main_file.strip():
        try:
            script_dir = Path(main_file).resolve().parent
            add_path(script_dir)
            for parent in script_dir.parents:
                add_path(parent)
        except OSError:
            pass

    argv0 = sys.argv[0] if sys.argv else ""
    if isinstance(argv0, str) and argv0.strip():
        try:
            argv_path = Path(argv0)
            if argv_path.is_file():
                argv_dir = argv_path.resolve().parent
                add_path(argv_dir)
                for parent in argv_dir.parents:
                    add_path(parent)
        except OSError:
            pass

    return candidates


def load_local_dotenv() -> None:
    loaded_files: set[Path] = set()
    for dotenv_path in candidate_dotenv_paths():
        resolved = dotenv_path.resolve()
        if resolved in loaded_files or not resolved.exists() or not resolved.is_file():
            continue
        loaded_files.add(resolved)

        try:
            lines = resolved.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                inferred_key = normalize_external_api_key(line)
                if inferred_key:
                    os.environ[AI_ASSISTANT_API_KEY_ENV] = inferred_key
                continue

            if line.lower().startswith("export "):
                line = line[7:].strip()

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            env_key = key.strip()
            env_value = value.strip()
            if not env_key:
                continue

            if len(env_value) >= 2 and env_value[0] == env_value[-1] and env_value[0] in {'"', "'"}:
                env_value = env_value[1:-1]

            if env_key in AI_ASSISTANT_API_KEY_ALIASES:
                normalized_key = normalize_external_api_key(env_value)
                if normalized_key:
                    os.environ[AI_ASSISTANT_API_KEY_ENV] = normalized_key
                continue

            if env_key == AI_ASSISTANT_API_KEY_ENV:
                normalized_key = normalize_configured_api_key(env_value)
                if not normalized_key:
                    continue
                env_value = normalized_key

            if env_key.startswith("DATABANK_AI_"):
                os.environ[env_key] = env_value
            else:
                os.environ.setdefault(env_key, env_value)


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
    project_storage_dir = (PROJECT_ROOT_DIR / ".data_bank").resolve()
    if is_writable_directory(project_storage_dir):
        legacy_home_storage_dir = (Path.home() / ".data_bank").resolve()
        if legacy_home_storage_dir != project_storage_dir and legacy_home_storage_dir.exists():
            try:
                has_project_data = any(project_storage_dir.iterdir())
            except OSError:
                has_project_data = True

            if not has_project_data:
                # One-time best-effort migration from legacy home storage.
                for file_name in (
                    "vault_data.json",
                    "vault_config.json",
                    "security_events.jsonl",
                    "ai_settings.json",
                    ".env",
                    "company_ai_config.json",
                ):
                    source = legacy_home_storage_dir / file_name
                    target = project_storage_dir / file_name
                    try:
                        if source.exists() and source.is_file() and not target.exists():
                            shutil.copy2(source, target)
                    except OSError:
                        pass
        return project_storage_dir

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
AI_SETTINGS_FILE = STORAGE_DIR / "ai_settings.json"

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
PROGRAM_HELP_INDEX: list[dict[str, object]] = []

AI_HELP_STOP_WORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "to",
    "for",
    "of",
    "in",
    "on",
    "is",
    "it",
    "how",
    "what",
    "can",
    "i",
    "do",
    "my",
    "with",
    "from",
    "that",
    "this",
}

AI_HELP_TOPIC_KEYWORDS: dict[str, set[str]] = {
    "two_step": {
        "two",
        "step",
        "2fa",
        "totp",
        "authenticator",
        "verification",
        "second",
        "factor",
        "code",
    },
    "backup": {
        "backup",
        "recovery",
        "codes",
        "recover",
        "fallback",
        "one-time",
        "regenerate",
    },
    "integrity": {
        "integrity",
        "tamper",
        "hash",
        "checksum",
        "verify",
        "corrupt",
        "corruption",
    },
    "security_ai": {
        "security",
        "ai",
        "alert",
        "alerts",
        "anomaly",
        "threshold",
        "learning",
        "sensitivity",
    },
    "cleanup": {
        "remove",
        "delete",
        "cleanup",
        "wipe",
        "erase",
        "files",
    },
    "credentials": {
        "password",
        "username",
        "credential",
        "credentials",
        "login",
        "change",
        "update",
    },
    "vault_ops": {
        "vault",
        "data",
        "save",
        "add",
        "list",
        "search",
        "retrieve",
        "delete",
        "key",
        "keys",
    },
}

AI_HELP_CONVERSATION_INTENTS: dict[str, set[str]] = {
    "thanks": {"thanks", "thank", "thankyou", "thx", "ty", "appreciate"},
    "greeting": {"hi", "hello", "hey", "yo", "sup", "goodmorning", "goodafternoon", "goodevening"},
    "confused": {
        "dontknow",
        "don'tknow",
        "stuck",
        "confused",
        "lost",
        "help",
        "unsure",
        "idk",
        "whatdoido",
        "nowwhat",
    },
    "goodbye": {"bye", "goodbye", "seeya", "later", "cya"},
}


def normalize_security_ai_sensitivity(value: object) -> str:
    candidate = str(value).strip().lower()
    if candidate in SECURITY_AI_PROFILES:
        return candidate
    return DEFAULT_SECURITY_AI_SENSITIVITY


def normalize_hex_digest(value: object, length: int = 64) -> str:
    candidate = str(value).strip().lower()
    if len(candidate) == length and all(ch in "0123456789abcdef" for ch in candidate):
        return candidate
    return ""


def normalize_ai_learning_state(value: object) -> dict[str, float]:
    defaults: dict[str, float] = {
        "failed_login_ewma": 0.0,
        "vault_access_ewma": 0.0,
        "unique_key_ewma": 0.0,
        "sample_count": 0.0,
    }
    if not isinstance(value, dict):
        return defaults

    normalized = defaults.copy()
    for key in defaults:
        try:
            parsed = float(value.get(key, defaults[key]))
        except (TypeError, ValueError):
            parsed = defaults[key]
        normalized[key] = max(0.0, parsed)
    return normalized


def normalize_ai_help_learning_state(value: object) -> dict[str, object]:
    numeric_defaults: dict[str, float] = {
        "total_questions": 0.0,
        "last_question_at": 0.0,
        "topic_two_step": 0.0,
        "topic_backup": 0.0,
        "topic_integrity": 0.0,
        "topic_security_ai": 0.0,
        "topic_cleanup": 0.0,
        "topic_credentials": 0.0,
        "topic_vault_ops": 0.0,
        "topic_general": 0.0,
    }
    allowed_topics = {
        "two_step",
        "backup",
        "integrity",
        "security_ai",
        "cleanup",
        "credentials",
        "vault_ops",
        "general",
    }

    normalized: dict[str, object] = {**numeric_defaults, "last_topic": ""}
    if not isinstance(value, dict):
        return normalized

    for key, default in numeric_defaults.items():
        try:
            parsed = float(value.get(key, default))
        except (TypeError, ValueError):
            parsed = default
        normalized[key] = max(0.0, parsed)

    topic = str(value.get("last_topic", "")).strip().lower()
    normalized["last_topic"] = topic if topic in allowed_topics else ""
    return normalized


def normalize_ai_help_chat_state(value: object) -> dict[str, object]:
    normalized: dict[str, object] = {
        "pending_question_type": "",
        "pending_question_text": "",
        "pending_set_at": 0.0,
    }
    allowed_question_types = {
        "choose_goal",
        "two_step_method_choice",
        "enable_two_step_confirm",
    }

    if not isinstance(value, dict):
        return normalized

    question_type = str(value.get("pending_question_type", "")).strip().lower()
    normalized["pending_question_type"] = (
        question_type if question_type in allowed_question_types else ""
    )
    normalized["pending_question_text"] = str(value.get("pending_question_text", "")).strip()[:240]

    try:
        parsed_time = float(value.get("pending_set_at", 0.0))
    except (TypeError, ValueError):
        parsed_time = 0.0
    normalized["pending_set_at"] = max(0.0, parsed_time)
    return normalized


def set_ai_help_pending_question(
    credentials: dict[str, object],
    question_type: str,
    question_text: str,
) -> None:
    state = normalize_ai_help_chat_state(credentials.get("ai_help_chat_state", {}))
    state["pending_question_type"] = question_type
    state["pending_question_text"] = question_text.strip()[:240]
    state["pending_set_at"] = float(int(time.time()))
    credentials["ai_help_chat_state"] = state


def clear_ai_help_pending_question(credentials: dict[str, object]) -> None:
    credentials["ai_help_chat_state"] = normalize_ai_help_chat_state({})


def classify_ai_help_topic(query: str) -> str:
    topic, _ = infer_ai_help_topic(query)
    return topic


def infer_ai_help_topic(query: str) -> tuple[str, float]:
    normalized_query = query.strip().lower()
    if not normalized_query:
        return "general", 0.0

    tokens = tokenize_ai_help_text(normalized_query)
    if not tokens:
        return "general", 0.0

    best_topic = "general"
    best_score = 0.0

    for topic, keywords in AI_HELP_TOPIC_KEYWORDS.items():
        overlap = len(tokens & keywords)
        if overlap <= 0:
            continue

        token_coverage = overlap / max(1, len(tokens))
        keyword_coverage = overlap / max(1, len(keywords))
        score = (token_coverage * 0.7) + (keyword_coverage * 0.3)

        if score > best_score:
            best_score = score
            best_topic = topic

    if best_score <= 0.0:
        return "general", 0.0

    return best_topic, min(1.0, best_score)


def infer_ai_help_conversation_intent(query: str) -> str:
    normalized_query = query.strip().lower()
    if not normalized_query:
        return ""

    compact = normalized_query.replace(" ", "")
    tokens = tokenize_ai_help_text(normalized_query)
    tokens.add(compact)

    for intent, keywords in AI_HELP_CONVERSATION_INTENTS.items():
        if tokens & keywords:
            return intent

    if "i don't know" in normalized_query or "i dont know" in normalized_query:
        return "confused"
    if "what should i do" in normalized_query or "what do i do" in normalized_query:
        return "confused"
    if "thank you" in normalized_query:
        return "thanks"
    return ""


def learn_from_ai_help_question(credentials: dict[str, object], question: str) -> None:
    query = question.strip().lower()
    if not query:
        return

    learning_state = normalize_ai_help_learning_state(
        credentials.get("ai_help_learning_state", {})
    )
    topic, confidence = infer_ai_help_topic(query)

    learning_state["total_questions"] = float(learning_state["total_questions"]) + 1.0
    topic_key = f"topic_{topic}"
    learning_state[topic_key] = float(learning_state.get(topic_key, 0.0)) + max(0.25, confidence)
    learning_state["last_topic"] = topic
    learning_state["last_question_at"] = float(int(time.time()))

    credentials["ai_help_learning_state"] = learning_state


def tokenize_ai_help_text(text: str) -> set[str]:
    tokens = {
        token
        for token in re.split(r"[^a-zA-Z0-9_]+", text.lower())
        if len(token) >= 2 and token not in AI_HELP_STOP_WORDS
    }
    return tokens


def build_program_help_index() -> None:
    global PROGRAM_HELP_INDEX

    try:
        source_candidate = globals().get("__file__")
        if isinstance(source_candidate, str) and source_candidate.strip():
            source_path = Path(source_candidate)
        else:
            argv_candidate = sys.argv[0] if sys.argv else ""
            if isinstance(argv_candidate, str) and argv_candidate.strip() and Path(argv_candidate).is_file():
                source_path = Path(argv_candidate)
            else:
                fallback = Path.cwd() / "DATABANK.PY"
                if not fallback.is_file():
                    PROGRAM_HELP_INDEX = []
                    return
                source_path = fallback

        source_text = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source_text)
    except (OSError, SyntaxError, UnicodeDecodeError):
        PROGRAM_HELP_INDEX = []
        return

    index: list[dict[str, object]] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue

        name = node.name
        doc = ast.get_docstring(node) or ""
        summary = doc.splitlines()[0].strip() if doc else ""
        if not summary:
            summary = f"Function '{name}' in Data-bank workflow."

        searchable = f"{name} {name.replace('_', ' ')} {summary}"
        tokens = tokenize_ai_help_text(searchable)
        if not tokens:
            continue

        index.append(
            {
                "name": name,
                "summary": summary,
                "tokens": tokens,
            }
        )

    PROGRAM_HELP_INDEX = index


def find_program_help_matches(question: str, max_results: int = 3) -> list[dict[str, object]]:
    if not PROGRAM_HELP_INDEX:
        build_program_help_index()

    question_tokens = tokenize_ai_help_text(question)
    if not question_tokens:
        return []

    scored: list[tuple[int, dict[str, object]]] = []
    for entry in PROGRAM_HELP_INDEX:
        entry_tokens = entry.get("tokens")
        if not isinstance(entry_tokens, set):
            continue

        overlap = len(question_tokens & entry_tokens)
        if overlap <= 0:
            continue

        name = str(entry.get("name", "")).lower()
        name_bonus = 2 if name and name in question.lower() else 0
        scored.append((overlap + name_bonus, entry))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [entry for _, entry in scored[:max_results]]


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


def collect_security_ai_learning_sample(
    window_seconds: int = SECURITY_AI_BASELINE_WINDOW_SECONDS,
) -> dict[str, float]:
    recent_events = load_recent_security_events(window_seconds)
    failed_login_count = sum(1 for event in recent_events if event.get("event") == "failed_login")
    vault_events = [event for event in recent_events if event.get("event") == "vault_access"]

    unique_keys: set[str] = set()
    for event in vault_events:
        details = event.get("details")
        if not isinstance(details, dict):
            continue
        key = str(details.get("key", "")).strip()
        if key:
            unique_keys.add(key)

    return {
        "failed_login_count": float(failed_login_count),
        "vault_access_count": float(len(vault_events)),
        "unique_key_count": float(len(unique_keys)),
    }


def apply_adaptive_security_ai(credentials: dict[str, object]) -> None:
    """Adapt Security AI thresholds using a bounded EWMA model of recent activity."""
    global ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD
    global ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD
    global ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD
    global ACTIVE_SECURITY_VAULT_BURST_THRESHOLD
    global ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD
    global ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS

    if not to_bool(
        credentials.get("security_ai_learning_enabled", DEFAULT_SECURITY_AI_LEARNING_ENABLED),
        DEFAULT_SECURITY_AI_LEARNING_ENABLED,
    ):
        return

    learning_state = normalize_ai_learning_state(credentials.get("ai_learning_state", {}))
    sample = collect_security_ai_learning_sample()

    sample_count = int(learning_state["sample_count"])
    alpha = SECURITY_AI_LEARNING_ALPHA
    if sample_count <= 0:
        learning_state["failed_login_ewma"] = sample["failed_login_count"]
        learning_state["vault_access_ewma"] = sample["vault_access_count"]
        learning_state["unique_key_ewma"] = sample["unique_key_count"]
    else:
        learning_state["failed_login_ewma"] = (
            (1.0 - alpha) * learning_state["failed_login_ewma"]
            + alpha * sample["failed_login_count"]
        )
        learning_state["vault_access_ewma"] = (
            (1.0 - alpha) * learning_state["vault_access_ewma"]
            + alpha * sample["vault_access_count"]
        )
        learning_state["unique_key_ewma"] = (
            (1.0 - alpha) * learning_state["unique_key_ewma"]
            + alpha * sample["unique_key_count"]
        )

    learning_state["sample_count"] = float(min(10_000, sample_count + 1))
    credentials["ai_learning_state"] = learning_state

    confidence = min(1.0, learning_state["sample_count"] / 8.0)
    failed_adjustment = min(
        SECURITY_AI_MAX_ADJUSTMENT,
        int((learning_state["failed_login_ewma"] / 5.0) * confidence),
    )
    vault_adjustment = min(
        SECURITY_AI_MAX_ADJUSTMENT,
        int((learning_state["vault_access_ewma"] / 25.0) * confidence),
    )
    unique_adjustment = min(
        SECURITY_AI_MAX_ADJUSTMENT,
        int((learning_state["unique_key_ewma"] / 6.0) * confidence),
    )

    ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD = min(
        40,
        max(2, ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD + failed_adjustment),
    )
    ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD = min(
        15,
        max(1, ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD + min(3, unique_adjustment)),
    )
    ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD = min(
        40,
        max(3, ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD + failed_adjustment),
    )
    ACTIVE_SECURITY_VAULT_BURST_THRESHOLD = min(
        120,
        max(4, ACTIVE_SECURITY_VAULT_BURST_THRESHOLD + vault_adjustment),
    )
    ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD = min(
        80,
        max(3, ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD + unique_adjustment),
    )
    if confidence >= 0.5 and (vault_adjustment >= 3 or unique_adjustment >= 3):
        ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS = min(
            5,
            ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS + 1,
        )


def apply_security_ai_profile(credentials: dict[str, object]) -> None:
    apply_security_ai_sensitivity(
        credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
    )
    apply_adaptive_security_ai(credentials)


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


def load_local_ai_settings_file() -> None:
    if not AI_SETTINGS_FILE.exists() or not AI_SETTINGS_FILE.is_file():
        return

    try:
        parsed = json.loads(AI_SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return

    if not isinstance(parsed, dict):
        return

    api_key = normalize_external_api_key(parsed.get("api_key", ""))
    model = str(parsed.get("model", "")).strip()
    api_url = str(parsed.get("api_url", "")).strip()

    if api_key and not os.environ.get(AI_ASSISTANT_API_KEY_ENV, "").strip():
        os.environ[AI_ASSISTANT_API_KEY_ENV] = api_key
    if model and not os.environ.get(AI_ASSISTANT_MODEL_ENV, "").strip():
        os.environ[AI_ASSISTANT_MODEL_ENV] = model
    if api_url and not os.environ.get(AI_ASSISTANT_API_URL_ENV, "").strip():
        os.environ[AI_ASSISTANT_API_URL_ENV] = api_url


def discover_local_api_key() -> str:
    candidate_files: list[Path] = candidate_dotenv_paths()
    candidate_files.append(AI_SETTINGS_FILE)

    checked: set[Path] = set()
    for candidate in candidate_files:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate

        if resolved in checked or not candidate.exists() or not candidate.is_file():
            continue
        checked.add(resolved)

        discovered = load_api_key_from_file(candidate)
        if discovered:
            return discovered

        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError:
            continue

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, dict):
            discovered = normalize_external_api_key(parsed.get("api_key", ""))
            if discovered:
                return discovered

    return ""


def normalize_assistant_endpoint(value: object) -> str:
    candidate = str(value).strip()
    if not candidate:
        return DEFAULT_AI_ASSISTANT_API_URL
    if not candidate.lower().startswith("https://"):
        return DEFAULT_AI_ASSISTANT_API_URL
    return candidate


def assistant_runtime_config() -> tuple[str, str, str]:
    global LAST_ASSISTANT_CONFIG_SOURCE

    LAST_ASSISTANT_CONFIG_SOURCE = ""
    load_local_dotenv()
    load_local_ai_settings_file()

    api_key = normalize_configured_api_key(os.environ.get(AI_ASSISTANT_API_KEY_ENV, ""))
    if api_key:
        LAST_ASSISTANT_CONFIG_SOURCE = f"env:{AI_ASSISTANT_API_KEY_ENV}"
    if not api_key:
        for alias in AI_ASSISTANT_API_KEY_ALIASES:
            alias_value = normalize_configured_api_key(os.environ.get(alias, ""))
            if alias_value:
                api_key = alias_value
                os.environ[AI_ASSISTANT_API_KEY_ENV] = api_key
                LAST_ASSISTANT_CONFIG_SOURCE = f"env-alias:{alias}"
                break

    if not api_key:
        direct_key = load_api_key_from_file(PRIMARY_DOTENV_FILE)
        if direct_key:
            api_key = direct_key
            os.environ[AI_ASSISTANT_API_KEY_ENV] = api_key
            LAST_ASSISTANT_CONFIG_SOURCE = f"hardwired:{PRIMARY_DOTENV_FILE}"

    if not api_key:
        discovered = discover_local_api_key()
        if discovered:
            api_key = discovered
            os.environ[AI_ASSISTANT_API_KEY_ENV] = api_key
            LAST_ASSISTANT_CONFIG_SOURCE = "file-discovery"

    model = str(os.environ.get(AI_ASSISTANT_MODEL_ENV, DEFAULT_AI_ASSISTANT_MODEL)).strip()
    if not model:
        model = DEFAULT_AI_ASSISTANT_MODEL

    endpoint = normalize_assistant_endpoint(
        os.environ.get(AI_ASSISTANT_API_URL_ENV, DEFAULT_AI_ASSISTANT_API_URL)
    )
    os.environ[AI_ASSISTANT_API_URL_ENV] = endpoint

    return api_key, model, endpoint


def save_local_ai_settings_file(api_key: str) -> bool:
    normalized_key = normalize_external_api_key(api_key)
    if not normalized_key:
        return False

    payload = {
        "api_key": normalized_key,
        "model": os.environ.get(AI_ASSISTANT_MODEL_ENV, DEFAULT_AI_ASSISTANT_MODEL).strip()
        or DEFAULT_AI_ASSISTANT_MODEL,
        "api_url": os.environ.get(AI_ASSISTANT_API_URL_ENV, DEFAULT_AI_ASSISTANT_API_URL).strip()
        or DEFAULT_AI_ASSISTANT_API_URL,
    }

    try:
        AI_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        AI_SETTINGS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        AI_SETTINGS_FILE.chmod(0o600)
        return True
    except OSError:
        return False


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
        "security_ai_learning_enabled": DEFAULT_SECURITY_AI_LEARNING_ENABLED,
        "ai_learning_state": normalize_ai_learning_state({}),
        "ai_help_learning_state": normalize_ai_help_learning_state({}),
        "ai_help_chat_state": normalize_ai_help_chat_state({}),
        "vault_integrity_hash": "",
        "vault_integrity_last_verified": 0,
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
                security_ai_learning_enabled = to_bool(
                    data.get(
                        "security_ai_learning_enabled",
                        DEFAULT_SECURITY_AI_LEARNING_ENABLED,
                    ),
                    DEFAULT_SECURITY_AI_LEARNING_ENABLED,
                )
                ai_learning_state = normalize_ai_learning_state(data.get("ai_learning_state", {}))
                ai_help_learning_state = normalize_ai_help_learning_state(
                    data.get("ai_help_learning_state", {})
                )
                ai_help_chat_state = normalize_ai_help_chat_state(
                    data.get("ai_help_chat_state", {})
                )
                vault_salt = normalize_vault_salt(data.get("vault_salt", ""))
                vault_integrity_hash = normalize_hex_digest(
                    data.get("vault_integrity_hash", "")
                )
                vault_integrity_last_verified = clamp_int(
                    data.get("vault_integrity_last_verified", 0),
                    0,
                    0,
                    2_147_483_647,
                )
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
                        "security_ai_learning_enabled": security_ai_learning_enabled,
                        "ai_learning_state": ai_learning_state,
                        "ai_help_learning_state": ai_help_learning_state,
                        "ai_help_chat_state": ai_help_chat_state,
                        "vault_integrity_hash": vault_integrity_hash,
                        "vault_integrity_last_verified": vault_integrity_last_verified,
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
                        "security_ai_learning_enabled": security_ai_learning_enabled,
                        "ai_learning_state": ai_learning_state,
                        "ai_help_learning_state": ai_help_learning_state,
                        "ai_help_chat_state": ai_help_chat_state,
                        "vault_integrity_hash": vault_integrity_hash,
                        "vault_integrity_last_verified": vault_integrity_last_verified,
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
        "security_ai_learning_enabled": to_bool(
            credentials.get("security_ai_learning_enabled", DEFAULT_SECURITY_AI_LEARNING_ENABLED),
            DEFAULT_SECURITY_AI_LEARNING_ENABLED,
        ),
        "ai_learning_state": normalize_ai_learning_state(credentials.get("ai_learning_state", {})),
        "ai_help_learning_state": normalize_ai_help_learning_state(
            credentials.get("ai_help_learning_state", {})
        ),
        "ai_help_chat_state": normalize_ai_help_chat_state(
            credentials.get("ai_help_chat_state", {})
        ),
        "vault_integrity_hash": normalize_hex_digest(credentials.get("vault_integrity_hash", "")),
        "vault_integrity_last_verified": clamp_int(
            credentials.get("vault_integrity_last_verified", 0),
            0,
            0,
            2_147_483_647,
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

        integrity_hash = hashlib.sha256(DATA_FILE.read_bytes()).hexdigest()
        credentials["vault_integrity_hash"] = integrity_hash
        if not save_credentials(credentials):
            print("Warning: Vault integrity metadata could not be updated in config.")
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
    print("\nChoose an option:")
    print("1) Add Data")
    print("2) List all keys")
    print("3) Search keys")
    print("4) Retrieve Data by Key")
    print("5) Delete Data by Key")
    print("6) Change Username/Password")
    print("7) Security Settings")
    print("8) Remove Data-bank Files (Data-bank files only)")
    print("9) Security Analytics Report (requires strong verification)")
    print("10) Data Integrity Check")
    print("11) Support Assistant")
    print("12) Exit")


def view_security_analytics_report(credentials: dict[str, object]) -> None:
    """Show a protected summary of Security AI detections and risk events."""
    print("\nSecurity Analytics Report")
    print("This report requires password confirmation")
    print("and 2-step verification if it is enabled.")

    if not authorize_sensitive_security_action(credentials):
        monitor_sensitive_action_failure("security_report_access_denied")
        print("Access denied: unable to verify identity for Security Analytics Report.")
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

    learning_enabled = to_bool(
        credentials.get("security_ai_learning_enabled", DEFAULT_SECURITY_AI_LEARNING_ENABLED),
        DEFAULT_SECURITY_AI_LEARNING_ENABLED,
    )
    learning_state = normalize_ai_learning_state(credentials.get("ai_learning_state", {}))
    learning_confidence = min(1.0, learning_state["sample_count"] / 8.0)

    print("\nAdaptive learning status:")
    print(f"- Enabled: {'Yes' if learning_enabled else 'No'}")
    print(f"- Sample count: {int(learning_state['sample_count'])}")
    print(f"- Learning confidence: {int(learning_confidence * 100)}%")
    print(f"- Learned failed-login baseline (24h EWMA): {learning_state['failed_login_ewma']:.2f}")
    print(f"- Learned vault-access baseline (24h EWMA): {learning_state['vault_access_ewma']:.2f}")
    print(f"- Learned unique-key baseline (24h EWMA): {learning_state['unique_key_ewma']:.2f}")

    print("\nActive Security AI thresholds:")
    print(f"- Failed login threshold: {ACTIVE_SECURITY_FAILED_LOGIN_THRESHOLD}")
    print(f"- Multi-user failed login threshold: {ACTIVE_SECURITY_FAILED_LOGIN_USER_THRESHOLD}")
    print(
        "- Single-user failed login spike threshold: "
        f"{ACTIVE_SECURITY_SINGLE_USER_FAILED_LOGIN_SPIKE_THRESHOLD}"
    )
    print(f"- Vault burst threshold: {ACTIVE_SECURITY_VAULT_BURST_THRESHOLD}")
    print(f"- Unique-key threshold: {ACTIVE_SECURITY_UNIQUE_KEY_THRESHOLD}")
    print(f"- Alert confirmations required: {ACTIVE_SECURITY_VAULT_ALERT_CONFIRMATIONS}")

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


def run_data_integrity_check(vault: dict[str, str], credentials: dict[str, object]) -> None:
    """Validate vault data integrity and report any corruption or mismatch."""
    print("\nData Integrity Check")

    if not DATA_FILE.exists():
        print("No vault file exists yet. Save data first, then run integrity check.")
        return

    expected_hash = normalize_hex_digest(credentials.get("vault_integrity_hash", ""))
    try:
        file_bytes = DATA_FILE.read_bytes()
    except OSError as error:
        print(f"Integrity check failed: could not read vault file ({error}).")
        log_security_event("integrity_check_failed", {"reason": "vault_read_error"})
        return

    actual_hash = hashlib.sha256(file_bytes).hexdigest()
    if expected_hash and not hmac.compare_digest(expected_hash, actual_hash):
        print("Integrity check FAILED: vault file hash does not match the last trusted save.")
        security_ai_alert(
            "vault_integrity_hash_mismatch",
            "Vault integrity hash mismatch detected. Possible tampering or corruption.",
            cooldown_seconds=30,
        )
        log_security_event("integrity_check_failed", {"reason": "hash_mismatch"})
        return

    session_password = get_session_password()
    if session_password is None:
        print("Integrity check failed: no active authenticated session.")
        log_security_event("integrity_check_failed", {"reason": "missing_session"})
        return

    try:
        file_payload = json.loads(file_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("Integrity check FAILED: vault file is not valid JSON.")
        log_security_event("integrity_check_failed", {"reason": "invalid_json"})
        return

    if not isinstance(file_payload, dict):
        print("Integrity check FAILED: vault payload format is invalid.")
        log_security_event("integrity_check_failed", {"reason": "invalid_payload"})
        return

    ciphertext = file_payload.get("ciphertext")
    if not isinstance(ciphertext, str) or not ciphertext:
        print("Integrity check FAILED: encrypted vault payload is missing.")
        log_security_event("integrity_check_failed", {"reason": "missing_ciphertext"})
        return

    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    decrypted_payload = decrypt_text_with_password(ciphertext, session_password, vault_salt)
    if decrypted_payload is None:
        print("Integrity check FAILED: vault decryption/authentication failed.")
        security_ai_alert(
            "vault_integrity_decrypt_failed",
            "Vault authentication failed during integrity check.",
            cooldown_seconds=30,
        )
        log_security_event("integrity_check_failed", {"reason": "decrypt_failed"})
        return

    try:
        parsed_vault = json.loads(decrypted_payload)
    except json.JSONDecodeError:
        print("Integrity check FAILED: decrypted data is not valid JSON.")
        log_security_event("integrity_check_failed", {"reason": "decrypted_invalid_json"})
        return

    if not isinstance(parsed_vault, dict):
        print("Integrity check FAILED: decrypted payload is not a key/value object.")
        log_security_event("integrity_check_failed", {"reason": "decrypted_invalid_payload"})
        return

    normalized_loaded = {str(key): str(value) for key, value in parsed_vault.items()}
    if normalized_loaded != vault:
        print("Integrity warning: in-memory vault differs from file. Latest in-memory edits may be unsaved.")

    credentials["vault_integrity_hash"] = actual_hash
    credentials["vault_integrity_last_verified"] = int(time.time())
    if save_credentials(credentials):
        print("Integrity check PASSED: vault data and encryption auth tag are valid.")
    else:
        print("Integrity check passed, but metadata timestamp could not be saved.")

    log_security_event(
        "integrity_check_passed",
        {"keys": len(normalized_loaded)},
    )


def run_startup_integrity_check(vault: dict[str, str], credentials: dict[str, object]) -> None:
    """Run a periodic warning-only integrity check at startup without blocking access."""
    if not DATA_FILE.exists():
        return

    expected_hash = normalize_hex_digest(credentials.get("vault_integrity_hash", ""))
    if not expected_hash:
        return

    last_verified = clamp_int(
        credentials.get("vault_integrity_last_verified", 0),
        0,
        0,
        2_147_483_647,
    )
    now = int(time.time())
    if last_verified > 0 and now - last_verified < STARTUP_INTEGRITY_CHECK_INTERVAL_SECONDS:
        return

    print("\nStartup integrity check: verifying vault integrity (warning-only).")

    try:
        file_bytes = DATA_FILE.read_bytes()
    except OSError:
        print("WARNING: Startup integrity check could not read the vault file.")
        log_security_event("startup_integrity_check_failed", {"reason": "vault_read_error"})
        return

    actual_hash = hashlib.sha256(file_bytes).hexdigest()
    if not hmac.compare_digest(expected_hash, actual_hash):
        print("WARNING: Startup integrity check found a vault hash mismatch.")
        print("Data-bank will continue in warning-only mode. Run a manual Data Integrity Check for details.")
        security_ai_alert(
            "startup_vault_integrity_hash_mismatch",
            "Startup integrity check detected a vault hash mismatch.",
            cooldown_seconds=30,
        )
        log_security_event("startup_integrity_check_failed", {"reason": "hash_mismatch"})
        return

    try:
        file_payload = json.loads(file_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("WARNING: Startup integrity check found invalid vault JSON format.")
        log_security_event("startup_integrity_check_failed", {"reason": "invalid_json"})
        return

    if not isinstance(file_payload, dict):
        print("WARNING: Startup integrity check found invalid vault payload format.")
        log_security_event("startup_integrity_check_failed", {"reason": "invalid_payload"})
        return

    ciphertext = file_payload.get("ciphertext")
    if not isinstance(ciphertext, str) or not ciphertext:
        print("WARNING: Startup integrity check found missing encrypted vault payload.")
        log_security_event("startup_integrity_check_failed", {"reason": "missing_ciphertext"})
        return

    session_password = get_session_password()
    if session_password is None:
        print("WARNING: Startup integrity check could not verify decrypted payload (no active session).")
        log_security_event("startup_integrity_check_failed", {"reason": "missing_session"})
        return

    vault_salt = normalize_vault_salt(credentials.get("vault_salt", ""))
    decrypted_payload = decrypt_text_with_password(ciphertext, session_password, vault_salt)
    if decrypted_payload is None:
        print("WARNING: Startup integrity check could not authenticate encrypted vault payload.")
        security_ai_alert(
            "startup_vault_integrity_decrypt_failed",
            "Startup integrity check failed vault authentication.",
            cooldown_seconds=30,
        )
        log_security_event("startup_integrity_check_failed", {"reason": "decrypt_failed"})
        return

    try:
        parsed_vault = json.loads(decrypted_payload)
    except json.JSONDecodeError:
        print("WARNING: Startup integrity check found invalid decrypted vault JSON.")
        log_security_event("startup_integrity_check_failed", {"reason": "decrypted_invalid_json"})
        return

    if not isinstance(parsed_vault, dict):
        print("WARNING: Startup integrity check found invalid decrypted payload shape.")
        log_security_event("startup_integrity_check_failed", {"reason": "decrypted_invalid_payload"})
        return

    normalized_loaded = {str(key): str(value) for key, value in parsed_vault.items()}
    if normalized_loaded != vault:
        print("WARNING: Startup integrity check found in-memory and file vault mismatch (possible unsaved edits).")

    credentials["vault_integrity_hash"] = actual_hash
    credentials["vault_integrity_last_verified"] = now
    if not save_credentials(credentials):
        print("WARNING: Startup integrity check passed but could not update verification metadata.")

    log_security_event("startup_integrity_check_passed", {"keys": len(normalized_loaded)})


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


def search_keys(vault: dict[str, str]) -> None:
    query = prompt("Enter text to search in keys: ")
    if query is None:
        return

    normalized_query = query.strip().lower()
    if not normalized_query:
        print("Search text cannot be empty.")
        return

    monitor_vault_access_activity("search_keys", normalized_query)

    matches = [
        key
        for key in sorted(vault.keys())
        if normalized_query in key.lower()
    ]

    if not matches:
        print("No keys matched your search.")
        return

    print("Matching keys:")
    for key in matches:
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
    print(
        "Security AI Adaptive Learning: "
        f"{'Enabled' if to_bool(credentials.get('security_ai_learning_enabled', DEFAULT_SECURITY_AI_LEARNING_ENABLED), DEFAULT_SECURITY_AI_LEARNING_ENABLED) else 'Disabled'}"
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

    sensitivity_choice = prompt("Security AI sensitivity (high/normal/low/keep): ")
    if sensitivity_choice is None:
        return

    learning_choice = prompt("Security AI adaptive learning (enable/disable/keep): ")
    if learning_choice is None:
        return

    if (
        not new_attempts_input
        and not new_lockout_input
        and not two_step_choice
        and not regen_choice
        and not sensitivity_choice
        and not learning_choice
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

    learning_normalized = learning_choice.strip().lower()
    if learning_normalized in {"enable", "on", "yes", "y"}:
        credentials["security_ai_learning_enabled"] = True
        print("Security AI adaptive learning enabled.")
    elif learning_normalized in {"disable", "off", "no", "n"}:
        credentials["security_ai_learning_enabled"] = False
        print("Security AI adaptive learning disabled.")
    elif learning_normalized in {"", "keep"}:
        pass
    else:
        print("Unknown adaptive learning choice. Keeping current setting.")

    apply_security_ai_profile(credentials)

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
    ai_learning = to_bool(
        credentials.get("security_ai_learning_enabled", DEFAULT_SECURITY_AI_LEARNING_ENABLED),
        DEFAULT_SECURITY_AI_LEARNING_ENABLED,
    )
    print(
        "Active security policy: "
        f"max_login_attempts={max_attempts}, "
        f"lockout={lockout_display}, "
        f"two_step={two_step_status}, "
        f"two_step_method={two_step_method}, "
        f"backup_codes={backup_count}, "
        f"security_ai_sensitivity={ai_sensitivity}, "
        f"security_ai_learning={'enabled' if ai_learning else 'disabled'}"
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


def ai_help_response(question: str, credentials: dict[str, object]) -> str:
    query = question.strip()
    if not query:
        return "Ask your question and I’ll help with the exact next steps in Data-bank."

    clear_ai_help_pending_question(credentials)
    external_response = generate_external_ai_help_response(query, credentials)
    if external_response:
        return external_response

    reason = LAST_EXTERNAL_AI_ERROR.strip() or "external API unavailable"
    return (
        "Support Assistant requires external AI right now, but the request failed "
        f"({reason}). Check preconfigured API key/network and try again. "
        "Expected key source: DATABANK_AI_API_KEY in .env or ai_settings.json."
    )


def extract_text_candidates(value: object) -> list[str]:
    results: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            text_value = node.strip()
            if text_value:
                results.append(text_value)
            return

        if isinstance(node, dict):
            prioritized_text_fields = ("output_text", "text", "content")
            for key in prioritized_text_fields:
                if key in node:
                    walk(node[key])

            for key, child in node.items():
                if key in prioritized_text_fields:
                    continue
                walk(child)
            return

        if isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return results


def generate_external_ai_help_response(
    question: str,
    credentials: dict[str, object],
) -> Optional[str]:
    global LAST_EXTERNAL_AI_ERROR
    global LAST_EXTERNAL_AI_USED

    LAST_EXTERNAL_AI_ERROR = ""
    LAST_EXTERNAL_AI_USED = False
    api_key, model, endpoint = assistant_runtime_config()
    if not api_key:
        LAST_EXTERNAL_AI_ERROR = "missing API key"
        return None
    os.environ[AI_ASSISTANT_API_KEY_ENV] = api_key

    user_question = question.strip()
    if not user_question:
        return None
    user_question = user_question[:AI_ASSISTANT_MAX_QUESTION_CHARS]

    two_step_enabled = is_two_step_enabled(credentials)
    two_step_method = configured_two_step_method(credentials)
    backup_codes_left = len(normalize_backup_code_hashes(credentials.get("backup_code_hashes", [])))
    ai_sensitivity = normalize_security_ai_sensitivity(
        credentials.get("security_ai_sensitivity", DEFAULT_SECURITY_AI_SENSITIVITY)
    )
    ai_learning_enabled = to_bool(
        credentials.get("security_ai_learning_enabled", DEFAULT_SECURITY_AI_LEARNING_ENABLED),
        DEFAULT_SECURITY_AI_LEARNING_ENABLED,
    )

    system_context = (
        "You are the Data-bank Support Assistant for a CLI app. "
        "You are the primary responder: do not use canned templates and do not mention internal fallback logic. "
        "Give practical, natural guidance based on the user's request and context. "
        "When helpful, map actions to menu options exactly as follows: "
        "1 Add Data, 2 List all keys, 3 Search keys, 4 Retrieve Data by Key, 5 Delete Data by Key, "
        "6 Change Username/Password, 7 Security Settings, 8 Remove Data-bank Files, "
        "9 Security Analytics Report, 10 Data Integrity Check, 11 Support Assistant, 12 Exit. "
        "Never invent option numbers or features. "
        "Never ask for API keys, passwords, 2-step codes, or recovery codes. "
        "Keep responses concise and clear, usually 2-6 sentences, but prioritize correctness over brevity. "
        f"Current security context: two_step_enabled={two_step_enabled}, "
        f"two_step_method={two_step_method}, backup_codes_left={backup_codes_left}, "
        f"security_ai_sensitivity={ai_sensitivity}, security_ai_learning_enabled={ai_learning_enabled}."
    )

    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": system_context},
            {"role": "user", "content": user_question},
        ],
    }

    request = Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=AI_ASSISTANT_REQUEST_TIMEOUT_SECONDS) as response:
            response_body = response.read().decode("utf-8")
    except HTTPError as error:
        detail = ""
        try:
            error_body = error.read().decode("utf-8")
            parsed_error = json.loads(error_body)
            if isinstance(parsed_error, dict):
                payload = parsed_error.get("error")
                if isinstance(payload, dict):
                    detail = str(payload.get("message", "")).strip()
        except (OSError, ValueError, json.JSONDecodeError):
            detail = ""

        if detail:
            LAST_EXTERNAL_AI_ERROR = f"HTTP {error.code}: {detail}"
        else:
            LAST_EXTERNAL_AI_ERROR = f"HTTP {error.code}"
        return None
    except URLError as error:
        LAST_EXTERNAL_AI_ERROR = f"network error: {error.reason}"
        return None
    except TimeoutError:
        LAST_EXTERNAL_AI_ERROR = "request timed out"
        return None
    except (OSError, ValueError):
        LAST_EXTERNAL_AI_ERROR = "request failed"
        return None

    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError:
        LAST_EXTERNAL_AI_ERROR = "invalid JSON response"
        return None

    if not isinstance(parsed, dict):
        LAST_EXTERNAL_AI_ERROR = "invalid response payload"
        return None

    error_payload = parsed.get("error")
    if isinstance(error_payload, dict):
        message = str(error_payload.get("message", "")).strip()
        LAST_EXTERNAL_AI_ERROR = message or "API returned an error"
        return None

    prioritized_sections: list[object] = [
        parsed.get("output_text"),
        parsed.get("output"),
        parsed.get("choices"),
        parsed,
    ]

    for section in prioritized_sections:
        for candidate in extract_text_candidates(section):
            if candidate and not candidate.startswith("{"):
                LAST_EXTERNAL_AI_USED = True
                return candidate

    status = str(parsed.get("status", "")).strip()
    if status:
        LAST_EXTERNAL_AI_ERROR = f"no assistant text in API response (status={status})"
    else:
        LAST_EXTERNAL_AI_ERROR = "no assistant text in API response"
    return None


def support_assistant_next_step(topic: str, confidence: float, user_question: str) -> str:
    normalized = user_question.strip().lower()
    if normalized.isdigit():
        value = int(normalized)
        if 1 <= value <= 12:
            return f"Next step: use option {value} from the main menu."

    option_match = re.search(r"\boption\s*(\d{1,2})\b", normalized)
    if option_match:
        value = int(option_match.group(1))
        if 1 <= value <= 12:
            return f"Next step: use option {value} from the main menu."

    if confidence < 0.2:
        return "Next step: try option 2 (List all keys) to see what’s currently stored."

    suggestions = {
        "two_step": "Next step: open option 7 (Security Settings) to enable or manage two-step verification.",
        "backup": "Next step: open option 7 (Security Settings) to regenerate or review backup recovery codes.",
        "integrity": "Next step: run option 10 (Data Integrity Check).",
        "security_ai": "Next step: open option 9 (Security Analytics Report).",
        "cleanup": "Next step: use option 8 (Remove Data-bank Files) only if you want cleanup.",
        "credentials": "Next step: use option 6 (Change Username/Password).",
        "vault_ops": "Next step: use option 1 to add data, or option 3 to search keys.",
        "general": "Next step: use option 2 (List all keys) or option 1 (Add Data).",
    }
    return suggestions.get(topic, suggestions["general"])


def ai_help_chat(credentials: dict[str, object]) -> None:
    def wants_to_exit_help_chat(text: str) -> bool:
        lowered = text.strip().lower()
        if not lowered:
            return False

        direct_commands = {
            "back",
            "exit",
            "quit",
            "stop",
            "menu",
            "close",
            "bye",
        }
        if lowered in direct_commands:
            return True

        exit_phrases = (
            "go back",
            "back to menu",
            "exit chat",
            "quit chat",
            "stop chat",
            "leave chat",
            "end chat",
        )
        return any(phrase in lowered for phrase in exit_phrases)

    print("\nSupport Assistant")
    print("Ask simple Data-bank usage and security questions.")
    api_key, _model, _endpoint = assistant_runtime_config()
    if not api_key:
        # Fail-safe retry for intermittent env loading edge cases.
        recovered = load_api_key_from_file(PRIMARY_DOTENV_FILE)
        if recovered:
            os.environ[AI_ASSISTANT_API_KEY_ENV] = recovered
            api_key, _model, _endpoint = assistant_runtime_config()
    api_key_loaded = bool(api_key)
    if not api_key_loaded and AI_ASSISTANT_ALLOW_RUNTIME_KEY_PROMPT:
        entered_api_key = prompt_password_masked(
            "API key not loaded. Paste OpenAI key now (or press Enter to skip): "
        )
        if entered_api_key:
            normalized_key = normalize_external_api_key(entered_api_key)
            if normalized_key:
                os.environ[AI_ASSISTANT_API_KEY_ENV] = normalized_key
                api_key_loaded = True
                persist_choice = prompt("Save this key for future app launches? (y/N): ")
                if persist_choice and persist_choice.strip().lower() in {"y", "yes"}:
                    if save_local_ai_settings_file(normalized_key):
                        print(f"Saved API settings to {AI_SETTINGS_FILE}")
                    else:
                        print("Could not save API settings file.")
            else:
                print("API key format was not recognized. Please paste only the key value.")

    if not api_key_loaded:
        print(
            "API key was not found in preconfigured sources. "
            "Expected: DATABANK_AI_API_KEY in .env or ai_settings.json."
        )
        print("Runtime key entry is disabled for this build.")

    print("Mode: External AI API")
    print(f"API key loaded: {'yes' if api_key_loaded else 'no'}")
    if api_key_loaded:
        print(f"API config source: {LAST_ASSISTANT_CONFIG_SOURCE or 'unknown'}")
    print("Type 'back' (or 'exit', 'quit', 'stop', 'bye') to return to the main menu.")

    while True:
        user_question = prompt("Support Assistant > ")
        if user_question is None:
            print("Leaving Support Assistant.")
            return

        if wants_to_exit_help_chat(user_question):
            print("Leaving Support Assistant.")
            return

        learn_from_ai_help_question(credentials, user_question)
        response = ai_help_response(user_question, credentials)
        save_credentials(credentials)
        print(f"Support Assistant: {response}")


def main() -> None:
    if not sys.stdin.isatty():
        print("Warning: non-interactive input mode detected.")
        print("If prompts do not accept input, run from an interactive terminal.")

    load_local_dotenv()
    load_local_ai_settings_file()
    show_storage_info()
    build_program_help_index()
    first_run = not CONFIG_FILE.exists()
    if first_run:
        print("First-time setup detected for Data-bank.")
        print(f"A storage folder is being used at: {STORAGE_DIR}")
        print("Data-bank will create required files for your account and vault data.")

    credentials = load_credentials()
    apply_security_ai_profile(credentials)
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
    run_startup_integrity_check(vault, credentials)

    while True:
        show_menu()
        choice = prompt("Enter your choice (1-12): ")
        if choice is None:
            print("Goodbye.")
            break

        if choice == "1":
            add_data(vault, credentials)
        elif choice == "2":
            list_data(vault)
        elif choice == "3":
            search_keys(vault)
        elif choice == "4":
            retrieve_data(vault)
        elif choice == "5":
            delete_data(vault, credentials)
        elif choice == "6":
            change_credentials(credentials, vault)
        elif choice == "7":
            change_security_settings(credentials)
        elif choice == "8":
            if remove_databank_files(credentials):
                break
        elif choice == "9":
            view_security_analytics_report(credentials)
        elif choice == "10":
            run_data_integrity_check(vault, credentials)
        elif choice == "11":
            ai_help_chat(credentials)
        elif choice == "12":
            print("You are being securely logged out of Data-bank. Goodbye.")
            set_session_password(None)
            break
        else:
            print("Invalid option. Please enter 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, or 12.")


if __name__ == "__main__":
    main()