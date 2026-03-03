"""
Focused tests for generate_external_ai_help_response.

Verifies every reachable code path:
  - missing API key
  - HTTP 4xx with a JSON error body (e.g. 401 bad key)
  - HTTP 4xx with an unreadable / non-JSON body
  - network timeout (URLError wrapping socket.timeout)
  - generic network error (URLError with plain reason)
  - OSError / ValueError from urlopen
  - invalid JSON response body
  - well-formed response with no assistant text
  - successful response – output_text field
  - successful response – choices[0].message.content field
  - HTTPS enforcement (http:// URL falls back to default)
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import socket
import sys
import unittest
from http.client import HTTPMessage
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError


# ---------------------------------------------------------------------------
# Load the module under test without executing its __main__ block
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent
_DATABANK_PATH = _ROOT / "DATABANK.PY"

loader = SourceFileLoader("databank_module", str(_DATABANK_PATH))
spec = importlib.util.spec_from_loader("databank_module", loader)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)

generate = _mod.generate_external_ai_help_response
AI_KEY_ENV = _mod.AI_ASSISTANT_API_KEY_ENV
AI_URL_ENV = _mod.AI_ASSISTANT_API_URL_ENV
AI_MODEL_ENV = _mod.AI_ASSISTANT_MODEL_ENV
DEFAULT_URL = _mod.DEFAULT_AI_ASSISTANT_API_URL

_VALID_KEY = "sk-testkey1234567890abcdefghijklmnop"  # nosec B105 - test-only placeholder key

_DUMMY_CREDS: dict = {
    "username": "guest",
    "two_step_enabled": False,
    "two_step_method": "custom_code",
    "backup_code_hashes": [],
    "security_ai_sensitivity": "high",
    "security_ai_learning_enabled": True,
}


def _http_error(code: int, body: bytes) -> HTTPError:
    """Build an HTTPError whose .read() returns *body*."""
    fp = io.BytesIO(body)
    return HTTPError(
        url="https://api.openai.com/v1/responses",
        code=code,
        msg="",
        hdrs=HTTPMessage(),
        fp=fp,
    )


def _ok_response(payload: dict) -> MagicMock:
    """Build a context-manager mock whose .read() returns JSON bytes."""
    body = json.dumps(payload).encode()
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read = MagicMock(return_value=body)
    return cm


class TestGenerateExternalAIHelpResponse(unittest.TestCase):

    def setUp(self):
        # Ensure a clean environment for every test
        for var in (AI_KEY_ENV, AI_URL_ENV, AI_MODEL_ENV):
            os.environ.pop(var, None)
        _mod.LAST_EXTERNAL_AI_ERROR = ""
        _mod.LAST_EXTERNAL_AI_USED = False

    # ------------------------------------------------------------------
    # 1. Missing API key
    # ------------------------------------------------------------------
    def test_missing_api_key_returns_none(self):
        result = generate("how do I add data?", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertIn("missing API key", _mod.LAST_EXTERNAL_AI_ERROR)

    # ------------------------------------------------------------------
    # 2. HTTP 401 with a structured JSON error body
    # ------------------------------------------------------------------
    def test_http_401_with_json_body(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        body = json.dumps({"error": {"message": "Incorrect API key provided."}}).encode()
        with patch.object(_mod, "urlopen", side_effect=_http_error(401, body)):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertIn("401", _mod.LAST_EXTERNAL_AI_ERROR)
        self.assertIn("Incorrect API key provided", _mod.LAST_EXTERNAL_AI_ERROR)

    # ------------------------------------------------------------------
    # 3. HTTP 400 with unreadable body (non-JSON)
    # ------------------------------------------------------------------
    def test_http_400_with_non_json_body(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        body = b"<html>Bad Request</html>"
        with patch.object(_mod, "urlopen", side_effect=_http_error(400, body)):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertEqual(_mod.LAST_EXTERNAL_AI_ERROR, "HTTP 400")

    # ------------------------------------------------------------------
    # 4. Timeout (URLError wrapping socket.timeout) → "request timed out"
    # ------------------------------------------------------------------
    def test_timeout_sets_correct_error(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        with patch.object(_mod, "urlopen", side_effect=URLError(socket.timeout("timed out"))):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertEqual(_mod.LAST_EXTERNAL_AI_ERROR, "request timed out")

    # ------------------------------------------------------------------
    # 5. Generic network error (URLError with a string reason)
    # ------------------------------------------------------------------
    def test_network_error_sets_correct_error(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        with patch.object(_mod, "urlopen", side_effect=URLError("Name or service not known")):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertIn("network error", _mod.LAST_EXTERNAL_AI_ERROR)

    # ------------------------------------------------------------------
    # 6. OSError from urlopen
    # ------------------------------------------------------------------
    def test_oserror_sets_request_failed(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        with patch.object(_mod, "urlopen", side_effect=OSError("connection reset")):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertEqual(_mod.LAST_EXTERNAL_AI_ERROR, "request failed")

    # ------------------------------------------------------------------
    # 7. Invalid JSON in response body
    # ------------------------------------------------------------------
    def test_invalid_json_response(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=b"not json at all")
        with patch.object(_mod, "urlopen", return_value=cm):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertIn("invalid JSON", _mod.LAST_EXTERNAL_AI_ERROR)

    # ------------------------------------------------------------------
    # 8. Well-formed response with no assistant text
    # ------------------------------------------------------------------
    def test_no_text_in_response(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        # An empty output list with no string values anywhere in the payload
        # is the only way to reach the "no assistant text" branch, because the
        # walker in extract_text_candidates also traverses the whole parsed dict.
        payload = {"output": []}
        with patch.object(_mod, "urlopen", return_value=_ok_response(payload)):
            result = generate("test", _DUMMY_CREDS)
        self.assertIsNone(result)
        self.assertIn("no assistant text", _mod.LAST_EXTERNAL_AI_ERROR)

    # ------------------------------------------------------------------
    # 9. Successful response via output_text field
    # ------------------------------------------------------------------
    def test_successful_output_text(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        payload = {"output_text": "Use option 1 to add data."}
        with patch.object(_mod, "urlopen", return_value=_ok_response(payload)):
            result = generate("how do I add data?", _DUMMY_CREDS)
        self.assertEqual(result, "Use option 1 to add data.")
        self.assertTrue(_mod.LAST_EXTERNAL_AI_USED)
        self.assertEqual(_mod.LAST_EXTERNAL_AI_ERROR, "")

    # ------------------------------------------------------------------
    # 10. Successful response via choices[0].message.content (ChatCompletion)
    # ------------------------------------------------------------------
    def test_successful_choices_path(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        payload = {
            "choices": [{"message": {"content": "Use option 4 to retrieve data."}}]
        }
        with patch.object(_mod, "urlopen", return_value=_ok_response(payload)):
            result = generate("how do I retrieve a key?", _DUMMY_CREDS)
        self.assertEqual(result, "Use option 4 to retrieve data.")
        self.assertTrue(_mod.LAST_EXTERNAL_AI_USED)

    # ------------------------------------------------------------------
    # 11. HTTPS enforcement: http:// URL must fall back to default endpoint
    # ------------------------------------------------------------------
    def test_https_enforcement_falls_back_to_default(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        os.environ[AI_URL_ENV] = "http://evil.example.com/v1/completions"
        captured_urls: list[str] = []

        def fake_urlopen(request, timeout):
            captured_urls.append(request.full_url)
            return _ok_response({"output_text": "ok"})

        with patch.object(_mod, "urlopen", side_effect=fake_urlopen):
            generate("test", _DUMMY_CREDS)

        self.assertEqual(len(captured_urls), 1)
        self.assertEqual(captured_urls[0], DEFAULT_URL,
                         "http:// URL should have been replaced with the default HTTPS endpoint")

    # ------------------------------------------------------------------
    # 12. Empty question is rejected early without making a network call
    # ------------------------------------------------------------------
    def test_empty_question_returns_none_without_network(self):
        os.environ[AI_KEY_ENV] = _VALID_KEY
        with patch.object(_mod, "urlopen") as mock_open:
            result = generate("   ", _DUMMY_CREDS)
        self.assertIsNone(result)
        mock_open.assert_not_called()

    # ------------------------------------------------------------------
    # 13. load_local_dotenv picks up OPENAI_API_KEY already in OS env
    # ------------------------------------------------------------------
    def test_load_local_dotenv_picks_up_os_openai_key(self):
        """load_local_dotenv should import OPENAI_API_KEY from the OS environment."""
        os.environ.pop(AI_KEY_ENV, None)
        os.environ["OPENAI_API_KEY"] = _VALID_KEY
        try:
            _mod.load_local_dotenv()
            self.assertEqual(os.environ.get(AI_KEY_ENV, ""), _VALID_KEY)
        finally:
            os.environ.pop("OPENAI_API_KEY", None)
            os.environ.pop(AI_KEY_ENV, None)

    # ------------------------------------------------------------------
    # 14. load_local_dotenv picks up OPENAI_KEY alias already in OS env
    # ------------------------------------------------------------------
    def test_load_local_dotenv_picks_up_os_openai_key_alias(self):
        """load_local_dotenv should also accept the OPENAI_KEY alias."""
        os.environ.pop(AI_KEY_ENV, None)
        os.environ["OPENAI_KEY"] = _VALID_KEY
        try:
            _mod.load_local_dotenv()
            self.assertEqual(os.environ.get(AI_KEY_ENV, ""), _VALID_KEY)
        finally:
            os.environ.pop("OPENAI_KEY", None)
            os.environ.pop(AI_KEY_ENV, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
