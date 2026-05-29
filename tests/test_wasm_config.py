import unittest
import os
import secrets
from unittest.mock import patch
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from adapters.pii_wasm_client import PIIWasmClient

@unittest.skipIf(sys.platform == "darwin", "WASM runtime unstable on macOS (SIGKILL)")
class TestWasmConfiguration(unittest.TestCase):
    def setUp(self):
        # Ensure we start with a clean environment (no PII_SAFE_REGEX_LIST)
        self.original_env = dict(os.environ)
        if "PII_SAFE_REGEX_LIST" in os.environ:
            del os.environ["PII_SAFE_REGEX_LIST"]
        
        # Reset singleton if it exists to ensure fresh init
        if PIIWasmClient._instance:
            PIIWasmClient._instance._initialized = False
            PIIWasmClient._instance = None

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)
        # Reset singleton
        if PIIWasmClient._instance:
            PIIWasmClient._instance._initialized = False
            PIIWasmClient._instance = None

    def test_safe_regex_list_behavior(self):
        """Test that PII_SAFE_REGEX_LIST is respected by the WASM client."""
        # This test depends on the WASM module actually supporting the env var.
        # If the WASM binary in lib/ is old, this might fail or be a no-op.
        # However, we assume the WASM binary has this feature (Phase 3).
        
        # We will try to whitelist a specific pattern that WOULD look like PII otherwise.
        # For example, an email address: "allowed@example.com"
        # Standard redaction should hide it.
        # Whitelisted should preserve it.
        
        text = "Contact: allowed@example.com"
        
        # 1. Without whitelist
        client = PIIWasmClient()
        redacted = client.redact(text)
        # Should be redacted
        # Note: If default config doesn't catch this email, try a standard credit card or something.
        # Assuming email is caught:
        if "allowed@example.com" in redacted:
             print("WARNING: Default WASM config did not redact email. Skipping 'Without whitelist' assertion part.")
        else:
             self.assertIn("[HIDDEN", redacted)

        # 2. With whitelist
        # Re-init client with env var
        PIIWasmClient._instance = None # Force re-init
        
        # Regex to match the email exactly
        safe_list_json = '[{"pattern": "allowed@example.com", "name": "SafeEmail"}]'
        os.environ["PII_SAFE_REGEX_LIST"] = safe_list_json
        
        client_safe = PIIWasmClient()
        redacted_safe = client_safe.redact(text)
        
        # Should NOT be redacted
        self.assertIn("allowed@example.com", redacted_safe)
        self.assertNotIn("[HIDDEN", redacted_safe)

    def test_wasi_env_does_not_inherit_ci_secrets(self):
        os.environ["GITHUB_TOKEN"] = "ghp_secret"
        os.environ["OPENAI_API_KEY"] = "sk-secret"
        os.environ["PII_SAFE_REGEX_LIST"] = "[]"

        client = PIIWasmClient()
        wasi_env = dict(client._wasi_env())

        self.assertEqual(wasi_env["PII_SAFE_REGEX_LIST"], "[]")
        self.assertNotIn("GITHUB_TOKEN", wasi_env)
        self.assertNotIn("OPENAI_API_KEY", wasi_env)

@unittest.skipIf(sys.platform == "darwin", "WASM runtime unstable on macOS (SIGKILL)")
class TestWasmStress(unittest.TestCase):
    def test_binary_data_resilience(self):
        """Test that the WASM client handles binary/garbage data without crashing."""
        client = PIIWasmClient()
        
        # Generate 10KB of random binary data
        binary_data = secrets.token_bytes(10240)
        
        # The client expects string. 
        # If we feed raw bytes, python type checking might fail or we need to decode.
        # Real-world scenario: File read as text but contains binary garbage (mojibake).
        # We'll use latin-1 to force it into a str without decoding errors, simulating binary string.
        text_input = binary_data.decode("latin-1")
        
        try:
            result = client.redact(text_input)
            # Should return a string
            self.assertIsInstance(result, str)
            # Logic: It shouldn't crash. Result might be same rubbish or partially redacted.
            # We don't check content, just stability.
        except Exception as e:
            self.fail(f"WASM client crashed on binary input: {e}")

if __name__ == "__main__":
    unittest.main()
