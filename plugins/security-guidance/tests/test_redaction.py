import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "hooks"
sys.path.insert(0, str(HOOKS))

import llm
import redaction
import review_api

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
ANTHROPIC_KEY = "sk-ant-" + "a" * 24
PRIVATE_KEY = (
    "-----BEGIN " + "PRIVATE KEY-----\n"
    + "b" * 32
    + "\n-----END " + "PRIVATE KEY-----"
)


class RedactionTest(unittest.TestCase):
    def test_redacts_known_credentials(self):
        text = f"{AWS_KEY}\n{ANTHROPIC_KEY}\n{PRIVATE_KEY}"
        redacted = redaction.redact_text(text)
        self.assertNotIn(AWS_KEY, redacted)
        self.assertNotIn(ANTHROPIC_KEY, redacted)
        self.assertNotIn("b" * 32, redacted)
        self.assertIn("[REDACTED:AWS_ACCESS_KEY]", redacted)
        self.assertIn("[REDACTED:ANTHROPIC_KEY]", redacted)
        self.assertIn("[REDACTED:PRIVATE_KEY]", redacted)

    def test_leaves_ordinary_code_unchanged(self):
        text = "token = os.environ['GITHUB_TOKEN']\napi_key = settings.api_key"
        self.assertEqual(redaction.redact_text(text), text)

    def test_redacts_nested_values(self):
        value = {"messages": [{"text": AWS_KEY}], "count": 1}
        redacted = redaction.redact_value(value)
        self.assertNotIn(AWS_KEY, redacted["messages"][0]["text"])
        self.assertEqual(redacted["count"], 1)

    def test_diff_cap_redacts_before_sending(self):
        files = [("app.py", f'AWS_KEY = "{AWS_KEY}"\n')]
        capped, dropped = review_api.cap_diff_for_prompt(files)
        self.assertEqual(dropped, 0)
        self.assertNotIn(AWS_KEY, capped[0][1])
        self.assertIn("[REDACTED:AWS_ACCESS_KEY]", capped[0][1])

    def test_refute_prompt_redacts_candidates_and_diff(self):
        prompt = review_api.build_refute_prompt(
            [{"vulnerableCode": AWS_KEY}], f"+ key = {AWS_KEY}\n"
        )
        self.assertNotIn(AWS_KEY, prompt)

    def test_llm_cap_redacts_before_sending(self):
        capped = llm._cap_files_for_prompt([("app.py", f'key = "{AWS_KEY}"\n')])
        self.assertNotIn(AWS_KEY, capped[0][1])
        self.assertIn("[REDACTED:AWS_ACCESS_KEY]", capped[0][1])


if __name__ == "__main__":
    unittest.main()
