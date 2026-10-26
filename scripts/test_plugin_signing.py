import base64
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import plugin_signing


class PluginSigningTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.plugin = self.root / "example-plugin"
        (self.plugin / ".claude-plugin").mkdir(parents=True)
        (self.plugin / ".claude-plugin" / "plugin.json").write_text(
            '{"name": "example-plugin"}\n', encoding="utf-8"
        )
        (self.plugin / "hook.py").write_text("print('ok')\n", encoding="utf-8")
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        self.key_id = plugin_signing.generate_keypair(
            self.private_key, self.public_key
        )

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_sign_and_verify(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        record = plugin_signing.verify_plugin(
            self.plugin, public_key_path=self.public_key
        )
        self.assertEqual(record["key_id"], self.key_id)
        self.assertEqual(record["algorithm"], "ed25519")

    def test_detects_tampering(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        (self.plugin / "hook.py").write_text("print('changed')\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            plugin_signing.verify_plugin(self.plugin, public_key_path=self.public_key)

    def test_rejects_wrong_key(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.pem"
        plugin_signing.generate_keypair(other_private, other_public)
        with self.assertRaisesRegex(ValueError, "key_id"):
            plugin_signing.verify_plugin(self.plugin, public_key_path=other_public)

    def test_rejects_tampered_signature(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        signature_path = self.plugin / "signature.json"
        record = json.loads(signature_path.read_text(encoding="utf-8"))
        record["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
        signature_path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "verification failed"):
            plugin_signing.verify_plugin(self.plugin, public_key_path=self.public_key)

    def test_rejects_invalid_key_id(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        signature_path = self.plugin / "signature.json"
        record = json.loads(signature_path.read_text(encoding="utf-8"))
        record["key_id"] = "../../outside"
        signature_path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "key_id"):
            plugin_signing.verify_plugin(self.plugin, trusted_keys_dir=self.root)

    def test_trusted_key_directory(self):
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        trusted = self.root / "trusted"
        trusted.mkdir()
        shutil.copy(self.public_key, trusted / f"{self.key_id}.pem")
        plugin_signing.verify_plugin(self.plugin, trusted_keys_dir=trusted)

    def test_signature_file_is_not_part_of_digest(self):
        first = plugin_signing.plugin_digest(self.plugin)
        plugin_signing.sign_plugin(self.plugin, self.private_key)
        second = plugin_signing.plugin_digest(self.plugin)
        self.assertEqual(first, second)
        record = json.loads((self.plugin / "signature.json").read_text(encoding="utf-8"))
        self.assertEqual(record["digest"], first)


if __name__ == "__main__":
    unittest.main()
