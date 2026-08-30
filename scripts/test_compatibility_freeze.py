import copy
from pathlib import Path
import tempfile
import unittest

from scripts import check_compatibility_freeze


class CompatibilityFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent
        cls.manifest_path = cls.root / "manifests/compatibility-freeze-v1.json"

    def test_repository_freeze_is_complete_and_hash_exact(self):
        document = check_compatibility_freeze.load_manifest(self.manifest_path)
        check_compatibility_freeze.validate_manifest(document, self.root)

    def test_unknown_top_level_field_is_rejected(self):
        document = copy.deepcopy(check_compatibility_freeze.load_manifest(self.manifest_path))
        document["auto_accept_breaking_changes"] = True
        with self.assertRaisesRegex(check_compatibility_freeze.FreezeError, "not closed"):
            check_compatibility_freeze.validate_manifest(document, self.root)

    def test_missing_contract_is_rejected(self):
        document = copy.deepcopy(check_compatibility_freeze.load_manifest(self.manifest_path))
        document["stable_current"].pop("api/openapi.yaml")
        with self.assertRaisesRegex(check_compatibility_freeze.FreezeError, "path set changed"):
            check_compatibility_freeze.validate_manifest(document, self.root)

    def test_hash_drift_is_rejected(self):
        document = copy.deepcopy(check_compatibility_freeze.load_manifest(self.manifest_path))
        document["stable_current"]["api/openapi.yaml"] = "0" * 64
        with self.assertRaisesRegex(check_compatibility_freeze.FreezeError, "compatibility decision"):
            check_compatibility_freeze.validate_manifest(document, self.root)

    def test_reclassifying_legacy_reader_is_rejected(self):
        document = copy.deepcopy(check_compatibility_freeze.load_manifest(self.manifest_path))
        digest = document["legacy_read"].pop("schemas/shadow-record-v1.schema.json")
        document["stable_current"]["schemas/shadow-record-v1.schema.json"] = digest
        with self.assertRaisesRegex(check_compatibility_freeze.FreezeError, "path set changed"):
            check_compatibility_freeze.validate_manifest(document, self.root)

    def test_duplicate_manifest_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "freeze.json"
            path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(check_compatibility_freeze.FreezeError, "duplicate JSON key"):
                check_compatibility_freeze.load_manifest(path)


if __name__ == "__main__":
    unittest.main()
