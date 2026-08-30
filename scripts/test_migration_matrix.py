import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import check_compatibility_freeze
from scripts import check_migration_matrix


class MigrationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent
        cls.matrix_path = cls.root / "manifests/migration-matrix-v1.json"

    def matrix(self):
        return copy.deepcopy(check_migration_matrix.load_matrix(self.matrix_path))

    def test_repository_matrix_exactly_covers_frozen_and_historical_contracts(self):
        check_migration_matrix.validate_matrix(self.matrix(), self.root)

    def test_every_frozen_contract_is_classified_once(self):
        document = self.matrix()
        values = [path for paths in document["classifications"].values() for path in paths]
        self.assertEqual(len(values), len(set(values)))
        self.assertEqual(
            set(values),
            check_compatibility_freeze.STABLE_CURRENT | check_compatibility_freeze.LEGACY_READ,
        )

    def test_missing_or_reclassified_contract_is_rejected(self):
        for mutation in ("missing", "reclassified"):
            with self.subTest(mutation=mutation):
                document = self.matrix()
                path = document["classifications"]["runtime_exchange"].pop(0)
                if mutation == "reclassified":
                    document["classifications"]["repository_control"].append(path)
                    document["classifications"]["repository_control"].sort()
                with self.assertRaises(check_migration_matrix.MatrixError):
                    check_migration_matrix.validate_matrix(document, self.root)

    def test_shadow_v1_linkage_is_never_invented(self):
        document = self.matrix()
        shadow = next(item for item in document["transitions"] if item["family"] == "shadow_record")
        self.assertEqual(shadow["previous_support"], "legacy_read")
        self.assertEqual(shadow["strategy"], "legacy_read_no_rewrite")
        self.assertEqual(shadow["loss_boundary"], "v1_outcome_has_no_decision_id")
        shadow["strategy"] = "regenerate_from_authenticated_source"
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "shadow_record"):
            check_migration_matrix.validate_matrix(document, self.root)

    def test_historical_analysis_cannot_become_rollout_authority(self):
        document = self.matrix()
        analysis = next(item for item in document["transitions"] if item["family"] == "shadow_analysis")
        self.assertEqual(analysis["operator_command"], "palisade analyze-shadow-log")
        self.assertEqual(analysis["loss_boundary"], "historical_report_is_not_rollout_authority")
        analysis["loss_boundary"] = "v1_outcome_has_no_decision_id"
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "shadow_analysis"):
            check_migration_matrix.validate_matrix(document, self.root)

    def test_transition_removal_and_unknown_fields_are_rejected(self):
        document = self.matrix()
        document["transitions"].pop()
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "count"):
            check_migration_matrix.validate_matrix(document, self.root)
        document = self.matrix()
        document["auto_migrate"] = True
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "not closed"):
            check_migration_matrix.validate_matrix(document, self.root)
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "not closed"):
            check_migration_matrix.validate_matrix([], self.root)

    def test_safety_invariant_reordering_and_boolean_substitution_are_rejected(self):
        document = self.matrix()
        document["invariants"].reverse()
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "invariants"):
            check_migration_matrix.validate_matrix(document, self.root)
        document = self.matrix()
        document["invariants"][0] = True
        with self.assertRaisesRegex(check_migration_matrix.MatrixError, "invariants"):
            check_migration_matrix.validate_matrix(document, self.root)

    def test_duplicate_json_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "matrix.json"
            path.write_text('{"schema_version":"one","schema_version":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(check_migration_matrix.MatrixError, "duplicate JSON key"):
                check_migration_matrix.load_matrix(path)

    def test_schema_matches_runtime_header_and_closed_fields(self):
        schema = json.loads(
            (self.root / "schemas/migration-matrix-v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema["properties"]["schema_version"]["const"], check_migration_matrix.SCHEMA_VERSION)
        self.assertEqual(set(schema["required"]), check_migration_matrix.TOP_LEVEL_FIELDS)
        self.assertEqual(
            schema["properties"]["invariants"]["prefixItems"],
            [{"const": value} for value in check_migration_matrix.INVARIANTS],
        )


if __name__ == "__main__":
    unittest.main()
