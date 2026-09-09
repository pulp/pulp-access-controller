import os
import unittest
from unittest.mock import MagicMock, patch

import domain_naming


class TestDomainNaming(unittest.TestCase):
    def setUp(self):
        domain_naming._cluster_id_cache = None

    def test_legacy_naming_without_cluster_id(self):
        self.assertEqual(domain_naming.generate_domain_name("my-namespace", None), "konflux-my-namespace")

    def test_hashed_naming_with_cluster_id(self):
        cluster_id = "7a3f2b1c-1234-5678-9abc-def012345678"
        suffix = domain_naming.cluster_id_suffix(cluster_id)
        domain = domain_naming.generate_domain_name("my-namespace", cluster_id)

        self.assertEqual(domain, f"konflux-my-namespace-{suffix}")
        self.assertEqual(len(suffix), domain_naming.CLUSTER_ID_HASH_LENGTH)

    def test_suffix_is_deterministic(self):
        cluster_id = "stable-cluster-id"
        self.assertEqual(
            domain_naming.cluster_id_suffix(cluster_id),
            domain_naming.cluster_id_suffix(cluster_id),
        )

    def test_different_clusters_get_different_suffixes(self):
        first = domain_naming.generate_domain_name("shared-ns", "cluster-a")
        second = domain_naming.generate_domain_name("shared-ns", "cluster-b")
        self.assertNotEqual(first, second)

    def test_truncates_long_namespace_to_slug_limit(self):
        long_namespace = "a" * 60
        domain = domain_naming.generate_domain_name(long_namespace, "cluster-id")

        self.assertLessEqual(len(domain), domain_naming.DOMAIN_NAME_MAX_LENGTH)
        self.assertTrue(domain.startswith("konflux-"))
        self.assertIn("-", domain[len("konflux-"):])

    def test_resolve_domain_name_uses_persisted_value(self):
        logger = MagicMock()
        persisted = "konflux-my-namespace-frozen"

        domain = domain_naming.resolve_domain_name("my-namespace", persisted, logger)

        self.assertEqual(domain, persisted)

    def test_resolve_domain_name_generates_when_not_persisted(self):
        logger = MagicMock()
        cluster_id = "test-cluster-id"

        with patch.object(domain_naming, "get_cluster_id", return_value=cluster_id):
            domain = domain_naming.resolve_domain_name("my-namespace", None, logger)

        expected = domain_naming.generate_domain_name("my-namespace", cluster_id)
        self.assertEqual(domain, expected)

    def test_get_cluster_id_uses_environment_override(self):
        logger = MagicMock()

        with patch.dict(os.environ, {"KONFLUX_CLUSTER_ID": "override-id"}):
            cluster_id = domain_naming.get_cluster_id(logger)

        self.assertEqual(cluster_id, "override-id")

    def test_get_cluster_id_reads_cluster_version(self):
        logger = MagicMock()

        env = os.environ.copy()
        env.pop("KONFLUX_CLUSTER_ID", None)
        with patch.dict(os.environ, env, clear=True):
            with patch.object(domain_naming.kubernetes.client, "CustomObjectsApi") as mock_api_cls:
                mock_api = mock_api_cls.return_value
                mock_api.get_cluster_custom_object.return_value = {
                    "spec": {"clusterID": "openshift-cluster-id"},
                }
                cluster_id = domain_naming.get_cluster_id(logger)

        self.assertEqual(cluster_id, "openshift-cluster-id")
        mock_api.get_cluster_custom_object.assert_called_once_with(
            group="config.openshift.io",
            version="v1",
            plural="clusterversions",
            name="version",
        )


if __name__ == "__main__":
    unittest.main()
