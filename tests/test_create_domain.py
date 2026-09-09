import unittest
from unittest.mock import MagicMock, patch

import main


class TestCreatePulpDomainGroupName(unittest.TestCase):
    @patch("main.requests.post")
    def test_group_name_included_in_basic_auth_request(self, mock_post):
        mock_post.return_value = MagicMock(status_code=201)

        result = main.create_pulp_domain(
            domain="test-domain",
            username="admin",
            password="secret",
            group_name="my-team",
            logger=MagicMock(),
        )

        self.assertTrue(result)
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["name"], "test-domain")
        self.assertEqual(payload["group_name"], "my-team")

    @patch("main.requests.post")
    def test_group_name_omitted_when_none(self, mock_post):
        mock_post.return_value = MagicMock(status_code=201)

        main.create_pulp_domain(
            domain="test-domain",
            username="admin",
            password="secret",
            group_name=None,
            logger=MagicMock(),
        )

        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload, {"name": "test-domain"})


class TestShouldCreateServiceAccount(unittest.TestCase):
    def test_defaults_true_without_credentials_secret(self):
        self.assertTrue(main.should_create_service_account({}))

    def test_defaults_false_with_credentials_secret(self):
        self.assertFalse(main.should_create_service_account({"credentialsSecretName": "my-creds"}))

    def test_explicit_true(self):
        self.assertTrue(main.should_create_service_account({"create_service_account": True}))

    def test_explicit_false(self):
        self.assertFalse(main.should_create_service_account({"create_service_account": False}))


if __name__ == "__main__":
    unittest.main()
