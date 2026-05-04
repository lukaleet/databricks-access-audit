"""Tests for config.py: profile loading and cloud detection."""
from __future__ import annotations

from databricks_access_audit.config import cloud_from_host, load_profile

# ---------------------------------------------------------------------------
# cloud_from_host
# ---------------------------------------------------------------------------

class TestCloudFromHost:
    def test_azure_with_scheme(self):
        assert cloud_from_host("https://accounts.azuredatabricks.net") == "azure"

    def test_azure_without_scheme(self):
        assert cloud_from_host("accounts.azuredatabricks.net") == "azure"

    def test_azure_trailing_slash(self):
        assert cloud_from_host("https://accounts.azuredatabricks.net/") == "azure"

    def test_aws_with_scheme(self):
        assert cloud_from_host("https://accounts.cloud.databricks.com") == "aws"

    def test_aws_without_scheme(self):
        assert cloud_from_host("accounts.cloud.databricks.com") == "aws"

    def test_gcp_with_scheme(self):
        assert cloud_from_host("https://accounts.gcp.databricks.com") == "gcp"

    def test_gcp_without_scheme(self):
        assert cloud_from_host("accounts.gcp.databricks.com") == "gcp"

    def test_unknown_host_returns_none(self):
        assert cloud_from_host("https://unknown.example.com") is None

    def test_workspace_host_returns_none(self):
        # workspace URL, not account URL
        assert cloud_from_host("https://adb-1234567890123456.9.azuredatabricks.net") is None

    def test_case_insensitive(self):
        assert cloud_from_host("HTTPS://ACCOUNTS.AZUREDATABRICKS.NET") == "azure"


# ---------------------------------------------------------------------------
# load_profile
# ---------------------------------------------------------------------------

class TestLoadProfile:
    def test_missing_file_returns_empty(self):
        assert load_profile(config_file="/nonexistent/.databrickscfg") == {}

    def test_default_profile(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text(
            "[DEFAULT]\n"
            "host = https://accounts.azuredatabricks.net\n"
            "account_id = acc-123\n"
            "client_id = cid-123\n"
            "client_secret = csc-123\n"
        )
        result = load_profile("DEFAULT", str(cfg))
        assert result["host"] == "https://accounts.azuredatabricks.net"
        assert result["account_id"] == "acc-123"
        assert result["client_id"] == "cid-123"
        assert result["client_secret"] == "csc-123"

    def test_named_profile(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text(
            "[DEFAULT]\n"
            "account_id = default-acc\n"
            "\n"
            "[prod]\n"
            "host = https://accounts.cloud.databricks.com\n"
            "client_id = prod-cid\n"
            "client_secret = prod-csc\n"
        )
        result = load_profile("prod", str(cfg))
        assert result["client_id"] == "prod-cid"
        assert result["client_secret"] == "prod-csc"
        assert result["host"] == "https://accounts.cloud.databricks.com"
        # account_id inherited from DEFAULT
        assert result["account_id"] == "default-acc"

    def test_named_profile_overrides_default(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text(
            "[DEFAULT]\n"
            "account_id = default-acc\n"
            "\n"
            "[prod]\n"
            "account_id = prod-acc\n"
        )
        result = load_profile("prod", str(cfg))
        assert result["account_id"] == "prod-acc"

    def test_missing_profile_returns_empty(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text("[DEFAULT]\naccount_id = acc-1\n")
        assert load_profile("nonexistent", str(cfg)) == {}

    def test_empty_values_excluded(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text("[DEFAULT]\nclient_id = \naccount_id = acc-1\n")
        result = load_profile("DEFAULT", str(cfg))
        assert "client_id" not in result
        assert result["account_id"] == "acc-1"

    def test_token_field_returned(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text("[DEFAULT]\nhost = https://adb-123.azuredatabricks.net\ntoken = dapi123\n")
        result = load_profile("DEFAULT", str(cfg))
        assert result["token"] == "dapi123"

    def test_whitespace_stripped(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text("[DEFAULT]\naccount_id =   acc-with-spaces   \n")
        result = load_profile("DEFAULT", str(cfg))
        assert result["account_id"] == "acc-with-spaces"

    def test_default_profile_case_insensitive(self, tmp_path):
        cfg = tmp_path / ".databrickscfg"
        cfg.write_text("[DEFAULT]\naccount_id = acc-1\n")
        assert load_profile("default", str(cfg))["account_id"] == "acc-1"

    def test_databricks_config_file_env_var(self, tmp_path, monkeypatch):
        cfg = tmp_path / "custom.cfg"
        cfg.write_text("[DEFAULT]\naccount_id = env-acc\n")
        monkeypatch.setenv("DATABRICKS_CONFIG_FILE", str(cfg))
        result = load_profile("DEFAULT")
        assert result["account_id"] == "env-acc"

    def test_explicit_config_file_overrides_env(self, tmp_path, monkeypatch):
        env_cfg = tmp_path / "env.cfg"
        env_cfg.write_text("[DEFAULT]\naccount_id = env-acc\n")
        explicit_cfg = tmp_path / "explicit.cfg"
        explicit_cfg.write_text("[DEFAULT]\naccount_id = explicit-acc\n")
        monkeypatch.setenv("DATABRICKS_CONFIG_FILE", str(env_cfg))
        result = load_profile("DEFAULT", str(explicit_cfg))
        assert result["account_id"] == "explicit-acc"
