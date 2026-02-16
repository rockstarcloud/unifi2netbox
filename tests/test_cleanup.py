"""Tests for cleanup utility functions."""
import os
from unittest.mock import patch

from main import _is_cleanup_enabled, _cleanup_stale_days


# ---------------------------------------------------------------------------
#  _is_cleanup_enabled
# ---------------------------------------------------------------------------

class TestIsCleanupEnabled:
    @patch.dict(os.environ, {"NETBOX_CLEANUP": "true"}, clear=False)
    def test_true(self):
        assert _is_cleanup_enabled() is True

    @patch.dict(os.environ, {"NETBOX_CLEANUP": "1"}, clear=False)
    def test_one(self):
        assert _is_cleanup_enabled() is True

    @patch.dict(os.environ, {"NETBOX_CLEANUP": "yes"}, clear=False)
    def test_yes(self):
        assert _is_cleanup_enabled() is True

    @patch.dict(os.environ, {"NETBOX_CLEANUP": "TRUE"}, clear=False)
    def test_case_insensitive(self):
        assert _is_cleanup_enabled() is True

    @patch.dict(os.environ, {"NETBOX_CLEANUP": "false"}, clear=False)
    def test_false(self):
        assert _is_cleanup_enabled() is False

    @patch.dict(os.environ, {"NETBOX_CLEANUP": "no"}, clear=False)
    def test_no(self):
        assert _is_cleanup_enabled() is False

    @patch.dict(os.environ, {}, clear=False)
    def test_default_is_false(self):
        os.environ.pop("NETBOX_CLEANUP", None)
        assert _is_cleanup_enabled() is False


# ---------------------------------------------------------------------------
#  _cleanup_stale_days
# ---------------------------------------------------------------------------

class TestCleanupStaleDays:
    @patch.dict(os.environ, {"CLEANUP_STALE_DAYS": "7"}, clear=False)
    def test_custom_value(self):
        assert _cleanup_stale_days() == 7

    @patch.dict(os.environ, {"CLEANUP_STALE_DAYS": "0"}, clear=False)
    def test_zero(self):
        assert _cleanup_stale_days() == 0

    @patch.dict(os.environ, {}, clear=False)
    def test_default_is_30(self):
        os.environ.pop("CLEANUP_STALE_DAYS", None)
        assert _cleanup_stale_days() == 30

    @patch.dict(os.environ, {"CLEANUP_STALE_DAYS": "not-a-number"}, clear=False)
    def test_invalid_returns_default(self):
        assert _cleanup_stale_days() == 30
