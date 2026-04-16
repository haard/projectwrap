"""Shared pytest fixtures."""

import pytest
from project_wrap import deps as deps_module


@pytest.fixture(autouse=True)
def _stub_bwrap_probe(request, monkeypatch):
    """Stub the bwrap feature probe for unit tests.

    Without this, any test that reaches `require_dep("bwrap")` (via
    prepare_project etc.) would actually run `bwrap --help` on the host.
    Tests that want the real probe can opt out with @pytest.mark.real_probe.
    """
    deps_module._bwrap_probe_cache = None
    if "real_probe" in request.keywords:
        return
    stub = lambda _path: (True, "")  # noqa: E731
    monkeypatch.setattr(deps_module, "_probe_bwrap", stub)
    monkeypatch.setattr(deps_module.DEPS["bwrap"], "feature_probe", stub)
