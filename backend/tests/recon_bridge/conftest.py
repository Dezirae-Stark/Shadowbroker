"""Local conftest for recon_bridge tests.

Overrides the root-level _suppress_background_services autouse fixture
so that the HMAC-auth unit tests (which have no FastAPI/APScheduler
dependencies) can run without needing the full service stack installed.
"""

import pytest


@pytest.fixture(autouse=True)
def _suppress_background_services():
    """No-op override: recon_bridge tests have no background-service deps."""
    yield
