"""
Pytest configuration and global test fixtures for SBOMGuard.
"""
import pytest
from sbomguard.core.circuit_breaker import ALL_BREAKERS


@pytest.fixture(autouse=True)
def reset_circuit_breakers():
    """Ensure all circuit breakers start each test in clean CLOSED state."""
    for breaker in ALL_BREAKERS:
        breaker.reset()
