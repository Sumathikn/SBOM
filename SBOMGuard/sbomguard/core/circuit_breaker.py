"""
SBOMGuard — Resilient Circuit Breaker Engine
Prevents cascading failures and denial-of-service when external threat feeds
(NVD, OSV, CISA KEV, EPSS, Package Registries) experience outages or rate limits.
Implements the classic 3-State Machine: CLOSED -> OPEN -> HALF_OPEN.
"""
import time
import logging
from enum import Enum
from typing import Callable, Any, Optional, TypeVar, Coroutine
from dataclasses import dataclass

logger = logging.getLogger("sbomguard.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"      # Normal operation: traffic flows through
    OPEN = "OPEN"          # External service failed: fast-fail, no traffic sent
    HALF_OPEN = "HALF_OPEN"# Testing recovery: limited probe requests permitted


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""
    def __init__(self, service_name: str, cooldown_remaining: float):
        super().__init__(
            f"Circuit breaker for service '{service_name}' is OPEN. "
            f"Failing fast. Retry in {cooldown_remaining:.1f}s."
        )
        self.service_name = service_name
        self.cooldown_remaining = cooldown_remaining


@dataclass
class CircuitBreakerStats:
    total_calls: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = 0.0


class CircuitBreaker:
    """
    Thread-safe & async-compatible Circuit Breaker.
    """
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_success_threshold: int = 2,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_success_threshold = half_open_success_threshold

        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats(last_state_change=time.time())

    def reset(self) -> None:
        """Reset the circuit breaker back to initial CLOSED state."""
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats(last_state_change=time.time())

    def _update_state(self, new_state: CircuitState) -> None:
        if self.state != new_state:
            logger.warning(
                f"⚡ Circuit breaker '{self.name}' state transition: "
                f"{self.state.value} -> {new_state.value}"
            )
            self.state = new_state
            self.stats.last_state_change = time.time()
            if new_state == CircuitState.HALF_OPEN:
                self.stats.consecutive_successes = 0

    def check_state(self) -> None:
        """Check and transition circuit state before executing a call."""
        now = time.time()
        if self.state == CircuitState.OPEN:
            elapsed = now - self.stats.last_failure_time
            if elapsed >= self.recovery_timeout:
                self._update_state(CircuitState.HALF_OPEN)
            else:
                remaining = self.recovery_timeout - elapsed
                raise CircuitBreakerOpenException(self.name, remaining)

    def record_success(self) -> None:
        """Record successful execution."""
        self.stats.total_calls += 1
        self.stats.consecutive_failures = 0

        if self.state == CircuitState.HALF_OPEN:
            self.stats.consecutive_successes += 1
            if self.stats.consecutive_successes >= self.half_open_success_threshold:
                self._update_state(CircuitState.CLOSED)
                logger.info(f"✅ Service '{self.name}' recovered. Circuit breaker CLOSED.")

    def record_failure(self, error: Exception) -> None:
        """Record failed execution."""
        now = time.time()
        self.stats.total_calls += 1
        self.stats.total_failures += 1
        self.stats.consecutive_failures += 1
        self.stats.last_failure_time = now

        logger.debug(
            f"Circuit breaker '{self.name}' recorded failure ({error}). "
            f"Consecutive failures: {self.stats.consecutive_failures}/{self.failure_threshold}"
        )

        if self.state in (CircuitState.CLOSED, CircuitState.HALF_OPEN):
            if self.stats.consecutive_failures >= self.failure_threshold or self.state == CircuitState.HALF_OPEN:
                self._update_state(CircuitState.OPEN)
                logger.error(
                    f"🚨 Circuit breaker '{self.name}' tripped OPEN due to repeated errors. "
                    f"Cooldown period: {self.recovery_timeout}s."
                )

    def call(self, func: Callable[..., T], *args: Any, fallback: Optional[Callable[..., T]] = None, **kwargs: Any) -> T:
        """Execute a synchronous function with circuit breaking protection."""
        try:
            self.check_state()
            res = func(*args, **kwargs)
            self.record_success()
            return res
        except CircuitBreakerOpenException as cbe:
            if fallback:
                logger.info(f"Circuit '{self.name}' is OPEN. Invoking fallback.")
                return fallback(*args, **kwargs)
            raise
        except Exception as e:
            self.record_failure(e)
            if fallback:
                logger.info(f"Execution failed on '{self.name}'. Invoking fallback.")
                return fallback(*args, **kwargs)
            raise

    async def call_async(
        self,
        coro_func: Callable[..., Coroutine[Any, Any, T]],
        *args: Any,
        fallback: Optional[Callable[..., Any]] = None,
        **kwargs: Any,
    ) -> T:
        """Execute an asynchronous coroutine function with circuit breaking protection."""
        try:
            self.check_state()
            res = await coro_func(*args, **kwargs)
            self.record_success()
            return res
        except CircuitBreakerOpenException as cbe:
            if fallback:
                logger.info(f"Circuit '{self.name}' is OPEN. Invoking fallback.")
                res = fallback(*args, **kwargs)
                return await res if hasattr(res, "__await__") else res
            raise
        except Exception as e:
            self.record_failure(e)
            if fallback:
                logger.info(f"Execution failed on '{self.name}'. Invoking fallback.")
                res = fallback(*args, **kwargs)
                return await res if hasattr(res, "__await__") else res
            raise

    def get_status(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "total_calls": self.stats.total_calls,
            "total_failures": self.stats.total_failures,
            "consecutive_failures": self.stats.consecutive_failures,
            "last_state_change": self.stats.last_state_change,
        }


# ─── Global Circuit Breaker Registry ─────────────────────────────────────────

osv_breaker = CircuitBreaker("OSV_API", failure_threshold=4, recovery_timeout=20.0)
nvd_breaker = CircuitBreaker("NVD_API", failure_threshold=3, recovery_timeout=30.0)
cisa_kev_breaker = CircuitBreaker("CISA_KEV", failure_threshold=3, recovery_timeout=60.0)
epss_breaker = CircuitBreaker("EPSS_API", failure_threshold=4, recovery_timeout=30.0)
registry_breaker = CircuitBreaker("REGISTRIES", failure_threshold=5, recovery_timeout=25.0)

ALL_BREAKERS = [
    osv_breaker,
    nvd_breaker,
    cisa_kev_breaker,
    epss_breaker,
    registry_breaker,
]
