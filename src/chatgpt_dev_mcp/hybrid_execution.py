"""Coordinate local execution and ChatGPT built-in assistant handoff."""

from __future__ import annotations

from collections.abc import Callable

from .execution_router import BackendAvailability, ExecutionBackend, ExecutionMode, RouteRequest, choose_backend


class HybridExecutionCoordinator:
    def __init__(
        self,
        *,
        local_execute: Callable[[object], object],
        chatgpt_builtin_available: bool | None = None,
    ) -> None:
        if not callable(local_execute):
            raise TypeError("local_execute must be callable")
        if chatgpt_builtin_available is not None and not isinstance(chatgpt_builtin_available, bool):
            raise TypeError("chatgpt_builtin_available must be boolean or None")
        self._local_execute = local_execute
        self._chatgpt_builtin_available = chatgpt_builtin_available is True

    def availability(self) -> BackendAvailability:
        return BackendAvailability(
            local=True,
            managed_cloud=self._chatgpt_builtin_available,
            managed_cloud_reason=(
                "caller_declared_available"
                if self._chatgpt_builtin_available
                else "caller_not_declared"
            ),
        )

    @staticmethod
    def _route_metadata(backend: ExecutionBackend, request: RouteRequest) -> dict[str, object]:
        if backend is ExecutionBackend.CHATGPT_BUILTIN:
            parallelism_hint = 3 if request.workload.value in {"compute_heavy", "bulk_analysis"} else 1
            return {
                "execution_kind": "assistant_handoff",
                "requires_assistant_action": True,
                "human_confirmation_required": False,
                "billable_api": False,
                "handoff": {
                    "kind": "python_analysis",
                    "parallelism_hint": parallelism_hint,
                    "max_parallelism": 5,
                },
            }
        return {
            "execution_kind": "local_execute",
            "requires_assistant_action": False,
            "human_confirmation_required": False,
            "billable_api": False,
        }

    def route(self, request: RouteRequest) -> dict[str, object]:
        availability = self.availability()
        decision = choose_backend(request, availability)
        return {
            "backend": decision.backend.value,
            "reason": decision.reason,
            "available": decision.available,
            "fallback": decision.fallback,
            "chatgpt_builtin_available": availability.chatgpt_builtin,
            # Compatibility alias retained for the pre-handoff field name.
            "managed_cloud_available": availability.managed_cloud,
            **self._route_metadata(decision.backend, request),
        }

    def execute(self, request: RouteRequest, payload: object) -> dict[str, object]:
        route = self.route(request)
        if route["backend"] == ExecutionBackend.CHATGPT_BUILTIN.value:
            return {**route, "result": None}
        if not route["available"]:
            return {**route, "result": None}
        return {**route, "result": self._local_execute(payload)}


__all__ = ["HybridExecutionCoordinator"]
