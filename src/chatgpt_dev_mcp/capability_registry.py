from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping, Sequence


CAPABILITY_REGISTRY_REVISION = "capability-registry-v1"
COMPOSITE_CAPABILITY_REGISTRY_REVISION = "capability-registry-v1-composite"
DEFAULT_CAPABILITY_SHARDS = (
    "development",
    "files_changes",
    "delivery",
    "verification",
    "qa",
    "governance_security",
    "platform_integrations",
)
_CAPABILITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHARD_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class CapabilityRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CapabilityValidationError(CapabilityRegistryError):
    pass


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    version: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    risk_class: str
    approval_policy: str
    workspace_binding: str
    session_required: bool
    writer_lease_required: bool
    network_required: bool
    credential_requirements: tuple[str, ...]
    timeout_ms: int
    idempotency: str
    audit_category: str
    deprecated: bool
    replacement: str | None
    handler: str
    handler_version: str
    category: str = "uncategorized"
    shard: str = ""
    exposure: str = "registry"

    def public_metadata(self, *, include_schemas: bool = True) -> dict[str, Any]:
        value = asdict(self)
        value["credential_requirements"] = list(self.credential_requirements)
        value.pop("handler", None)
        value.pop("handler_version", None)
        if not include_schemas:
            value.pop("input_schema", None)
            value.pop("output_schema", None)
        return value

    def internal_metadata(self) -> dict[str, Any]:
        value = asdict(self)
        value["credential_requirements"] = list(self.credential_requirements)
        return value


class CapabilityRegistry:
    def __init__(self, specs: Sequence[CapabilitySpec] | None = None, *, shard_id: str | None = None) -> None:
        if shard_id is not None and not _SHARD_ID_RE.fullmatch(shard_id):
            raise CapabilityRegistryError("INVALID_CAPABILITY_SHARD", "Invalid shard_id.")
        self.shard_id = shard_id
        self._specs: dict[str, CapabilitySpec] = {}
        self._frozen = False
        for spec in specs or ():
            self.register(spec)

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> CapabilityRegistry:
        self._frozen = True
        return self

    def register(self, spec: CapabilitySpec) -> None:
        if self._frozen:
            raise CapabilityRegistryError(
                "CAPABILITY_REGISTRY_FROZEN",
                "Capability registry is frozen and cannot be modified.",
            )
        self._validate_spec(spec)
        if self.shard_id is not None:
            if spec.shard and spec.shard != self.shard_id:
                raise CapabilityRegistryError(
                    "CAPABILITY_SHARD_MISMATCH",
                    f"Capability {spec.capability_id} belongs to shard {spec.shard}, not {self.shard_id}.",
                )
            if not spec.shard:
                spec = replace(spec, shard=self.shard_id)
        if spec.capability_id in self._specs:
            raise CapabilityRegistryError("DUPLICATE_CAPABILITY", f"Capability already registered: {spec.capability_id}")
        self._specs[spec.capability_id] = spec

    def get(self, capability_id: str) -> CapabilitySpec:
        spec = self._specs.get(capability_id)
        if spec is None:
            raise CapabilityRegistryError("UNKNOWN_CAPABILITY", f"Unknown capability: {capability_id}")
        return spec

    def describe(self, capability_id: str) -> dict[str, Any]:
        return self.get(capability_id).public_metadata(include_schemas=True)

    def catalog(
        self,
        *,
        prefix: str | None = None,
        limit: int = 50,
        include_deprecated: bool = True,
        category: str | None = None,
        shard: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CapabilityRegistryError("CATALOG_LIMIT_OUT_OF_RANGE", "Capability catalog limit must be between 1 and 100.")
        prefix_value = prefix or ""
        query_value = (query or "").strip().lower()
        matches = []
        for capability_id, spec in sorted(self._specs.items()):
            if not capability_id.startswith(prefix_value):
                continue
            if not include_deprecated and spec.deprecated:
                continue
            if category is not None and spec.category != category:
                continue
            if shard is not None and spec.shard != shard:
                continue
            if query_value:
                haystack = " ".join((spec.capability_id, spec.description, spec.category, spec.shard)).lower()
                if query_value not in haystack:
                    continue
            matches.append(spec)
        return {
            "registry": self.metadata(),
            "prefix": prefix_value,
            "category": category,
            "shard": shard,
            "query": query_value,
            "count": len(matches),
            "returned": min(limit, len(matches)),
            "capabilities": [spec.public_metadata(include_schemas=False) for spec in matches[:limit]],
        }

    def overview(self, *, include_deprecated: bool = False) -> dict[str, Any]:
        visible_specs = [
            spec
            for spec in self._specs.values()
            if include_deprecated or not spec.deprecated
        ]
        category_counts: dict[str, int] = {}
        for spec in visible_specs:
            category_counts[spec.category] = category_counts.get(spec.category, 0) + 1
        shard_summaries = []
        if visible_specs:
            shard_summaries.append(
                {
                    "shard_id": self.shard_id or "registry",
                    "count": len(visible_specs),
                    "categories": [
                        {"category": category_name, "count": category_counts[category_name]}
                        for category_name in sorted(category_counts)
                    ],
                }
            )
        return {
            "registry": self.metadata(),
            "mode": "overview",
            "include_deprecated": include_deprecated,
            "count": len(visible_specs),
            "returned": len(shard_summaries),
            "capabilities": [],
            "shards": shard_summaries,
            "discovery": {
                "filters": ["shard", "category", "query", "prefix"],
                "describe_tool": "capability_describe",
            },
        }

    def validate_params(self, capability_id: str, params: Mapping[str, Any]) -> dict[str, Any]:
        spec = self.get(capability_id)
        if not isinstance(params, Mapping):
            raise CapabilityValidationError("INVALID_CAPABILITY_PARAMS", "Capability params must be an object.")
        normalized = dict(params)
        try:
            _validate_schema(spec.input_schema, normalized, path="params")
        except ValueError as exc:
            raise CapabilityValidationError("INVALID_CAPABILITY_PARAMS", str(exc)) from exc
        return normalized

    def validate_result(self, capability_id: str, result: Any) -> Any:
        spec = self.get(capability_id)
        try:
            _validate_schema(spec.output_schema, result, path="result")
        except ValueError as exc:
            raise CapabilityValidationError("INVALID_CAPABILITY_RESULT", str(exc)) from exc
        return dict(result) if isinstance(result, Mapping) else result

    def metadata(self) -> dict[str, Any]:
        canonical = [self._specs[capability_id].internal_metadata() for capability_id in sorted(self._specs)]
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return {
            "revision": CAPABILITY_REGISTRY_REVISION,
            "count": len(canonical),
            "hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "shard_id": self.shard_id,
        }

    @staticmethod
    def _validate_spec(spec: CapabilitySpec) -> None:
        if not _CAPABILITY_ID_RE.fullmatch(spec.capability_id):
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "Invalid capability_id.")
        for field_name in (
            "version",
            "description",
            "risk_class",
            "approval_policy",
            "workspace_binding",
            "idempotency",
            "audit_category",
            "handler",
            "handler_version",
            "category",
            "exposure",
        ):
            if not getattr(spec, field_name):
                raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", f"{field_name} must not be empty.")
        if not isinstance(spec.timeout_ms, int) or isinstance(spec.timeout_ms, bool) or spec.timeout_ms <= 0:
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "timeout_ms must be positive.")
        if spec.deprecated and spec.replacement == spec.capability_id:
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "A deprecated capability cannot replace itself.")
        if not isinstance(spec.input_schema, Mapping) or not isinstance(spec.output_schema, Mapping):
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "input_schema and output_schema must be objects.")
        if spec.shard and not _SHARD_ID_RE.fullmatch(spec.shard):
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "Invalid capability shard.")
        if spec.exposure not in {"registry", "direct", "internal"}:
            raise CapabilityRegistryError("INVALID_CAPABILITY_SPEC", "Invalid capability exposure mode.")


class CompositeCapabilityRegistry:
    """Deterministic facade over independently owned capability shards."""

    def __init__(self, registries: Sequence[CapabilityRegistry]) -> None:
        self._registries: dict[str, CapabilityRegistry] = {}
        self._specs: dict[str, CapabilitySpec] = {}
        self._frozen = False
        for registry in registries:
            if not isinstance(registry, CapabilityRegistry):
                raise TypeError("registries must contain CapabilityRegistry instances")
            shard_id = registry.shard_id
            if not shard_id:
                raise CapabilityRegistryError("INVALID_CAPABILITY_SHARD", "Composite registry children require shard_id.")
            if shard_id in self._registries:
                raise CapabilityRegistryError("DUPLICATE_CAPABILITY_SHARD", f"Duplicate shard: {shard_id}")
            self._registries[shard_id] = registry
        self._rebuild_index()

    @property
    def shard_ids(self) -> tuple[str, ...]:
        ordered_defaults = [shard for shard in DEFAULT_CAPABILITY_SHARDS if shard in self._registries]
        extra = sorted(shard for shard in self._registries if shard not in DEFAULT_CAPABILITY_SHARDS)
        return tuple(ordered_defaults + extra)

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> CompositeCapabilityRegistry:
        for registry in self._registries.values():
            registry.freeze()
        self._rebuild_index()
        self._frozen = True
        return self

    def get(self, capability_id: str) -> CapabilitySpec:
        self._rebuild_index()
        spec = self._specs.get(capability_id)
        if spec is None:
            raise CapabilityRegistryError("UNKNOWN_CAPABILITY", f"Unknown capability: {capability_id}")
        return spec

    def describe(self, capability_id: str) -> dict[str, Any]:
        return self.get(capability_id).public_metadata(include_schemas=True)

    def validate_params(self, capability_id: str, params: Mapping[str, Any]) -> dict[str, Any]:
        spec = self.get(capability_id)
        return self._registries[spec.shard].validate_params(capability_id, params)

    def validate_result(self, capability_id: str, result: Any) -> Any:
        spec = self.get(capability_id)
        return self._registries[spec.shard].validate_result(capability_id, result)

    def catalog(
        self,
        *,
        prefix: str | None = None,
        limit: int = 50,
        include_deprecated: bool = True,
        category: str | None = None,
        shard: str | None = None,
        query: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise CapabilityRegistryError("CATALOG_LIMIT_OUT_OF_RANGE", "Capability catalog limit must be between 1 and 100.")
        self._rebuild_index()
        prefix_value = prefix or ""
        query_value = (query or "").strip().lower()
        matches: list[CapabilitySpec] = []
        for capability_id, spec in sorted(self._specs.items()):
            if not capability_id.startswith(prefix_value):
                continue
            if not include_deprecated and spec.deprecated:
                continue
            if category is not None and spec.category != category:
                continue
            if shard is not None and spec.shard != shard:
                continue
            if query_value:
                haystack = " ".join((spec.capability_id, spec.description, spec.category, spec.shard)).lower()
                if query_value not in haystack:
                    continue
            matches.append(spec)
        return {
            "registry": self.metadata(),
            "prefix": prefix_value,
            "category": category,
            "shard": shard,
            "query": query_value,
            "count": len(matches),
            "returned": min(limit, len(matches)),
            "capabilities": [spec.public_metadata(include_schemas=False) for spec in matches[:limit]],
        }

    def overview(self, *, include_deprecated: bool = False) -> dict[str, Any]:
        self._rebuild_index()
        visible_specs = [
            spec
            for spec in self._specs.values()
            if include_deprecated or not spec.deprecated
        ]
        shard_summaries: list[dict[str, Any]] = []
        for shard_id in self.shard_ids:
            shard_specs = [spec for spec in visible_specs if spec.shard == shard_id]
            if not shard_specs:
                continue
            category_counts: dict[str, int] = {}
            for spec in shard_specs:
                category_counts[spec.category] = category_counts.get(spec.category, 0) + 1
            shard_summaries.append(
                {
                    "shard_id": shard_id,
                    "count": len(shard_specs),
                    "categories": [
                        {"category": category_name, "count": category_counts[category_name]}
                        for category_name in sorted(category_counts)
                    ],
                }
            )
        return {
            "registry": self.metadata(),
            "mode": "overview",
            "include_deprecated": include_deprecated,
            "count": len(visible_specs),
            "returned": len(shard_summaries),
            "capabilities": [],
            "shards": shard_summaries,
            "discovery": {
                "filters": ["shard", "category", "query", "prefix"],
                "describe_tool": "capability_describe",
            },
        }

    def metadata(self) -> dict[str, Any]:
        self._rebuild_index()
        canonical = [self._specs[capability_id].internal_metadata() for capability_id in sorted(self._specs)]
        shard_metadata = [
            {"shard_id": shard_id, **self._registries[shard_id].metadata()}
            for shard_id in self.shard_ids
        ]
        payload = json.dumps(
            {"capabilities": canonical, "shards": shard_metadata},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return {
            "revision": COMPOSITE_CAPABILITY_REGISTRY_REVISION,
            "count": len(canonical),
            "hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "shards": shard_metadata,
        }

    def _rebuild_index(self) -> None:
        specs: dict[str, CapabilitySpec] = {}
        for shard_id, registry in self._registries.items():
            for capability_id, spec in registry._specs.items():
                if spec.shard != shard_id:
                    raise CapabilityRegistryError(
                        "CAPABILITY_SHARD_MISMATCH",
                        f"Capability {capability_id} is not pinned to shard {shard_id}.",
                    )
                if capability_id in specs:
                    raise CapabilityRegistryError("DUPLICATE_CAPABILITY", f"Capability already registered: {capability_id}")
                specs[capability_id] = spec
        self._specs = specs


def _validate_schema(schema: Mapping[str, Any], value: Any, *, path: str) -> None:
    if "allOf" in schema:
        for nested in schema["allOf"]:
            _validate_schema(nested, value, path=path)
    if "anyOf" in schema and not any(_schema_accepts(nested, value, path=path) for nested in schema["anyOf"]):
        raise ValueError(f"{path} does not match any allowed schema.")
    if "oneOf" in schema:
        matches = sum(1 for nested in schema["oneOf"] if _schema_accepts(nested, value, path=path))
        if matches != 1:
            raise ValueError(f"{path} must match exactly one allowed schema.")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is not an allowed value.")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match the required constant.")

    expected = schema.get("type")
    if expected is not None:
        expected_types = expected if isinstance(expected, list) else [expected]
        if not any(_matches_type(item, value) for item in expected_types):
            raise ValueError(f"{path} has invalid type; expected {expected!r}.")

    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ValueError(f"{path}.{key} is required.")
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            raise ValueError(f"{path} has too few properties.")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise ValueError(f"{path} has too many properties.")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                _validate_schema(properties[key], item, path=f"{path}.{key}")
            elif additional is False:
                raise ValueError(f"{path}.{key} is not allowed.")
            elif isinstance(additional, Mapping):
                _validate_schema(additional, item, path=f"{path}.{key}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValueError(f"{path} is shorter than minLength.")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ValueError(f"{path} exceeds maxLength.")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValueError(f"{path} does not match required pattern.")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValueError(f"{path} has too few items.")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValueError(f"{path} has too many items.")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise ValueError(f"{path} items must be unique.")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema(item_schema, item, path=f"{path}[{index}]")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path} is below minimum.")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValueError(f"{path} exceeds maximum.")


def _schema_accepts(schema: Mapping[str, Any], value: Any, *, path: str) -> bool:
    try:
        _validate_schema(schema, value, path=path)
    except ValueError:
        return False
    return True


def _matches_type(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ValueError(f"Unsupported schema type: {expected!r}.")
