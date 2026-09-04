from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from pathlib import Path


MAX_SOURCE_BYTES = 512 * 1024
BACKEND_REVISION = "builtin-ast-v2"


@dataclass(frozen=True)
class SymbolRecord:
    symbol_id: str
    path: str
    kind: str
    name: str
    start_line: int
    end_line: int
    content_hash: str


@dataclass(frozen=True)
class SemanticEdge:
    relation: str
    source: str
    target: str
    path: str
    line: int


@dataclass(frozen=True)
class SemanticIndexSnapshot:
    identity: str
    symbols: tuple[SymbolRecord, ...]
    edges: tuple[SemanticEdge, ...]

    def symbol(self, symbol_id: str) -> SymbolRecord:
        for item in self.symbols:
            if item.symbol_id == symbol_id:
                return item
        raise KeyError(symbol_id)

    def references_to(self, symbol_id: str) -> tuple[SemanticEdge, ...]:
        return tuple(edge for edge in self.edges if edge.relation == "reference" and edge.target == symbol_id)

    def importers_of(self, module_id: str) -> tuple[str, ...]:
        return tuple(sorted({edge.source for edge in self.edges if edge.relation == "import" and edge.target == module_id}))

    def tests_for(self, symbol_id: str) -> tuple[str, ...]:
        return tuple(sorted({edge.source.split(":", 1)[0] for edge in self.edges if edge.relation == "test" and edge.target == symbol_id}))


@dataclass(frozen=True)
class SemanticQuery:
    text: str = ""
    symbol: str = ""
    path: str = ""
    relations: tuple[str, ...] = ("definition", "references", "imports", "tests")
    limit: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or len(self.text) > 500 or "\x00" in self.text:
            raise ValueError("query text is invalid")
        if not isinstance(self.symbol, str) or len(self.symbol) > 500 or "\x00" in self.symbol:
            raise ValueError("query symbol is invalid")
        if not isinstance(self.path, str) or len(self.path) > 1000 or "\x00" in self.path:
            raise ValueError("query path is invalid")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= 100:
            raise ValueError("query limit is outside bounds")
        allowed = {"definition", "references", "imports", "tests"}
        if not self.relations or len(self.relations) != len(set(self.relations)) or any(item not in allowed for item in self.relations):
            raise ValueError("query relations are invalid")


@dataclass(frozen=True)
class SemanticMatch:
    relation: str
    symbol_id: str
    path: str
    line: int
    score: int
    confidence: float
    reason: str
    source_hash: str

    def as_dict(self) -> dict[str, object]:
        return {
            "relation": self.relation,
            "symbol_id": self.symbol_id,
            "path": self.path,
            "line": self.line,
            "score": self.score,
            "confidence": self.confidence,
            "reason": self.reason,
            "source_hash": self.source_hash,
        }


@dataclass(frozen=True)
class _ParsedFile:
    path: Path
    relative_path: str
    module_id: str
    content_hash: str
    tree: ast.AST


def _module_id(relative_path: str) -> str:
    path = relative_path[:-3] if relative_path.endswith(".py") else relative_path
    parts = path.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_test_module(module_id: str, relative_path: str) -> bool:
    name = Path(relative_path).name
    return module_id.startswith("tests.") or name.startswith("test_") or name.endswith("_test.py")


def _qualname(stack: list[str], name: str) -> str:
    return ".".join((*stack, name)) if stack else name


class _DefinitionVisitor(ast.NodeVisitor):
    def __init__(self, parsed: _ParsedFile) -> None:
        self.parsed = parsed
        self.stack: list[str] = []
        self.symbols: list[SymbolRecord] = []

    def _record(self, node: ast.AST, name: str, kind: str) -> None:
        qualified = _qualname(self.stack, name)
        self.symbols.append(SymbolRecord(symbol_id=f"{self.parsed.module_id}:{qualified}", path=self.parsed.relative_path, kind=kind, name=name, start_line=int(getattr(node, "lineno", 1)), end_line=int(getattr(node, "end_lineno", getattr(node, "lineno", 1))), content_hash=self.parsed.content_hash))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record(node, node.name, "function" if not self.stack else "method")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record(node, node.name, "function" if not self.stack else "method")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._record(node, node.name, "class")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


class _EdgeVisitor(ast.NodeVisitor):
    def __init__(self, parsed: _ParsedFile) -> None:
        self.parsed = parsed
        self.stack: list[str] = []
        self.direct_symbols: dict[str, str] = {}
        self.local_symbols: dict[str, str] = {}
        self.modules: dict[str, str] = {}
        self.edges: list[SemanticEdge] = []
        if isinstance(parsed.tree, ast.Module):
            for node in parsed.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    self.local_symbols[node.name] = f"{parsed.module_id}:{node.name}"

    def _source(self) -> str:
        return self.parsed.module_id if not self.stack else f"{self.parsed.module_id}:{'.'.join(self.stack)}"

    def _append(self, relation: str, target: str, node: ast.AST) -> None:
        self.edges.append(SemanticEdge(relation=relation, source=self._source(), target=target, path=self.parsed.relative_path, line=int(getattr(node, "lineno", 1))))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level != 0 or not node.module:
            return
        self._append("import", node.module, node)
        for alias in node.names:
            if alias.name != "*":
                self.direct_symbols[alias.asname or alias.name] = f"{node.module}:{alias.name}"

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.modules[local] = alias.name
            self._append("import", alias.name, node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        target = ""
        if isinstance(node.func, ast.Name):
            target = self.direct_symbols.get(node.func.id, "") or self.local_symbols.get(node.func.id, "")
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = self.modules.get(node.func.value.id)
            if module:
                target = f"{module}:{node.func.attr}"
        if target:
            self._append("reference", target, node)
            if _is_test_module(self.parsed.module_id, self.parsed.relative_path):
                self._append("test", target, node)
        self.generic_visit(node)


class SemanticIndex:
    def __init__(self, root: Path, *, identity: str) -> None:
        self.root = Path(root).resolve(strict=True)
        self.identity = identity
        self._parsed_files: dict[str, _ParsedFile] = {}
        self._content_hashes: dict[str, str] = {}
        self._file_symbols: dict[str, tuple[SymbolRecord, ...]] = {}
        self._file_edges: dict[str, tuple[SemanticEdge, ...]] = {}

    def _drop_path(self, path: str) -> None:
        self._parsed_files.pop(path, None)
        self._content_hashes.pop(path, None)
        self._file_symbols.pop(path, None)
        self._file_edges.pop(path, None)

    def _index_parsed(self, parsed: _ParsedFile) -> None:
        definitions = _DefinitionVisitor(parsed)
        definitions.visit(parsed.tree)
        relations = _EdgeVisitor(parsed)
        relations.visit(parsed.tree)
        self._parsed_files[parsed.relative_path] = parsed
        self._content_hashes[parsed.relative_path] = parsed.content_hash
        self._file_symbols[parsed.relative_path] = tuple(definitions.symbols)
        self._file_edges[parsed.relative_path] = tuple(relations.edges)

    def _files(self) -> tuple[Path, ...]:
        files: list[Path] = []
        for path in self.root.rglob("*.py"):
            relative = path.relative_to(self.root)
            if any(part.startswith(".") for part in relative.parts) or path.is_symlink() or not path.is_file():
                continue
            try:
                if path.stat().st_size > MAX_SOURCE_BYTES:
                    continue
            except OSError:
                continue
            files.append(path)
        return tuple(sorted(files, key=lambda item: item.as_posix()))

    def _parse(self, path: Path) -> _ParsedFile | None:
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if len(data) > MAX_SOURCE_BYTES or b"\x00" in data:
            return None
        try:
            text = data.decode("utf-8")
            tree = ast.parse(text, filename=str(path))
        except (UnicodeDecodeError, SyntaxError):
            return None
        relative = path.relative_to(self.root).as_posix()
        module_relative = relative
        relative_parts = Path(relative).parts
        if (
            len(relative_parts) > 1
            and relative_parts[0] == "src"
            and not (self.root / "src" / "__init__.py").is_file()
        ):
            module_relative = Path(*relative_parts[1:]).as_posix()
        return _ParsedFile(path=path, relative_path=relative, module_id=_module_id(module_relative), content_hash=hashlib.sha256(data).hexdigest(), tree=tree)

    def _snapshot(self) -> SemanticIndexSnapshot:
        symbols: list[SymbolRecord] = []
        edges: list[SemanticEdge] = []
        for path in sorted(self._file_symbols):
            symbols.extend(self._file_symbols[path])
            edges.extend(self._file_edges.get(path, ()))
        return SemanticIndexSnapshot(identity=self.identity, symbols=tuple(sorted(symbols, key=lambda item: (item.symbol_id, item.path, item.start_line))), edges=tuple(sorted(edges, key=lambda item: (item.relation, item.target, item.source, item.path, item.line))))

    def build(self) -> SemanticIndexSnapshot:
        parsed_files = tuple(parsed for parsed in (self._parse(path) for path in self._files()) if parsed is not None and parsed.module_id)
        for parsed in parsed_files:
            self._index_parsed(parsed)
        current = {parsed.relative_path for parsed in parsed_files}
        for stale in set(self._file_symbols) - current:
            self._drop_path(stale)
        return self._snapshot()

    def refresh(self, changed_paths: tuple[str, ...]) -> SemanticIndexSnapshot:
        for raw_path in changed_paths:
            if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
                raise ValueError("changed path is invalid")
            relative = Path(raw_path)
            if relative.is_absolute() or any(part in {"", ".", ".."} or part.startswith(".") for part in relative.parts):
                raise ValueError("changed path is invalid")
            normalized = relative.as_posix()
            if not normalized.endswith(".py"):
                self._drop_path(normalized)
                continue
            target = self.root / relative
            if target.is_symlink() or not target.is_file():
                self._drop_path(normalized)
                continue
            try:
                resolved = target.resolve(strict=True)
                resolved.relative_to(self.root)
            except (OSError, ValueError):
                self._drop_path(normalized)
                continue
            parsed = self._parse(resolved)
            if parsed is None or not parsed.module_id:
                self._drop_path(normalized)
            else:
                self._index_parsed(parsed)
        return self._snapshot()

    def metadata_records(self, *, workspace_id: str, working_tree_id: str, source_revision: str, updated_at: str) -> list[dict[str, object]]:
        if not self._file_symbols:
            self.build()
        records: list[dict[str, object]] = []
        for path in sorted(self._file_symbols):
            records.append({
                "workspace_id": workspace_id,
                "working_tree_id": working_tree_id,
                "source_revision": source_revision,
                "backend_revision": BACKEND_REVISION,
                "path": path,
                "content_hash": self._content_hashes[path],
                "symbols": [{"symbol_id": item.symbol_id, "kind": item.kind, "name": item.name, "start_line": item.start_line, "end_line": item.end_line} for item in self._file_symbols[path]],
                "edges": [{"relation": item.relation, "source": item.source, "target": item.target, "line": item.line} for item in self._file_edges.get(path, ())],
                "updated_at": updated_at,
            })
        return records

    def restore_metadata(self, records: list[dict[str, object]]) -> bool:
        if not isinstance(records, list) or not records:
            return False
        restored_hashes: dict[str, str] = {}
        restored_symbols: dict[str, tuple[SymbolRecord, ...]] = {}
        restored_edges: dict[str, tuple[SemanticEdge, ...]] = {}
        for record in records:
            if not isinstance(record, dict) or record.get("backend_revision") != BACKEND_REVISION:
                return False
            path = record.get("path")
            content_hash = record.get("content_hash")
            symbols = record.get("symbols")
            edges = record.get("edges")
            if not isinstance(path, str) or not path.endswith(".py") or path.startswith(("/", "~")) or "\\" in path or any(part in {"", ".", ".."} or part.startswith(".") for part in Path(path).parts) or not isinstance(content_hash, str) or len(content_hash) != 64 or not isinstance(symbols, list) or not isinstance(edges, list):
                return False
            target = self.root / path
            if target.is_symlink() or not target.is_file():
                return False
            try:
                resolved = target.resolve(strict=True)
                resolved.relative_to(self.root)
                data = resolved.read_bytes()
            except (OSError, ValueError):
                return False
            if len(data) > MAX_SOURCE_BYTES or hashlib.sha256(data).hexdigest() != content_hash:
                return False
            try:
                restored_symbols[path] = tuple(SymbolRecord(symbol_id=str(item["symbol_id"]), path=path, kind=str(item["kind"]), name=str(item["name"]), start_line=int(item["start_line"]), end_line=int(item["end_line"]), content_hash=content_hash) for item in symbols if isinstance(item, dict))
                restored_edges[path] = tuple(SemanticEdge(relation=str(item["relation"]), source=str(item["source"]), target=str(item["target"]), path=path, line=int(item["line"])) for item in edges if isinstance(item, dict))
            except (KeyError, TypeError, ValueError):
                return False
            if len(restored_symbols[path]) != len(symbols) or len(restored_edges[path]) != len(edges):
                return False
            restored_hashes[path] = content_hash
        self._parsed_files.clear()
        self._content_hashes = restored_hashes
        self._file_symbols = restored_symbols
        self._file_edges = restored_edges
        return True

    def query(self, query: SemanticQuery) -> tuple[SemanticMatch, ...]:
        if not isinstance(query, SemanticQuery):
            raise TypeError("query must be a SemanticQuery")
        snapshot = self._snapshot() if self._file_symbols else self.build()
        text = query.text.casefold().strip()
        requested_path = query.path.strip()
        matches: list[SemanticMatch] = []
        if "definition" in query.relations:
            for symbol in snapshot.symbols:
                exact_symbol = bool(query.symbol and symbol.symbol_id == query.symbol)
                exact_text = bool(text and (symbol.name.casefold() == text or symbol.symbol_id.casefold() == text))
                fuzzy_text = bool(text and (text in symbol.name.casefold() or text in symbol.symbol_id.casefold()))
                if query.symbol and not exact_symbol and not fuzzy_text:
                    continue
                if not query.symbol and text and not fuzzy_text:
                    continue
                score = 100 if exact_symbol else 78 if exact_text else 62 if fuzzy_text else 45
                reasons = ["exact_symbol" if exact_symbol else "exact_text" if exact_text else "fuzzy_text" if fuzzy_text else "definition"]
                if requested_path and symbol.path == requested_path:
                    score += 8
                    reasons.append("same_path")
                matches.append(SemanticMatch(relation="definition", symbol_id=symbol.symbol_id, path=symbol.path, line=symbol.start_line, score=score, confidence=min(1.0, score / 108.0), reason="+".join(reasons), source_hash=symbol.content_hash))
        relation_map = {"references": "reference", "imports": "import", "tests": "test"}
        for requested_relation, edge_relation in relation_map.items():
            if requested_relation not in query.relations:
                continue
            for edge in snapshot.edges:
                if edge.relation != edge_relation:
                    continue
                exact_symbol = bool(query.symbol and edge.target == query.symbol)
                fuzzy_text = bool(text and (text in edge.target.casefold() or text in edge.source.casefold()))
                if query.symbol and not exact_symbol and not fuzzy_text:
                    continue
                if not query.symbol and text and not fuzzy_text:
                    continue
                base = {"reference": 72, "test": 68, "import": 60}[edge_relation]
                score = base + (8 if exact_symbol else 0)
                reasons = ["exact_symbol_edge" if exact_symbol else "fuzzy_edge"]
                if requested_path and edge.path == requested_path:
                    score += 12
                    reasons.append("same_path")
                parsed = self._parsed_files.get(edge.path)
                source_hash = parsed.content_hash if parsed is not None else hashlib.sha256(f"{self.identity}\0{edge.path}".encode("utf-8")).hexdigest()
                matches.append(SemanticMatch(relation=edge_relation, symbol_id=edge.target, path=edge.path, line=edge.line, score=score, confidence=min(0.99, score / 108.0), reason="+".join(reasons), source_hash=source_hash))
        matches.sort(key=lambda item: (-item.score, item.path, item.line, item.relation, item.symbol_id))
        return tuple(matches[: query.limit])
