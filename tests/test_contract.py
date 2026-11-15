"""The code may only use what the REAL GraphClient offers.

Tests run against fakes (tests/fakes.py). A fake that offers something the real client lacks lets a bug
through: that is exactly how `sess.graph.base_url` shipped broken (the fake had it, the client didn't).
This test reads every place the package touches a Graph client and checks it against the real class."""

import ast
import inspect
import pathlib

import entra_auditor
from entra_auditor.graph.client import GraphClient

PACKAGE = pathlib.Path(entra_auditor.__file__).parent
# methods that pass **kwargs on to another method
DELEGATES = {"get_all": "get_paged", "post": "request", "patch": "request", "delete": "request"}


def is_graph(node):
    """`graph`, `sess.graph`, `self.graph`, `self._graph`"""
    if isinstance(node, ast.Name):
        return node.id == "graph"
    return isinstance(node, ast.Attribute) and node.attr in ("graph", "_graph")


def uses():
    """(file, line, attribute, keyword names) for every `<graph>.attribute` in the package."""
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text())
        calls = {id(n.func): n for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and is_graph(node.value):
                call = calls.get(id(node))
                keywords = [k.arg for k in call.keywords if k.arg] if call else []
                found.append((path.relative_to(PACKAGE), node.lineno, node.attr, keywords))
    return found


def accepted_keywords(method):
    params = inspect.signature(getattr(GraphClient, method)).parameters
    allowed = set(params)
    if method in DELEGATES:
        allowed |= set(inspect.signature(getattr(GraphClient, DELEGATES[method])).parameters)
    return allowed


def test_the_scan_actually_finds_the_graph_calls():
    assert len(uses()) > 40          # guards against this test passing because it looked at nothing


def test_everything_used_on_a_graph_client_exists_on_the_real_client():
    missing = [f"{path}:{line} uses graph.{attr}" for path, line, attr, _ in uses() if not hasattr(GraphClient, attr)]
    assert missing == []


def test_every_keyword_argument_is_accepted_by_the_real_method():
    bad = []
    for path, line, attr, keywords in uses():
        if keywords and hasattr(GraphClient, attr):
            extra = set(keywords) - accepted_keywords(attr)
            if extra:
                bad.append(f"{path}:{line} graph.{attr}({', '.join(sorted(extra))}=...)")
    assert bad == []
