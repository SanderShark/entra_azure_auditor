"""Shared fixtures. Nothing here touches a real tenant, the network, or your home directory."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from types import SimpleNamespace

# Rich wraps output at the terminal width. Make it wide so assertions on printed text don't
# break across lines. This must run BEFORE the package (and its Rich consoles) is imported.
os.environ["COLUMNS"] = "250"
# GUI tests run headless everywhere (no display needed); CI sets the same.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

try:
    import questionary  # noqa: E402
    import typer  # noqa: E402
except ImportError as exc:  # pragma: no cover - an environment problem, not a test failure
    pytest.exit(
        f"The tests need the project's dependencies ('{exc.name}' is missing). Inside your virtualenv run:\n"
        "    python -m pip install -r requirements-dev.txt\n"
        "and start the tests with:\n"
        "    python -m pytest\n"
        "(a bare `pytest` may belong to a different Python than your virtualenv's).",
        returncode=2,
    )

from tests.fakes import FakeTenant  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Tests must never read the developer's real settings or write into their home directory."""
    for key in list(os.environ):
        if key.startswith(("AZURE_", "AUDITOR_", "GRAPH_")):
            monkeypatch.delenv(key)
    paths = SimpleNamespace(
        log=tmp_path / "actions.jsonl", runs=tmp_path / "runs", cache=tmp_path / "token_cache.json")
    monkeypatch.setenv("AUDITOR_ACTION_LOG", str(paths.log))
    monkeypatch.setenv("AUDITOR_RUNS_DIR", str(paths.runs))
    monkeypatch.setenv("AUDITOR_TOKEN_CACHE", str(paths.cache))
    paths.config = tmp_path / "config"          # tenants.json and per-tenant token caches
    monkeypatch.setenv("AUDITOR_CONFIG_DIR", str(paths.config))
    return paths


class Prompts:
    """Scripted answers for ``typer.confirm/prompt`` and questionary menus.

    An unscripted prompt fails the test, so a flow that unexpectedly asks something is caught."""

    def __init__(self):
        self.typer: list = []
        self.menu: list = []
        self.asked_typer: list = []
        self.asked_menu: list = []

    def say(self, *answers):
        """Answers for typer.confirm / typer.prompt, in the order they will be asked."""
        self.typer[:] = list(answers)

    def pick(self, *answers):
        """Answers for questionary calls. A string selects the choice whose title contains it;
        checkbox answers are lists of such strings; None means Ctrl-C."""
        self.menu[:] = list(answers)

    @property
    def exhausted(self):
        return not self.typer and not self.menu


def _install_prompts(monkeypatch, prompts: Prompts) -> None:
    def pop(queue, asked, kind, text):
        asked.append((kind, text))
        if not queue:
            raise AssertionError(f"unscripted {kind}: {text!r}")
        return queue.pop(0)

    monkeypatch.setattr(typer, "confirm", lambda text, *a, **k: pop(prompts.typer, prompts.asked_typer, "confirm", text))
    monkeypatch.setattr(typer, "prompt", lambda text, *a, **k: pop(prompts.typer, prompts.asked_typer, "prompt", text))

    class Ask:
        def __init__(self, fn):
            self.fn = fn

        def ask(self):
            return self.fn()

    def menu_pop(kind, message):
        return pop(prompts.menu, prompts.asked_menu, kind, message)

    def select(message, choices, **k):
        def go():
            want = menu_pop("select", message)
            if want is None:
                return None
            for choice in choices:
                if want in str(choice.title):
                    return choice.value
            raise AssertionError(f"no choice containing {want!r} for {message!r}: {[str(c.title)[:40] for c in choices]}")
        return Ask(go)

    def checkbox(message, choices, **k):
        def go():
            want = menu_pop("checkbox", message)
            if want is None:
                return None
            return [c.value for c in choices if any(w in str(c.title) for w in want)]
        return Ask(go)

    monkeypatch.setattr(questionary, "select", select)
    monkeypatch.setattr(questionary, "checkbox", checkbox)
    monkeypatch.setattr(questionary, "text", lambda message, *a, **k: Ask(lambda: menu_pop("text", message)))
    monkeypatch.setattr(questionary, "password", lambda message, *a, **k: Ask(lambda: menu_pop("password", message)))
    monkeypatch.setattr(questionary, "confirm", lambda message, *a, **k: Ask(lambda: menu_pop("confirm", message)))


class FakeProvider:
    """Stands in for a token provider; counts how often the token was force-refreshed."""

    def __init__(self):
        self.refreshes = 0

    def refresh(self):
        self.refreshes += 1

    def identity(self):
        return "user:me@contoso.com"


class Toolkit:
    """Runs toolkit commands against a fake tenant with scripted prompts and captured output."""

    def __init__(self, monkeypatch, capsys):
        self._mp, self._capsys = monkeypatch, capsys
        self.prompts = Prompts()
        self.tenant: FakeTenant | None = None
        self.session = None
        _install_prompts(monkeypatch, self.prompts)

    def use(self, tenant: FakeTenant | None = None, *, user_mode: bool = True, interactive: bool = False):
        import entra_auditor.toolkit.cli as tcli
        import entra_auditor.toolkit.ui as ui

        self.tenant = tenant or FakeTenant()
        self.session = ui.Session(
            graph=self.tenant, provider=FakeProvider(),
            settings=SimpleNamespace(mode=SimpleNamespace(is_user=user_mode)), identity="user:me@contoso.com")

        @contextmanager
        def fake_open(mode):
            yield self.session

        self._mp.setattr(tcli, "open_session", fake_open)
        self._mp.setattr(ui, "is_interactive", lambda: interactive)
        self._mp.setattr(tcli, "is_interactive", lambda: interactive)
        self._mp.setattr(ui, "_sleep", lambda seconds: None)
        return self.session

    def run(self, fn, *args, **kwargs):
        """Call a command/menu function. Returns (exit code, everything it printed)."""
        self._capsys.readouterr()
        try:
            fn(*args, **kwargs)
            code = 0
        except typer.Exit as exc:
            code = exc.exit_code
        captured = self._capsys.readouterr()
        return code, captured.out + captured.err


@pytest.fixture
def tk(monkeypatch, capsys):
    return Toolkit(monkeypatch, capsys)


@pytest.fixture
def tenant():
    return FakeTenant()


class TTY:
    """Wraps a stream and claims to be a terminal (for code that refuses to run without one)."""

    def __init__(self, inner):
        self._inner = inner

    def isatty(self):
        return True

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture
def fake_tty(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", TTY(sys.stdin))
    # pytest's capsys re-installs its own stream as sys.stdout at the start of every test phase, so a
    # wrapper put on sys.stdout here is gone by the time the test body runs. Mark the stream type instead.
    from _pytest.capture import CaptureIO

    monkeypatch.setattr(sys, "stdout", TTY(sys.stdout))
    monkeypatch.setattr(CaptureIO, "isatty", lambda self: True)


@pytest.fixture(autouse=True)
def no_stdin(monkeypatch):
    """Rich's console.input() calls input(); pytest forbids reading stdin, so answer 'Enter'."""
    import builtins

    monkeypatch.setattr(builtins, "input", lambda *args, **kwargs: "")


@pytest.fixture
def runner(qtbot):
    """The desktop app's background task runner (GUI tests only; they skip without PySide6)."""
    from entra_auditor.gui.tasks import TaskRunner

    task_runner = TaskRunner()
    yield task_runner
    task_runner.wait(10_000)
    qtbot.wait(10)          # let the last queued callbacks run before widgets go away
