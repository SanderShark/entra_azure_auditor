"""Desktop app building blocks: the background task runner, the user model and the type-to-filter proxy."""

import threading
import time

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import QThread, Qt  # noqa: E402

from entra_auditor.gui.user_model import USER_ROLE, UserFilterProxy, UserTableModel  # noqa: E402
from entra_auditor.toolkit.directory import load_users  # noqa: E402
from entra_auditor.toolkit.models import UserSummary  # noqa: E402
from tests.fakes import FakeTenant  # noqa: E402


# ---- TaskRunner --------------------------------------------------------------------------

def test_work_runs_off_the_ui_thread_and_the_result_comes_back_on_it(qtbot, runner):
    ui_thread = QThread.currentThread()
    seen = {}

    def work():
        seen["work_thread"] = threading.current_thread()
        return 42

    def done(value):
        seen["value"], seen["callback_thread"] = value, QThread.currentThread()

    runner.submit(work, done)
    qtbot.waitUntil(lambda: "value" in seen)
    assert seen["value"] == 42
    assert seen["work_thread"] is not threading.main_thread()
    assert seen["callback_thread"] is ui_thread


def test_a_failure_reaches_the_error_callback_on_the_ui_thread(qtbot, runner):
    ui_thread = QThread.currentThread()
    seen = {}

    def boom():
        raise RuntimeError("no network")

    runner.submit(boom, lambda v: seen.setdefault("done", v),
                  lambda exc: seen.update(error=exc, thread=QThread.currentThread()))
    qtbot.waitUntil(lambda: "error" in seen)
    assert isinstance(seen["error"], RuntimeError) and "done" not in seen and seen["thread"] is ui_thread


def test_the_ui_keeps_running_while_work_blocks(qtbot, runner):
    release = threading.Event()
    seen = []
    runner.submit(lambda: release.wait(5), seen.append)
    qtbot.wait(50)                       # the event loop is free while the worker waits
    assert runner.busy and not seen
    release.set()
    qtbot.waitUntil(lambda: seen == [True])
    assert not runner.busy


# ---- the user model -----------------------------------------------------------------------

@pytest.fixture
def models(qtbot):
    model = UserTableModel()
    model.set_users(load_users(FakeTenant()))
    proxy = UserFilterProxy()
    proxy.setSourceModel(model)
    return model, proxy


def names(proxy):
    return sorted(proxy.index(r, 0).data() for r in range(proxy.rowCount()))


def test_the_model_shows_one_row_per_user_with_readable_columns(models):
    model, _ = models
    assert model.rowCount() == 8 and model.columnCount() == 6
    row = next(r for r in range(8) if model.index(r, 1).data() == "alice@contoso.com")
    assert [model.index(row, c).data() for c in range(6)] == [
        "Alice Ng", "alice@contoso.com", "Member", "Enabled", "Engineer", "IT"]
    assert model.index(row, 0).data(USER_ROLE).id == "u-alice"


def test_typing_filters_on_any_field_and_every_word_must_match(models):
    _, proxy = models
    proxy.set_filter_text("bob")
    assert names(proxy) == ["Bob Smith", "Bob Stone"]
    proxy.set_filter_text("BOB  smith")                      # case-insensitive, words in any field
    assert names(proxy) == ["Bob Smith"]
    proxy.set_filter_text("E100")                            # employee id
    assert names(proxy) == ["Alice Ng"]
    proxy.set_filter_text("a.ng@")                           # not a column, but mail/aliases count
    assert names(proxy) == []                                # proxy addresses aren't loaded in the list
    proxy.set_filter_text("")
    assert proxy.rowCount() == 8


def test_disabled_and_synced_can_be_typed_as_words(models):
    model, proxy = models
    alice = next(u for u in model.users if u.id == "u-alice")
    model.update_user(alice.model_copy(update={"account_enabled": False}))
    proxy.set_filter_text("disabled")
    assert names(proxy) == ["Alice Ng"]
    proxy.set_filter_text("synced")
    assert names(proxy) == ["Sync Sam"]


def test_updating_one_user_changes_only_that_row(models, qtbot):
    model, _ = models
    alice = next(u for u in model.users if u.id == "u-alice")
    with qtbot.waitSignal(model.dataChanged) as signal:
        model.update_user(alice.model_copy(update={"account_enabled": False}))
    top_left, bottom_right = signal.args[:2]
    assert top_left.row() == bottom_right.row() and model.index(top_left.row(), 3).data() == "Disabled"
    assert model.index(top_left.row(), 3).data(Qt.ItemDataRole.ForegroundRole) is not None
    model.update_user(UserSummary(id="not-loaded"))           # unknown ids are ignored
    assert model.rowCount() == 8


def test_filtering_fifty_thousand_users_is_fast_enough_to_feel_instant(qtbot):
    model = UserTableModel()
    model.set_users([UserSummary(id=f"u{i}", display_name=f"User {i}", upn=f"user{i}@contoso.com",
                                 department=("Sales" if i % 7 else "Finance")) for i in range(50_000)])
    proxy = UserFilterProxy()
    proxy.setSourceModel(model)
    start = time.perf_counter()
    proxy.set_filter_text("finance user1")
    elapsed = time.perf_counter() - start
    assert proxy.rowCount() > 0 and elapsed < 1.0
