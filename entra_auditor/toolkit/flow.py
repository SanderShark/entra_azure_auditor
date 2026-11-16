"""The change flow every tenant change goes through, independent of any user interface.

    start -> NeedsConfirmation(plan) -> execute
          -> (Entra says "forbidden") -> NeedsElevation(candidate_roles) -> NeedsJustification(role)
          -> activate, wait until active, refresh the token, retry -> Done(result)

`ChangeFlow` is a small state machine. Each call returns the next `Step`; the caller (the terminal
UI, a GUI dialog sequence, a test) answers it by calling the matching method:

    NeedsConfirmation   -> flow.confirm(True | False)
    NeedsElevation      -> flow.choose_role(role | None)   (None: don't elevate)
    NeedsJustification  -> flow.justify(text | None)       (None: give up)
    Done                -> finished; read .result

The flow does the blocking work itself (executing the plan, activating a role, waiting for it), so a GUI
calls these methods from a worker thread. Progress and messages go to a `Reporter`; the default one
discards them. Nothing here prompts, prints, or imports a UI library.
"""

from __future__ import annotations

import time
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from typing import Any, Callable, ContextManager, Literal, Mapping, Optional, Protocol, Union

from ..graph.client import GraphError
from .actions import ActionPlan, ActionResult, execute_plan
from .admin_units import admin_units_of
from .group_pim import GroupAccess, GroupPimService
from .pim import AU_SCOPE_PREFIX, TENANT_SCOPE, PimError, PimRole, PimService, scope_applies

READ_ONLY_MESSAGE = "Read-only session: nothing was sent. Sign in without read-only mode to make changes."
RETRY_ATTEMPTS = 4         # tries after an elevation (the role takes a moment to take effect)
RETRY_WAIT = 8.0           # seconds between those tries

Level = Literal["info", "warning", "error", "success"]
# What an elevation can activate: a directory role, or (PIM for Groups) membership of a group holding the role.
Candidate = Union[PimRole, GroupAccess]


# --------------------------------------------------------------------------- #
# Steps
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class NeedsConfirmation:
    """Show the plan and ask whether to apply it."""
    plan: ActionPlan


@dataclass(frozen=True)
class NeedsElevation:
    """The change was denied; these could do it (best first): eligible PIM roles, then eligible group
    memberships whose group holds a suitable role. Pick one, or None."""
    plan: ActionPlan
    candidate_roles: tuple[Candidate, ...]
    minutes: int


@dataclass(frozen=True)
class NeedsJustification:
    """Activating `role` (a PimRole or a GroupAccess) needs a justification (ticket or task)."""
    role: Candidate
    minutes: int


@dataclass(frozen=True)
class Done:
    """Finished. `cancelled` = the operator declined at confirmation (nothing was sent).
    `activate_manually` lists roles the operator could activate themselves when the flow
    could not offer an elevation (e.g. their PIM roles couldn't be read)."""
    result: ActionResult
    cancelled: bool = False
    activate_manually: tuple[str, ...] = ()


Step = Union[NeedsConfirmation, NeedsElevation, NeedsJustification, Done]


class FlowStateError(RuntimeError):
    """An answer was given that doesn't match the step the flow is waiting on."""


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Notice:
    level: Level
    text: str


class Reporter(Protocol):
    def notice(self, notice: Notice) -> None: ...

    def busy(self, text: str) -> ContextManager[Any]: ...


class NullReporter:
    def notice(self, notice: Notice) -> None:
        pass

    def busy(self, text: str) -> ContextManager[Any]:
        return nullcontext()


@dataclass
class RecordingReporter:
    """Keeps every notice and busy message (useful in tests and for a GUI's activity pane)."""
    notices: list[Notice] = field(default_factory=list)
    busy_texts: list[str] = field(default_factory=list)

    def notice(self, notice: Notice) -> None:
        self.notices.append(notice)

    def busy(self, text: str) -> ContextManager[Any]:
        self.busy_texts.append(text)
        return nullcontext()


# --------------------------------------------------------------------------- #
# PIM activation (also used on its own by `pim activate`)
# --------------------------------------------------------------------------- #

def is_read_only(sess: Any) -> bool:
    """A read-only session sends no change and activates no role (giving up an active role is still allowed)."""
    return bool(getattr(sess, "read_only", False))


def activate_and_wait(sess: Any, pim: Any, role: Candidate, reason: str, minutes: int,
                      reporter: Optional[Reporter] = None) -> bool:
    """Activate `role` (with a PimService) or a group membership (with a GroupPimService), wait until it is
    effective and refresh the token. True when it is usable."""
    rep = reporter or NullReporter()
    if is_read_only(sess):
        rep.notice(Notice("error", f"Not activating {role.name}: this is a read-only session."))
        return False
    try:
        result = pim.activate(role, reason=reason, minutes=minutes)
    except PimError as exc:
        rep.notice(Notice("error", f"Could not activate {role.name}: {exc}"))
        if exc.hint:
            rep.notice(Notice("info", exc.hint))
        return False
    if result.pending_approval:
        rep.notice(Notice("warning", f"{role.name} needs approval; the request was sent to the approvers."))
        return False
    with rep.busy(f"Waiting for {role.name} to become active..."):
        active = (pim.wait_until_active(role) if isinstance(role, GroupAccess)
                  else pim.wait_until_active(role.role_id, scope=role.scope))
    if not active:
        rep.notice(Notice("warning", f"{role.name} was requested but isn't showing as active yet; try again shortly."))
        return False
    sess.refresh()
    rep.notice(Notice("success", f"{role.name} is active for {minutes} minutes."))
    return True


# --------------------------------------------------------------------------- #
# The state machine
# --------------------------------------------------------------------------- #

class ChangeFlow:
    """One change, from preview to result. See the module docstring for the protocol.

    `sess` needs `.graph`, `.identity`, `.user_mode` and `.refresh()` (the toolkit's `Session` has them).
    """

    def __init__(
        self,
        sess: Any,
        plan: ActionPlan,
        *,
        dry_run: bool = False,
        minutes: int = 60,
        extra_secrets: Optional[Mapping[str, str]] = None,
        reporter: Optional[Reporter] = None,
        pim: Optional[PimService] = None,
        group_pim: Optional[GroupPimService] = None,
        sleep: Callable[[float], None] = time.sleep,
        retry_attempts: int = RETRY_ATTEMPTS,
        retry_wait: float = RETRY_WAIT,
    ) -> None:
        self.sess = sess
        self.plan = plan
        self.dry_run = dry_run
        self.minutes = minutes
        self._extra_secrets = dict(extra_secrets or {})
        self.reporter: Reporter = reporter or NullReporter()
        self._pim = pim
        self._group_pim = group_pim
        self._sleep = sleep
        self._attempts = max(1, retry_attempts)
        self._wait = retry_wait
        self._denied: Optional[ActionResult] = None
        self.step: Optional[Step] = None

    # -- public protocol ---------------------------------------------------- #

    def start(self) -> Step:
        if self.step is not None:
            raise FlowStateError("The flow has already started.")
        if self.dry_run:
            return self._done(execute_plan(self.sess.graph, self.plan, actor=self.sess.identity, dry_run=True),
                              add_secrets=False)
        if is_read_only(self.sess):       # the backstop: whatever screen or command built the plan
            return self._done(ActionResult("skipped", READ_ONLY_MESSAGE), add_secrets=False)
        return self._go(NeedsConfirmation(self.plan))

    def confirm(self, apply: bool) -> Step:
        self._expect(NeedsConfirmation)
        if not apply:
            return self._go(Done(ActionResult("skipped", "Cancelled by the user."), cancelled=True))
        result = self._execute()
        if result.status != "denied":
            return self._done(result)
        self._denied = result
        return self._after_denied()

    def choose_role(self, role: Optional[Candidate]) -> Step:
        step = self._expect(NeedsElevation)
        if role is None:
            return self._done(self._denied)
        if role not in step.candidate_roles:
            raise ValueError(f"{role.name} is not one of the offered roles.")
        return self._go(NeedsJustification(role, self.minutes))

    def justify(self, reason: Optional[str]) -> Step:
        step = self._expect(NeedsJustification)
        if reason is None:
            return self._done(self._denied)
        why = reason.strip()
        if not why:
            raise ValueError("A justification is required.")
        service = self._group_pim_service() if isinstance(step.role, GroupAccess) else self._pim_service()
        if not activate_and_wait(self.sess, service, step.role, why, self.minutes, self.reporter):
            return self._done(self._denied)
        return self._retry()

    @property
    def done(self) -> bool:
        return isinstance(self.step, Done)

    # -- internals ---------------------------------------------------------- #

    def _go(self, step: Step) -> Step:
        self.step = step
        return step

    def _expect(self, kind: type) -> Any:
        if not isinstance(self.step, kind):
            current = type(self.step).__name__ if self.step is not None else "not started"
            raise FlowStateError(f"The flow is waiting on {current}, not {kind.__name__}.")
        return self.step

    def _done(self, result: ActionResult, *, add_secrets: bool = True, activate_manually: tuple[str, ...] = ()) -> Step:
        if add_secrets and result.status == "ok" and self._extra_secrets:
            result.secrets.update(self._extra_secrets)  # e.g. a password generated locally: shown once
        return self._go(Done(result, activate_manually=activate_manually))

    def _execute(self) -> ActionResult:
        return execute_plan(self.sess.graph, self.plan, actor=self.sess.identity)

    def _pim_service(self) -> PimService:
        if self._pim is None:
            self._pim = PimService(self.sess.graph)
        return self._pim

    def _group_pim_service(self) -> GroupPimService:
        if self._group_pim is None:
            self._group_pim = GroupPimService(self.sess.graph)
        return self._group_pim

    def _read_groups(self) -> tuple[list[GroupAccess], list[GroupAccess]]:
        """Eligible and active PIM group memberships, or nothing if they can't be read (the permissions for
        PIM for Groups are optional; without them the flow offers roles only, as before)."""
        service = self._group_pim_service()
        try:
            return service.eligible(), service.active(with_roles=True)
        except (PimError, GraphError):
            return [], []

    def _say(self, level: Level, text: str) -> None:
        self.reporter.notice(Notice(level, text))

    def _target_units(self) -> Optional[dict[str, str]]:
        """{id: name} of the administrative units the plan's target is in; None when they can't be read.
        Only users and groups are looked up: a role scoped to a unit manages the unit's members, never the
        unit itself, so for any other target no scoped role applies."""
        if self.plan.target_type not in ("user", "group"):
            return {}
        try:
            return admin_units_of(self.sess.graph, self.plan.target_type, self.plan.target_id)
        except GraphError:
            self._say("info", f"Couldn't check which administrative units {self.plan.target_name} is in, so roles "
                              "scoped to one unit are offered too; they only work if it is in that unit.")
            return None

    def _after_denied(self) -> Step:
        """Work out whether an elevation can be offered, and offer it."""
        plan, denied = self.plan, self._denied
        assert denied is not None
        self._say("warning", "Entra says your current permissions aren't enough for this change.")
        if not self.sess.user_mode:
            self._say("info", "PIM only works with a user sign-in (--mode device or browser); in app mode the "
                              "app registration itself lacks the permission.")
            return self._done(denied)
        pim = self._pim_service()
        try:
            eligible, active = pim.eligible(), pim.active()
        except GraphError as exc:
            self._say("info", f"Couldn't read your PIM roles ({exc}).")
            return self._done(denied, activate_manually=tuple(plan.suggested_roles))

        wanted = {n.lower() for n in plan.suggested_roles}
        groups_eligible, groups_active = self._read_groups()

        # A role (or a group's role) can be scoped to one administrative unit: it then only helps when the
        # target is in that unit. Look the target's units up only when such a role is in play.
        scoped_roles = [r for r in [*eligible, *active] if r.name.lower() in wanted and not r.tenant_wide]
        scoped_groups = [g for g in [*groups_eligible, *groups_active] if g.access == "member"
                         and any(n.lower() in wanted and s != TENANT_SCOPE for n, s in g.role_scopes)]
        units: Optional[dict[str, str]] = {}
        if scoped_roles or scoped_groups:
            units = self._target_units()
        scopes = None if units is None else frozenset({TENANT_SCOPE} | {AU_SCOPE_PREFIX + u for u in units})

        already: list[Candidate] = [r for r in active if r.name.lower() in wanted and scope_applies(r.scope, scopes)]
        already += [g for g in groups_active if g.access == "member"
                    and any(g.grants(name, scopes) for name in plan.suggested_roles)]
        if already:
            self._say("info", f"You already have {already[0].name} active; refreshing your token and retrying.")
            self.sess.refresh()
            return self._retry()

        matches: list[Candidate] = [self._named(r, units) for r in
                                    PimService.match(eligible, plan.suggested_roles, active, scopes)]
        matches += GroupPimService.granting(groups_eligible, plan.suggested_roles, groups_active, scopes)
        if not matches:
            self._say("info", "You aren't eligible for any role that can do this ("
                              + ", ".join(plan.suggested_roles) + ").")
            outside = sorted({r.name for r in scoped_roles if r.state == "eligible"}
                             | {g.name for g in scoped_groups if g.state == "eligible"})
            if outside:
                self._say("info", ", ".join(outside) + ": scoped to an administrative unit that "
                                  f"{plan.target_name} isn't in, so it can't be used for this change.")
            if eligible:
                self._say("info", "You are eligible for: " + ", ".join(r.label for r in eligible))
            return self._done(denied)
        return self._go(NeedsElevation(plan, tuple(matches), self.minutes))

    @staticmethod
    def _named(role: PimRole, units: Optional[dict[str, str]]) -> PimRole:
        """The role with its administrative unit's name filled in (for the label), when we know it."""
        name = (units or {}).get(role.scope[len(AU_SCOPE_PREFIX):]) if role.scope.startswith(AU_SCOPE_PREFIX) else None
        return replace(role, scope_name=name) if name else role

    def _retry(self) -> Step:
        """Retry after an elevation: the role can take a little while to show up in the token."""
        result = self._denied
        for attempt in range(self._attempts):
            result = self._execute()
            if result.status != "denied" or attempt == self._attempts - 1:
                break
            if attempt == 1:
                self.sess.refresh()
            with self.reporter.busy("Waiting for the role to take effect..."):
                self._sleep(self._wait)
        assert result is not None
        return self._done(result)
