# SPDX-License-Identifier: Apache-2.0
"""
Regression tests for the post-failure analysis prompt.

When verify_pov reports that a POV ran without crashing, the POV agent injects a
message asking the agent whether the input reached the vulnerable function, and
quotes the fuzzer output underneath as the evidence for answering it.

That evidence was read from a key nothing produces, so the prompt asked the
question and then rendered "(no output)" every single time.

Needs no LLM, no MongoDB and no Docker.

Run with: pytest tests/test_pov_no_crash_feedback.py -v
"""

import inspect

from fuzzingbrain.agents.pov_agent import POVAgent
from fuzzingbrain.tools import pov as pov_tools

# The key _verify_pov_core puts the fuzzer-output summary under on a non-crash.
PRODUCED_KEY = "output_summary"

# The key the agent used to read. It is not produced anywhere in the codebase.
STALE_KEY = "output_hint"


class TestNoCrashFeedbackKey:
    """The consumer must read the key the producer writes."""

    def test_verify_pov_produces_output_summary_on_no_crash(self):
        """_verify_pov_core's non-crash return carries the output summary."""
        source = inspect.getsource(pov_tools._verify_pov_core)
        assert f'"{PRODUCED_KEY}"' in source, (
            f"_verify_pov_core no longer returns {PRODUCED_KEY!r}; "
            "the POV agent's post-failure prompt reads that key"
        )

    def test_stale_key_is_produced_by_nothing(self):
        """Nothing in the tools layer ever sets the key the agent used to read."""
        source = inspect.getsource(pov_tools)
        assert STALE_KEY not in source, (
            f"{STALE_KEY!r} now appears in the tools layer — if it became a real "
            "return key, this test and the agent's reader should be revisited"
        )

    def test_agent_reads_the_produced_key(self):
        """The post-failure prompt reads output_summary, not the stale key."""
        source = inspect.getsource(POVAgent._run_agent_loop)
        assert f'get("{PRODUCED_KEY}"' in source, (
            "the post-failure analysis prompt must read the key verify_pov "
            f"actually returns ({PRODUCED_KEY!r})"
        )
        # Only an actual read is a bug; the key may still be named in a comment.
        assert f'get("{STALE_KEY}"' not in source, (
            f"{STALE_KEY!r} is read but never produced, so the reach question "
            'in the injected prompt always renders "(no output)"'
        )

    def test_reach_question_and_its_evidence_stay_together(self):
        """The injected prompt still asks the reach question above the output."""
        source = inspect.getsource(POVAgent._run_agent_loop)
        assert "Did the input reach the vulnerable function?" in source
        # The quoted evidence must be interpolated right after the question;
        # if it is dropped the question becomes unanswerable again.
        question_at = source.index("Did the input reach the vulnerable function?")
        assert f"{PRODUCED_KEY}[:300]" in source[question_at : question_at + 400], (
            "the reach question no longer quotes the fuzzer output beneath it"
        )
