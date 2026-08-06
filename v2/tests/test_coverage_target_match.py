# SPDX-License-Identifier: Apache-2.0
"""
Tests for matching a target function against LCOV's executed-function list.

check_pov_reaches_target is handed a plain function name -- the one a caller
reads out of the source or a sanitizer stack trace. LCOV reports the symbol
names the binary carries, which for C++ are mangled. Comparing the two with ==
answers "not reached" for every C++ target and reports no error while doing it.

The mangled symbols below are the real ones emitted by the coverage build of
OSS-Fuzz project `muparser` (ARVO 25402, heap-buffer-overflow READ 8), whose
crash trace names the plain `ParseCmdCodeBulk`.

Needs no LLM, no MongoDB and no Docker.

Run with: pytest tests/test_coverage_target_match.py -v
"""

from fuzzingbrain.tools.coverage import function_was_executed

# Executed symbols from muparser's coverage build, verbatim.
MUPARSER_EXECUTED = [
    "_ZNK2mu10ParserBase16ParseCmdCodeBulkEii",
    "_ZNK2mu10ParserBase11ParseStringEv",
    "_ZNK2mu14ParserByteCode7GetBaseEv",
    "_ZN2mu10ParserBase9DefineFunIPFddEEEvRKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEET_b",
    "LLVMFuzzerTestOneInput",
]

# A C project's list: plain names, no mangling.
C_EXECUTED = [
    "LLVMFuzzerTestOneInput",
    "avro_generic_value_new",
    "avro_raw_array_ensure_size",
]


class TestPlainNames:
    """C targets keep working exactly as before."""

    def test_plain_name_present(self):
        assert function_was_executed("avro_raw_array_ensure_size", C_EXECUTED)

    def test_plain_name_absent(self):
        assert not function_was_executed("avro_schema_decref", C_EXECUTED)

    def test_empty_list(self):
        assert not function_was_executed("anything", [])


class TestMangledNames:
    """A C++ target named in plain form must match its mangled symbol."""

    def test_target_from_crash_trace_is_found(self):
        """The regression: this returned False for a POV that did reach."""
        assert function_was_executed("ParseCmdCodeBulk", MUPARSER_EXECUTED)

    def test_other_mangled_target_is_found(self):
        assert function_was_executed("ParseString", MUPARSER_EXECUTED)

    def test_absent_cxx_function_is_not_found(self):
        assert not function_was_executed("EvalDeep", MUPARSER_EXECUTED)

    def test_unmangled_entry_in_a_cxx_list_still_matches(self):
        """extern "C" harness entry points are not mangled."""
        assert function_was_executed("LLVMFuzzerTestOneInput", MUPARSER_EXECUTED)


class TestNoFalsePositives:
    """The length prefix is what makes the match precise; keep it that way."""

    def test_prefix_of_a_longer_name_does_not_match(self):
        """`Parse` must not match `11ParseStringEv` via a bare substring."""
        assert not function_was_executed("Parse", MUPARSER_EXECUTED)

    def test_length_digits_are_not_borrowed_from_a_longer_number(self):
        """`Foo` (len 3) must not match the trailing `3Foo` inside `13FooBarBazQuux`."""
        assert not function_was_executed("Foo", ["_ZN2ns13FooBarBazQuuxEv"])

    def test_suffix_of_a_longer_name_does_not_match(self):
        assert not function_was_executed("CodeBulk", MUPARSER_EXECUTED)

    def test_plain_name_is_not_matched_inside_an_unmangled_symbol(self):
        """Only symbols that look mangled get the length-prefix treatment."""
        assert not function_was_executed("Fuzzer", ["LLVMFuzzerTestOneInput"])
