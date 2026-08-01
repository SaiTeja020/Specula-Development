"""
Component 7 — Knowledge Graph Ingestion
Ref: specula_ingestion_final_plan.md §8

Covers: schema_constraints.cypher, apoc_triggers.cypher, cypher_builder.py,
dfkg_cypher.py (check_supernode).

Carries two of the highest-severity regression tests in the suite:
1. apoc.node.degree must always be called TYPED and DIRECTIONAL.
2. The historical case-tagging backfill must NEVER be built via string
   concatenation of label names, even from a hardcoded list.
"""
import inspect
import pathlib
import re

import pytest


class TestTypedSupernodeCheck:

    def test_supernode_flagged_for_dense_relationship_type(self, neo4j_graph):
        from src.mcp.dfkg_cypher import check_supernode

        for i in range(10001):
            neo4j_graph.merge_edge("HOST-042", "COMMUNICATED_WITH", f"IP-{i}")

        assert check_supernode(neo4j_graph, "HOST-042", rel_spec="COMMUNICATED_WITH>") is True

    @pytest.mark.regression
    def test_node_not_flagged_for_unrelated_sparse_relationship_type(self, neo4j_graph):
        """
        THE regression test for the untyped-degree bug. A node dense in
        one relationship type must NOT be flagged as a supernode for a
        traversal over a DIFFERENT, sparse relationship type. An untyped
        `apoc.node.degree(n)` call (summing all relationship types in
        both directions) would incorrectly flag this node here.
        """
        from src.mcp.dfkg_cypher import check_supernode

        for i in range(10001):
            neo4j_graph.merge_edge("HOST-042", "COMMUNICATED_WITH", f"IP-{i}")
        for i in range(10):
            neo4j_graph.merge_edge("HOST-042", "EXECUTED_BY", f"PROC-{i}")

        assert check_supernode(neo4j_graph, "HOST-042", rel_spec="EXECUTED_BY>") is False

    @pytest.mark.regression
    def test_check_supernode_requires_explicit_rel_spec_argument(self):
        """
        Regression guard: rel_spec must be a required argument with no
        default. A default (or an optional untyped fallback) reintroduces
        the exact bug this fix was meant to close, at every call site that
        forgets to pass it explicitly.
        """
        from src.mcp.dfkg_cypher import check_supernode

        sig = inspect.signature(check_supernode)
        rel_spec_param = sig.parameters.get("rel_spec")
        assert rel_spec_param is not None, "check_supernode must accept rel_spec"
        assert rel_spec_param.default is inspect.Parameter.empty, (
            "rel_spec must have NO default -- every call site must specify "
            "the traversal-relevant relationship type explicitly."
        )

    def test_below_threshold_degree_not_flagged(self, neo4j_graph):
        from src.mcp.dfkg_cypher import check_supernode
        for i in range(50):
            neo4j_graph.merge_edge("HOST-001", "COMMUNICATED_WITH", f"IP-{i}")
        assert check_supernode(neo4j_graph, "HOST-001", rel_spec="COMMUNICATED_WITH>") is False


class TestNoPatternComprehensionDegreeChecks:

    @pytest.mark.regression
    def test_no_size_pattern_comprehension_anywhere_in_graph_module(self):
        """
        Regression guard: `size((n)--())`-style pattern comprehension
        forces Neo4j to expand and count every relationship before
        comparing -- for a genuine supernode, this operation IS the
        traversal explosion the check exists to prevent. Static-scan the
        actual Cypher source for this anti-pattern.
        """
        graph_src_dir = pathlib.Path("src/graph")
        mcp_src_dir = pathlib.Path("src/mcp")
        offending = []
        for d in (graph_src_dir, mcp_src_dir):
            if not d.exists():
                continue
            for f in d.rglob("*"):
                if f.suffix in (".py", ".cypher"):
                    text = f.read_text(errors="ignore")
                    if re.search(r"size\(\s*\(\s*\w*\s*\)\s*--\s*\(\s*\)\s*\)", text):
                        offending.append(str(f))
        assert not offending, f"Pattern-comprehension degree check found in: {offending}"


class TestParameterizedCypherOnly:

    @pytest.mark.regression
    def test_historical_backfill_uses_parameter_bound_labels_not_string_concat(self):
        """
        THE regression test for the Cypher-injection-precedent bug. The
        historical case-tagging backfill must filter labels via a bound
        parameter (e.g. `labels(n)[0] IN $labels`), never by concatenating
        label names into the Cypher text -- even from a fixed, hardcoded
        list. Verified both behaviorally and by source inspection, since
        the risk is about establishing an unsafe PATTERN, not just this
        one call site.
        """
        from src.graph.cypher_builder import build_case_backfill_query

        query, params = build_case_backfill_query(
            labels=["Host", "Process", "File", "NetworkEndpoint"],
            host_id="HOST-042", start_time="2026-07-01T00:00:00Z",
            case_open_time="2026-07-28T00:00:00Z", case_id="CASE-1",
        )
        # the query text must not contain any label name baked in literally
        for label in ("Host", "Process", "File", "NetworkEndpoint"):
            assert f":{label}" not in query, (
                f"Label '{label}' appears to be string-concatenated directly "
                f"into the Cypher text rather than passed as a bound parameter."
            )
        assert "$labels" in query or "labels" in params

    @pytest.mark.regression
    def test_no_plus_concatenation_building_cypher_strings_in_graph_module(self):
        """
        Broader static-analysis guard: no Cypher string in the codebase
        should be built via `+` concatenation with any variable component.
        This is a source-level check, not just a behavioral one, because
        the risk (an injection vector the moment the label list is ever
        made configurable) doesn't manifest until someone extends the code
        later -- a passing behavioral test today wouldn't catch that.
        """
        graph_src_dir = pathlib.Path("src/graph")
        if not graph_src_dir.exists():
            pytest.skip("src/graph not present in this checkout")
        offending = []
        for f in graph_src_dir.rglob("*.py"):
            text = f.read_text(errors="ignore")
            # heuristic: a string literal containing "MATCH"/"CREATE"/"MERGE"
            # immediately followed by a `+` concatenation
            if re.search(r'["\'].*(MATCH|MERGE|CREATE).*["\']\s*\+', text):
                offending.append(str(f))
        assert not offending, f"String-concatenated Cypher found in: {offending}"

    def test_cypher_builder_produces_merge_with_parameter_map(self):
        from src.graph.cypher_builder import build_node_merge
        query, params = build_node_merge(
            label="Host", uid="uid-1", props={"case_id": "c1", "trace_id": "t1"},
        )
        assert "MERGE" in query
        assert "$uid" in query
        assert params["uid"] == "uid-1"


class TestCompositeIndexes:

    @pytest.mark.regression
    def test_all_four_backfill_labels_have_composite_indexes_defined(self):
        """
        Regression guard: an earlier draft omitted the NetworkEndpoint
        index while adding Host/Process/File, forcing a full label scan
        on every case-open backfill for what is plausibly the
        highest-volume label in the graph.
        """
        cypher_file = pathlib.Path("src/graph/schema_constraints.cypher")
        if not cypher_file.exists():
            pytest.skip("schema_constraints.cypher not present in this checkout")
        text = cypher_file.read_text()
        for label in ("Host", "Process", "File", "NetworkEndpoint"):
            pattern = rf"CREATE INDEX .*FOR \(n:{label}\) ON \(n\.canonical_host_id, n\.timestamp\)"
            assert re.search(pattern, text), f"Missing composite (canonical_host_id, timestamp) index for :{label}"


class TestDebouncedAPOCTriggers:

    def test_trigger_config_specifies_afterasync_phase_and_debounce(self):
        cypher_file = pathlib.Path("src/graph/apoc_triggers.cypher")
        if not cypher_file.exists():
            pytest.skip("apoc_triggers.cypher not present in this checkout")
        text = cypher_file.read_text()
        assert "afterAsync" in text
        assert re.search(r"debounceMs\s*[:=]\s*5000", text)

    @pytest.mark.regression
    def test_no_dead_end_detection_logic_in_apoc_trigger_file(self):
        """
        Regression guard: dead-end detection (absence of expected activity
        within a timeout) is a Supervisor-side inactivity heuristic, NOT
        something a database write-trigger can observe. If "dead_end"
        or "deadend" language appears in this file, it's a scope
        violation that needs to be removed.
        """
        cypher_file = pathlib.Path("src/graph/apoc_triggers.cypher")
        if not cypher_file.exists():
            pytest.skip("apoc_triggers.cypher not present in this checkout")
        text = cypher_file.read_text().lower()
        assert "dead_end" not in text and "deadend" not in text and "dead-end" not in text


class TestDeterministicUIDMerge:

    def test_two_agents_writing_same_entity_merge_not_duplicate(self, neo4j_graph):
        from src.graph.cypher_builder import build_node_merge

        query1, params1 = build_node_merge(label="Host", uid="uid-1", props={"seen_by": "agent-a"})
        query2, params2 = build_node_merge(label="Host", uid="uid-1", props={"seen_by": "agent-b"})

        neo4j_graph.merge_node(params1["uid"], ["Host"], params1["props"])
        neo4j_graph.merge_node(params2["uid"], ["Host"], params2["props"])

        assert len(neo4j_graph.nodes) == 1
