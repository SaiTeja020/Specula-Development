"""
Specula Log Analysis Agent package.

Consumes normalized OCSF events (ProcessActivity class_uid=1007,
FileActivity class_uid=1001) from Kafka, runs deterministic rule-based
and statistical anomaly detection, and publishes grounded findings back
to Kafka via the ReAct LLM orchestrator.

PR Note [CONFLICT — FLAG]:
    Rebuff cross-document conflict (Task 0, item 4):
    Master doc §6.2 states Rebuff runs as a general service; internal
    agent-level docs treat it as text-field-scoped only. This package
    treats Rebuff as process-text-field-scoped only (i.e., NOT every
    field arriving here has been Rebuff-scanned). A Master-doc §14
    addendum is required to formally resolve this. Do not silently
    expand Rebuff scope in this package without that sign-off.

PR Note [INTERPRETATION — FLAG]:
    NetworkActivityEvent / AuthenticationEvent class-scope:
    The resolved-decisions memo (item #3) lists these as relevant OCSF
    fields for Log Analysis, but Master doc §3.1 assigns Network and
    Auth logs to separate agents. This package's CONSUMED_CLASS_UIDS
    stays {1007, 1001}. Network/Auth events may only appear as
    read-only DFKG context (via query_dfkg), never as this agent's
    own Kafka consumption topic. Needs confirmation.
"""
