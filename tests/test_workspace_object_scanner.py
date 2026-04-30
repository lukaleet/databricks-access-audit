"""Tests for WorkspaceObjectScanner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from databricks_group_audit.models import GrantSource, GroupMember, MemberType, WorkspaceInfo
from databricks_group_audit.workspace_object_scanner import (
    ALL_OBJECT_TYPES,
    WorkspaceObjectScanner,
    _OBJECT_CONFIGS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ws(name="test-ws", url="https://ws.azuredatabricks.net"):
    return WorkspaceInfo(
        workspace_id="ws-1",
        deployment_name="ws",
        workspace_name=name,
        workspace_url=url,
        cloud="AZURE",
        region="eastus",
    )


def _mock_scanner(workspace_api_side_effect=None):
    """Return (scanner, mock_api_client, mock_resolver)."""
    api = MagicMock()
    resolver = MagicMock()
    # get_group_membership_map: (id_to_name, id_to_ext, child_to_parents)
    resolver.get_group_membership_map.return_value = (
        {"g1": "data-engineers", "g2": "all-data"},
        {"g1": None, "g2": None},
        {"g1": {"g2"}},  # g1 (data-engineers) is child of g2 (all-data)
    )
    if workspace_api_side_effect is not None:
        api.workspace_api.side_effect = workspace_api_side_effect
    scanner = WorkspaceObjectScanner(api, resolver)
    return scanner, api, resolver


def _members(emails=("alice@example.com",), sp_names=("ETL-Bot",)):
    users = [
        MagicMock(spec=GroupMember, email=e, display_name=e, application_id=None,
                  member_type=MemberType.USER)
        for e in emails
    ]
    sps = [
        MagicMock(spec=GroupMember, email=None, display_name=n, application_id="app-1",
                  member_type=MemberType.SERVICE_PRINCIPAL)
        for n in sp_names
    ]
    return {"users": users, "service_principals": sps}


def _job_list_resp(jobs):
    return {"jobs": jobs}


def _acl_resp(entries):
    return {"access_control_list": entries}


def _acl_entry(field, value, perm_level):
    return {field: value, "all_permissions": [{"permission_level": perm_level}]}


# ---------------------------------------------------------------------------
# OBJECT_CONFIGS sanity
# ---------------------------------------------------------------------------

def test_all_object_types_in_configs():
    assert set(ALL_OBJECT_TYPES) == set(_OBJECT_CONFIGS.keys())
    assert len(ALL_OBJECT_TYPES) == 13


def test_object_configs_have_required_keys():
    required = {"list_endpoint", "list_key", "id_field", "object_type",
                "perm_prefix", "name_fn", "paginated"}
    for key, cfg in _OBJECT_CONFIGS.items():
        assert required <= set(cfg.keys()), f"Config '{key}' missing keys"


def test_job_name_fn():
    fn = _OBJECT_CONFIGS["jobs"]["name_fn"]
    assert fn({"settings": {"name": "my-job"}}) == "my-job"
    assert fn({}) == ""
    assert fn({"settings": {}}) == ""


def test_cluster_name_fn():
    fn = _OBJECT_CONFIGS["clusters"]["name_fn"]
    assert fn({"cluster_name": "shared"}) == "shared"
    assert fn({}) == ""


# ---------------------------------------------------------------------------
# _extract_acl_principal
# ---------------------------------------------------------------------------

def test_extract_user_principal():
    entry = {"user_name": "alice@corp.com", "all_permissions": []}
    p, f = WorkspaceObjectScanner._extract_acl_principal(entry)
    assert p == "alice@corp.com"
    assert f == "user_name"


def test_extract_group_principal():
    entry = {"group_name": "data-engineers", "all_permissions": []}
    p, f = WorkspaceObjectScanner._extract_acl_principal(entry)
    assert p == "data-engineers"
    assert f == "group_name"


def test_extract_sp_principal():
    entry = {"service_principal_name": "ETL-Bot", "all_permissions": []}
    p, f = WorkspaceObjectScanner._extract_acl_principal(entry)
    assert p == "ETL-Bot"
    assert f == "service_principal_name"


def test_extract_no_principal():
    p, f = WorkspaceObjectScanner._extract_acl_principal({})
    assert p == ""
    assert f == ""


# ---------------------------------------------------------------------------
# _best_perm_level
# ---------------------------------------------------------------------------

def test_best_perm_level_first_entry():
    perms = [{"permission_level": "CAN_MANAGE"}, {"permission_level": "CAN_VIEW"}]
    assert WorkspaceObjectScanner._best_perm_level(perms) == "CAN_MANAGE"


def test_best_perm_level_empty():
    assert WorkspaceObjectScanner._best_perm_level([]) == ""


# ---------------------------------------------------------------------------
# _get_upstream_groups
# ---------------------------------------------------------------------------

def test_get_upstream_groups_finds_ancestor():
    scanner, _, resolver = _mock_scanner()
    # data-engineers (g1) has parent all-data (g2)
    ups = scanner._get_upstream_groups("data-engineers")
    assert "all-data" in ups


def test_get_upstream_groups_unknown_returns_empty():
    scanner, _, _ = _mock_scanner()
    ups = scanner._get_upstream_groups("nonexistent-group")
    assert ups == {}


# ---------------------------------------------------------------------------
# _scan_one_type — group audit
# ---------------------------------------------------------------------------

def _setup_single_job_scan(scanner, api, job_name="prod-etl", acl_entries=None):
    """Wire api.workspace_api to return one job and a given ACL."""
    if acl_entries is None:
        acl_entries = [_acl_entry("group_name", "data-engineers", "CAN_MANAGE")]

    def _side_effect(ws_url, method, endpoint, **kwargs):
        if endpoint == "/api/2.1/jobs/list":
            return {"jobs": [{"job_id": "1", "settings": {"name": job_name}}]}
        if endpoint == "/api/2.0/permissions/jobs/1":
            return _acl_resp(acl_entries)
        return {}

    api.workspace_api.side_effect = _side_effect


def test_scan_one_type_direct_group_grant():
    scanner, api, _ = _mock_scanner()
    _setup_single_job_scan(scanner, api)

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        set(), set(), set(), set(),
    )

    assert len(grants) == 1
    g = grants[0]
    assert g.object_type == "JOB"
    assert g.object_name == "prod-etl"
    assert g.principal == "data-engineers"
    assert g.principal_type == "GROUP"
    assert g.grant_source == GrantSource.DIRECT
    assert g.permission_level == "CAN_MANAGE"


def test_scan_one_type_upstream_group_grant():
    scanner, api, _ = _mock_scanner()
    _setup_single_job_scan(scanner, api, acl_entries=[
        _acl_entry("group_name", "all-data", "CAN_VIEW"),
    ])

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {"all-data": "g2"},
        set(), set(), set(), set(),
    )

    assert len(grants) == 1
    g = grants[0]
    assert g.grant_source == GrantSource.UPSTREAM
    assert g.inherited_from == "all-data"
    assert g.permission_level == "CAN_VIEW"


def test_scan_one_type_member_direct_user_grant():
    scanner, api, _ = _mock_scanner()
    _setup_single_job_scan(scanner, api, acl_entries=[
        _acl_entry("user_name", "alice@example.com", "CAN_RUN"),
    ])

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        {"alice@example.com"}, set(), set(), set(),
    )

    assert len(grants) == 1
    g = grants[0]
    assert g.grant_source == GrantSource.MEMBER_DIRECT
    assert g.principal_type == "USER"
    assert g.permission_level == "CAN_RUN"
    assert g.member_of_target is True


def test_scan_one_type_member_direct_sp_grant():
    scanner, api, _ = _mock_scanner()
    _setup_single_job_scan(scanner, api, acl_entries=[
        _acl_entry("service_principal_name", "ETL-Bot", "CAN_MANAGE_RUN"),
    ])

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        set(), set(), {"ETL-Bot"}, set(),
    )

    assert len(grants) == 1
    g = grants[0]
    assert g.grant_source == GrantSource.MEMBER_DIRECT
    assert g.principal_type == "SERVICE_PRINCIPAL"


def test_scan_one_type_irrelevant_principal_skipped():
    scanner, api, _ = _mock_scanner()
    _setup_single_job_scan(scanner, api, acl_entries=[
        _acl_entry("user_name", "unrelated@corp.com", "CAN_VIEW"),
    ])

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        set(), set(), set(), set(),
    )
    assert grants == []


def test_scan_one_type_missing_perm_level_skipped():
    scanner, api, _ = _mock_scanner()
    api.workspace_api.side_effect = lambda url, method, ep, **kw: (
        {"jobs": [{"job_id": "1", "settings": {"name": "j"}}]}
        if "jobs/list" in ep
        else {"access_control_list": [{"group_name": "data-engineers", "all_permissions": []}]}
    )

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        set(), set(), set(), set(),
    )
    assert grants == []


# ---------------------------------------------------------------------------
# _list_objects — pagination
# ---------------------------------------------------------------------------

def test_list_objects_pagination():
    scanner, api, _ = _mock_scanner()
    calls = []

    def _side_effect(url, method, endpoint, **kwargs):
        params = kwargs.get("params", {})
        calls.append(params)
        if not params:  # first call — no page token yet
            return {"jobs": [{"job_id": "1"}], "next_page_token": "tok1"}
        return {"jobs": [{"job_id": "2"}]}

    api.workspace_api.side_effect = _side_effect

    items = scanner._list_objects("https://ws", _OBJECT_CONFIGS["jobs"])
    assert len(items) == 2
    assert len(calls) == 2
    assert calls[1].get("page_token") == "tok1"


def test_list_objects_no_pagination():
    scanner, api, _ = _mock_scanner()
    api.workspace_api.return_value = {"clusters": [{"cluster_id": "c1"}, {"cluster_id": "c2"}]}
    items = scanner._list_objects("https://ws", _OBJECT_CONFIGS["clusters"])
    assert len(items) == 2
    assert api.workspace_api.call_count == 1


def test_list_objects_api_error_returns_empty():
    scanner, api, _ = _mock_scanner()
    api.workspace_api.side_effect = Exception("network error")
    items = scanner._list_objects("https://ws", _OBJECT_CONFIGS["jobs"])
    assert items == []


# ---------------------------------------------------------------------------
# ACL error — single object skipped, others returned
# ---------------------------------------------------------------------------

def test_acl_error_skips_object():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "1", "settings": {"name": "job1"}},
                              {"job_id": "2", "settings": {"name": "job2"}}]}
        if "permissions/jobs/1" in endpoint:
            raise Exception("forbidden")
        if "permissions/jobs/2" in endpoint:
            return _acl_resp([_acl_entry("group_name", "data-engineers", "CAN_RUN")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner._scan_one_type(
        _ws(), _OBJECT_CONFIGS["jobs"],
        "data-engineers", {},
        set(), set(), set(), set(),
    )
    assert len(grants) == 1
    assert grants[0].object_name == "job2"


# ---------------------------------------------------------------------------
# object_types filter
# ---------------------------------------------------------------------------

def test_object_type_filter_jobs_only():
    scanner, api, _ = _mock_scanner()
    api.workspace_api.return_value = {"jobs": [], "clusters": []}

    scanner.scan_workspace(
        _ws(), "data-engineers", _members(),
        object_types=["jobs"], max_workers=1,
    )

    endpoints = [call.args[2] for call in api.workspace_api.call_args_list]
    assert any("jobs/list" in ep for ep in endpoints)
    assert not any("clusters/list" in ep for ep in endpoints)


# ---------------------------------------------------------------------------
# scan_all_workspaces — deduplication
# ---------------------------------------------------------------------------

def test_scan_all_workspaces_deduplicates_urls():
    scanner, api, _ = _mock_scanner()
    api.workspace_api.return_value = {"jobs": []}

    ws = _ws()
    scanner.scan_all_workspaces(
        [ws, ws],  # duplicate
        "data-engineers", MagicMock(), _members(),
        object_types=["jobs"], max_workers=2,
    )
    # Should only call workspace_api for one workspace
    list_calls = [c for c in api.workspace_api.call_args_list if "jobs/list" in c.args[2]]
    assert len(list_calls) == 1


# ---------------------------------------------------------------------------
# scan_workspace_for_principal
# ---------------------------------------------------------------------------

def test_scan_workspace_for_principal_via_group():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "10", "settings": {"name": "etl"}}]}
        if "permissions/jobs/10" in endpoint:
            return _acl_resp([_acl_entry("group_name", "data-engineers", "CAN_MANAGE")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com",
        group_names={"data-engineers"},
        object_types=["jobs"],
    )
    assert len(grants) == 1
    g = grants[0]
    assert g.grant_source == GrantSource.UPSTREAM
    assert g.inherited_from == "data-engineers"
    assert g.principal_type == "GROUP"
    assert g.permission_level == "CAN_MANAGE"


def test_scan_workspace_for_principal_direct_user():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "10", "settings": {"name": "etl"}}]}
        if "permissions/jobs/10" in endpoint:
            return _acl_resp([_acl_entry("user_name", "alice@example.com", "CAN_VIEW")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com",
        group_names=set(),
        object_types=["jobs"],
    )
    assert len(grants) == 1
    g = grants[0]
    assert g.grant_source == GrantSource.DIRECT
    assert g.principal_type == "USER"


def test_scan_workspace_for_principal_unrelated_skipped():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "1", "settings": {"name": "j"}}]}
        if "permissions/jobs/1" in endpoint:
            return _acl_resp([_acl_entry("user_name", "stranger@corp.com", "CAN_RUN")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com",
        group_names={"data-engineers"},
        object_types=["jobs"],
    )
    assert grants == []


def test_scan_workspace_for_principal_case_insensitive():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "1", "settings": {"name": "j"}}]}
        if "permissions/jobs/1" in endpoint:
            return _acl_resp([_acl_entry("user_name", "Alice@Example.COM", "CAN_VIEW")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com",
        group_names=set(),
        object_types=["jobs"],
    )
    assert len(grants) == 1


def test_scan_workspace_for_principal_with_alias():
    scanner, api, _ = _mock_scanner()

    def _side_effect(url, method, endpoint, **kwargs):
        if "jobs/list" in endpoint:
            return {"jobs": [{"job_id": "1", "settings": {"name": "j"}}]}
        if "permissions/jobs/1" in endpoint:
            return _acl_resp([_acl_entry("user_name", "alice_ext@tenant.onmicrosoft.com",
                                          "CAN_MANAGE")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com",
        group_names=set(),
        principal_aliases={"alice_ext@tenant.onmicrosoft.com"},
        object_types=["jobs"],
    )
    assert len(grants) == 1


# ---------------------------------------------------------------------------
# WorkspaceObjectGrant model
# ---------------------------------------------------------------------------

def test_workspace_object_grant_model():
    from databricks_group_audit.models import WorkspaceObjectGrant
    g = WorkspaceObjectGrant(
        object_type="JOB",
        object_id="123",
        object_name="prod-etl",
        workspace_name="prod",
        workspace_url="https://ws.azuredatabricks.net",
        principal="data-engineers",
        principal_type="GROUP",
        permission_level="CAN_MANAGE",
        grant_source=GrantSource.DIRECT,
    )
    assert g.inherited_from is None
    assert g.member_of_target is False


# ---------------------------------------------------------------------------
# PrincipalAuditResult has workspace_object_grants
# ---------------------------------------------------------------------------

def test_principal_audit_result_has_workspace_object_grants():
    from databricks_group_audit.models import PrincipalAuditResult
    r = PrincipalAuditResult(
        principal_type="USER",
        principal_id="u1",
        principal_name="alice@example.com",
    )
    assert r.workspace_object_grants == []


# ---------------------------------------------------------------------------
# New object types — config and scan smoke tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("type_key,list_ep,list_resp,id_field,obj_id,perm_ep", [
    (
        "sql_queries",
        "/api/2.0/sql/queries",
        {"results": [{"id": "q-1", "name": "daily report"}]},
        "id", "q-1",
        "/api/2.0/permissions/queries/q-1",
    ),
    (
        "sql_alerts",
        "/api/2.0/sql/alerts",
        {"results": [{"id": "a-1", "name": "high cpu alert"}]},
        "id", "a-1",
        "/api/2.0/permissions/alerts/a-1",
    ),
    (
        "lakeview_dashboards",
        "/api/2.0/lakeview/dashboards",
        {"dashboards": [{"dashboard_id": "dash-1", "display_name": "Sales"}]},
        "dashboard_id", "dash-1",
        "/api/2.0/permissions/dashboards/dash-1",
    ),
    (
        "genie_spaces",
        "/api/2.0/genie/spaces",
        {"spaces": [{"id": "gs-1", "title": "Finance Genie"}]},
        "id", "gs-1",
        "/api/2.0/permissions/genie/spaces/gs-1",
    ),
    (
        "mlflow_experiments",
        "/api/2.0/mlflow/experiments/list",
        {"experiments": [{"experiment_id": "exp-1", "name": "/Users/alice/run1"}]},
        "experiment_id", "exp-1",
        "/api/2.0/permissions/experiments/exp-1",
    ),
    (
        "registered_models",
        "/api/2.0/mlflow/registered-models/list",
        {"registered_models": [{"name": "churn-model"}]},
        "name", "churn-model",
        "/api/2.0/permissions/registered-models/churn-model",
    ),
    (
        "serving_endpoints",
        "/api/2.0/serving-endpoints",
        {"endpoints": [{"name": "churn-ep"}]},
        "name", "churn-ep",
        "/api/2.0/permissions/serving-endpoints/churn-ep",
    ),
    (
        "apps",
        "/api/2.0/apps",
        {"apps": [{"name": "my-app"}]},
        "name", "my-app",
        "/api/2.0/permissions/apps/my-app",
    ),
])
def test_new_type_scan_returns_grant(
    type_key, list_ep, list_resp, id_field, obj_id, perm_ep
):
    """Each new object type produces a grant when the target group is in the ACL."""
    scanner, api, _ = _mock_scanner()

    def _side_effect(ws_url, method, endpoint, **kwargs):
        if endpoint == list_ep:
            return list_resp
        if endpoint == perm_ep:
            return _acl_resp([_acl_entry("group_name", "data-engineers", "CAN_MANAGE")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace(
        _ws(), "data-engineers", _members(), object_types=[type_key]
    )
    assert len(grants) == 1
    assert grants[0].object_type == _OBJECT_CONFIGS[type_key]["object_type"]
    assert grants[0].object_id == str(obj_id)
    assert grants[0].permission_level == "CAN_MANAGE"
    assert grants[0].grant_source == GrantSource.DIRECT


def test_sql_alerts_bare_array_response():
    """Bare JSON array from old DBSQL alert endpoint is handled without crash."""
    scanner, api, _ = _mock_scanner()

    def _side_effect(ws_url, method, endpoint, **kwargs):
        if endpoint == "/api/2.0/sql/alerts":
            # Simulates a workspace that returns a bare array (old behaviour)
            return [{"id": "a-1", "name": "cpu alert"}]
        if endpoint == "/api/2.0/permissions/alerts/a-1":
            return _acl_resp([_acl_entry("group_name", "data-engineers", "CAN_VIEW")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace(
        _ws(), "data-engineers", _members(), object_types=["sql_alerts"]
    )
    assert len(grants) == 1
    assert grants[0].object_type == "SQL_ALERT"


def test_new_type_principal_scan(type_key="mlflow_experiments"):
    """New types work in principal-audit mode (scan_workspace_for_principal)."""
    scanner, api, _ = _mock_scanner()
    cfg = _OBJECT_CONFIGS[type_key]

    def _side_effect(ws_url, method, endpoint, **kwargs):
        if endpoint == cfg["list_endpoint"]:
            obj = {cfg["id_field"]: "exp-1", "name": "/Users/alice/run1"}
            return {cfg["list_key"]: [obj]}
        if "permissions" in endpoint:
            return _acl_resp([_acl_entry("user_name", "alice@example.com", "CAN_READ")])
        return {}

    api.workspace_api.side_effect = _side_effect

    grants = scanner.scan_workspace_for_principal(
        _ws(), "alice@example.com", group_names=set(), object_types=[type_key]
    )
    assert len(grants) == 1
    assert grants[0].grant_source == GrantSource.DIRECT
