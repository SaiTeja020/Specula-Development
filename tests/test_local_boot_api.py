"""The local boot operation may replace only this Compose stack's containers."""

import asyncio
from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from scripts import local_boot_api


def result(args, code=0, stdout=""):
    return CompletedProcess(args, code, stdout=stdout, stderr="failure" if code else "")


def test_recreate_preserves_volumes_and_uses_local_images():
    commands = []

    def compose(*args, **kwargs):
        commands.append(args)
        if args == ("config", "--images"):
            return result(args, stdout="redis:7.2-alpine\n")
        return result(args)

    with patch.object(local_boot_api, "_run", side_effect=compose), patch.object(
            local_boot_api.subprocess, "run", return_value=result(["docker", "image", "inspect"])) as inspect:
        local_boot_api._recreate()

    assert commands == [("config", "-q"), ("config", "--images"), ("down",),
                        ("up", "-d", "--no-build", "--pull", "never")]
    assert all(call.args[0][:3] == ["docker", "image", "inspect"] for call in inspect.call_args_list)
    assert inspect.call_count == 2


def test_failed_image_preflight_keeps_running_stack():
    commands = []

    def compose(*args, **kwargs):
        commands.append(args)
        return result(args, stdout="redis:7.2-alpine\n" if args == ("config", "--images") else "")

    with patch.object(local_boot_api, "_run", side_effect=compose), patch.object(
            local_boot_api.subprocess, "run", return_value=result(["docker", "image", "inspect"], code=1)):
        with pytest.raises(RuntimeError, match="Local image"):
            local_boot_api._recreate()

    assert commands == [("config", "-q"), ("config", "--images")]


def test_boot_requires_local_dashboard_request():
    request = SimpleNamespace(client=SimpleNamespace(host="192.0.2.10"),
                              headers={"origin": "http://localhost:5173", "x-specula-local-boot": "1"})
    with pytest.raises(HTTPException) as error:
        local_boot_api._local_dashboard(request)
    assert error.value.status_code == 403

    request.client.host = "127.0.0.1"
    request.headers["origin"] = "https://other.example"
    with pytest.raises(HTTPException) as error:
        local_boot_api._local_dashboard(request)
    assert error.value.status_code == 403

    request.headers["origin"] = "http://localhost:5173"
    request.headers.pop("x-specula-local-boot")
    with pytest.raises(HTTPException) as error:
        local_boot_api._local_dashboard(request)
    assert error.value.status_code == 403

    request.headers["x-specula-local-boot"] = "1"
    local_boot_api._local_dashboard(request)


def test_readiness_uses_host_token_without_exposing_it(tmp_path, monkeypatch):
    token = "specula_local_example_only"
    path = tmp_path / "verification_token"
    path.write_text(token, encoding="utf-8")
    monkeypatch.setattr(local_boot_api, "TOKEN_PATH", path)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"origin": "http://localhost:5173", "x-specula-local-boot": "1"})
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "success", "services": {"redis": {"status": "ready"}}}
    session = MagicMock()
    session.__enter__.return_value.get.return_value = response

    with patch.object(local_boot_api.requests, "Session", return_value=session):
        result = asyncio.run(local_boot_api.local_readiness(request))

    assert result == response.json.return_value
    assert token not in str(result)
    assert session.__enter__.return_value.get.call_args.kwargs["headers"] == {
        "Authorization": f"Bearer {token}"}


def test_local_ingestion_window_is_validated():
    body = local_boot_api.LocalInvestigationRequest(
        start_date="2026-10-11T09:00", end_date="2026-10-11T10:00",
        max_events=25, exclude_ports=[80, 443])
    assert local_boot_api._local_window(body) == (
        "2026-10-11T09:00:00", "2026-10-11T10:00:00")
    body.end_date = "2026-10-11T08:00"
    with pytest.raises(HTTPException) as error:
        local_boot_api._local_window(body)
    assert error.value.status_code == 422


def test_current_job_can_be_recovered_after_page_refresh(monkeypatch):
    paths = [route.path for route in local_boot_api.app.routes]
    assert paths.index("/api/local/investigations/current") < paths.index(
        "/api/local/investigations/{job_id}")
    job = {"id": "job-1", "case_id": "LOCAL-1", "phase": "ingesting"}
    monkeypatch.setattr(local_boot_api, "_case_job", job)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"origin": "http://localhost:5173", "x-specula-local-boot": "1"})
    assert asyncio.run(local_boot_api.current_local_investigation(request)) == job
    assert asyncio.run(local_boot_api.local_investigation_status("job-1", request)) == job


def test_local_graph_view_uses_host_credential(tmp_path, monkeypatch):
    path = tmp_path / "verification_token"
    path.write_text("local-only-example", encoding="utf-8")
    monkeypatch.setattr(local_boot_api, "TOKEN_PATH", path)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"origin": "http://localhost:5173", "x-specula-local-boot": "1"})
    response = MagicMock(status_code=200)
    response.json.return_value = {"status": "success", "nodes": [{"id": "1"}], "edges": []}
    session = MagicMock()
    session.__enter__.return_value.get.return_value = response
    with patch.object(local_boot_api.requests, "Session", return_value=session):
        result = asyncio.run(local_boot_api.local_store_data("neo4j", request))
    assert result == response.json.return_value
    assert session.__enter__.return_value.get.call_args.kwargs["headers"] == {
        "Authorization": "Bearer local-only-example"}


def test_local_store_view_is_restricted_to_dashboard_origin():
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"),
                              headers={"origin": "https://other.example", "x-specula-local-boot": "1"})
    with pytest.raises(HTTPException) as error:
        asyncio.run(local_boot_api.local_store_data("quickwit", request))
    assert error.value.status_code == 403
