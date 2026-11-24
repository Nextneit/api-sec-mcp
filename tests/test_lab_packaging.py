"""Tests derived from specs/005-target-lab.md (R2): the lab can only be exposed on loopback."""

from pathlib import Path

import pytest
import yaml

from target.run import resolve_bind

ROOT = Path(__file__).parents[1]


def test_r2_compose_publishes_only_loopback_8099():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    lab = compose["services"]["lab"]
    assert lab["ports"] == ["127.0.0.1:8099:8099"]
    assert len(compose["services"]) == 1


def test_r2_scope_lab_authorizes_only_the_lab():
    cfg = yaml.safe_load((ROOT / "scope.lab.yaml").read_text())
    assert cfg["allowed_ips"] == ["127.0.0.1"] and cfg["allowed_ports"] == [8099]
    assert cfg.get("allowed_hosts", []) == []


@pytest.mark.parametrize("bind", ["127.0.0.1", "::1", "localhost"])
def test_r2_loopback_binds_accepted(bind):
    assert resolve_bind({"LAB_BIND": bind}) == bind


def test_r2_default_is_loopback():
    assert resolve_bind({}) == "127.0.0.1"


@pytest.mark.parametrize("bind", ["0.0.0.0", "192.168.1.5", "::", "example.com"])
def test_r2_non_loopback_refused(bind):
    with pytest.raises(SystemExit):
        resolve_bind({"LAB_BIND": bind})


def test_r2_container_flag_allows_wildcard_bind():
    assert resolve_bind({"LAB_BIND": "0.0.0.0", "LAB_CONTAINER": "1"}) == "0.0.0.0"


def test_r2_dockerfile_sets_container_flag_and_no_other_ports():
    text = (ROOT / "target" / "Dockerfile").read_text()
    assert "LAB_CONTAINER=1" in text and text.count("EXPOSE") == 1 and "EXPOSE 8099" in text
