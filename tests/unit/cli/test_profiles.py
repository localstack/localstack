import os
import sys

from localstack.cli.profiles import set_profile_from_sys_argv


def test_profiles_equals_notation(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["--profile=non-existing-test-profile"])
    monkeypatch.setenv("CONFIG_PROFILE", "")
    set_profile_from_sys_argv()
    assert os.environ["CONFIG_PROFILE"] == "non-existing-test-profile"


def test_profiles_separate_args_notation(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["--profile", "non-existing-test-profile"])
    monkeypatch.setenv("CONFIG_PROFILE", "")
    set_profile_from_sys_argv()
    assert os.environ["CONFIG_PROFILE"] == "non-existing-test-profile"
