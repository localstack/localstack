import os
import sys

from localstack.cli.profiles import set_and_remove_profile_from_sys_argv


def profile_test(monkeypatch, input_args, expected_profile, expected_argv):
    monkeypatch.setattr(sys, "argv", input_args)
    monkeypatch.setenv("CONFIG_PROFILE", "")
    set_and_remove_profile_from_sys_argv()
    assert os.environ["CONFIG_PROFILE"] == expected_profile
    assert sys.argv == expected_argv


def test_profiles_equals_notation(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["--profile=non-existing-test-profile"],
        expected_profile="non-existing-test-profile",
        expected_argv=[],
    )


def test_profiles_separate_args_notation(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["--profile", "non-existing-test-profile"],
        expected_profile="non-existing-test-profile",
        expected_argv=[],
    )


def test_p_equals_notation(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["-p=non-existing-test-profile"],
        expected_profile="non-existing-test-profile",
        expected_argv=["-p=non-existing-test-profile"],
    )


def test_p_separate_args_notation(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["-p", "non-existing-test-profile"],
        expected_profile="non-existing-test-profile",
        expected_argv=["-p", "non-existing-test-profile"],
    )


def test_profiles_args_before_and_after(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["cli", "-D", "--profile=non-existing-test-profile", "start"],
        expected_profile="non-existing-test-profile",
        expected_argv=["cli", "-D", "start"],
    )


def test_profiles_args_before_and_after_separate(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["cli", "-D", "--profile", "non-existing-test-profile", "start"],
        expected_profile="non-existing-test-profile",
        expected_argv=["cli", "-D", "start"],
    )


def test_p_args_before_and_after_separate(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["cli", "-D", "-p", "non-existing-test-profile", "start"],
        expected_profile="non-existing-test-profile",
        expected_argv=["cli", "-D", "-p", "non-existing-test-profile", "start"],
    )


def test_profiles_args_multiple(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=[
            "cli",
            "--profile",
            "non-existing-test-profile",
            "start",
            "--profile",
            "another-profile",
        ],
        expected_profile="another-profile",
        expected_argv=["cli", "start"],
    )


def test_p_args_multiple(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=[
            "cli",
            "-p",
            "non-existing-test-profile",
            "start",
            "-p",
            "another-profile",
        ],
        expected_profile="non-existing-test-profile",
        expected_argv=[
            "cli",
            "-p",
            "non-existing-test-profile",
            "start",
            "-p",
            "another-profile",
        ],
    )


def test_p_and_profile_args(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=[
            "cli",
            "-p",
            "non-existing-test-profile",
            "start",
            "--profile",
            "the_profile",
            "-p",
            "another-profile",
        ],
        expected_profile="the_profile",
        expected_argv=[
            "cli",
            "-p",
            "non-existing-test-profile",
            "start",
            "-p",
            "another-profile",
        ],
    )


def test_trailing_p_argument(monkeypatch):
    profile_test(
        monkeypatch,
        input_args=["cli", "start", "-p"],
        expected_profile="",
        expected_argv=["cli", "start", "-p"],
    )
