import time

from localstack.testing.pytest import markers


@markers.aws.validated
def test_duration_2_seconds(snapshot):
    test_duration = {"seconds": 2}
    time.sleep(test_duration["seconds"])
    snapshot.match("test_duration", test_duration)


@markers.aws.validated
def test_duration_1_second(snapshot):
    test_duration = {"seconds": 1}
    time.sleep(test_duration["seconds"])
    raise AssertionError()
    snapshot.match("test_duration_1_second", test_duration)
