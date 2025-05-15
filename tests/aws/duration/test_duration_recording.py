import time

from localstack.testing.pytest import markers


@markers.aws.validated
def test_duration_2_seconds(snapshot):
    test_duration = {"seconds": 1.1}
    time.sleep(test_duration["seconds"])
    snapshot.match("test_duration", test_duration)
