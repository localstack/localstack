from localstack.utils.analytics.usage import UsageMultiSetCounter, UsageSetCounter


def test_set_counter():
    my_feature_counter = UsageSetCounter("lambda:runtime")
    my_feature_counter.record("python3.7")
    my_feature_counter.record("nodejs16.x")
    my_feature_counter.record("nodejs16.x")
    assert my_feature_counter.aggregate() == {"python3.7": 1, "nodejs16.x": 2}


def test_multi_set_counter():
    my_feature_counter = UsageMultiSetCounter("pipes:invocation")
    my_feature_counter.record("aws:sqs", "aws:lambda")
    my_feature_counter.record("aws:sqs", "aws:lambda")
    my_feature_counter.record("aws:sqs", "aws:stepfunctions")
    my_feature_counter.record("aws:kinesis", "aws:lambda")
    assert my_feature_counter.aggregate() == {
        "pipes:invocation:aws:sqs": {
            "aws:lambda": 2,
            "aws:stepfunctions": 1,
        },
        "pipes:invocation:aws:kinesis": {"aws:lambda": 1},
    }
    assert my_feature_counter._counters["pipes:invocation:aws:sqs"].state == {
        "aws:lambda": 2,
        "aws:stepfunctions": 1,
    }
    assert my_feature_counter._counters["pipes:invocation:aws:kinesis"].state == {"aws:lambda": 1}
