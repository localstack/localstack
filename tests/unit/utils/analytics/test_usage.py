from localstack.utils.analytics.usage import UsageMultiSetCounter


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
