from localstack.utils.analytics.usage import UsageSetCounter


def test_set_counter():
    my_feature_counter = UsageSetCounter("lambda:runtime")
    my_feature_counter.record("python3.7")
    my_feature_counter.record("nodejs16.x")
    my_feature_counter.record("nodejs16.x")
    assert my_feature_counter.aggregate() == {"python3.7": 1, "nodejs16.x": 2}
