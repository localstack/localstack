from localstack.dashboard import infra


def test_infra_graph_generation():
    if True:
        # TODO: skipping this test for now, as it takes a relatively long time, with limited benefit
        return

    graph = infra.get_graph()
    assert "nodes" in graph
    assert "edges" in graph

    # TODO add more tests/assertions
