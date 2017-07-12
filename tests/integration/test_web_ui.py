from localstack.dashboard import infra
from localstack.config import USE_SSL


def test_infra_graph_generation():
    graph = infra.get_graph()
    assert 'nodes' in graph
    assert 'edges' in graph

    # TODO add more tests/assertions
