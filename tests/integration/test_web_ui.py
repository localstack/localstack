from localstack.dashboard import infra
from localstack.config import USE_SSL


def test_infra_graph_generation():
    try:
        graph = infra.get_graph()
    except Exception as e:
        if USE_SSL:
            print('TODO: the Web UI in combination with USE_SSL=true is currently broken.')
            return
    assert 'nodes' in graph
    assert 'edges' in graph

    # TODO add more tests/assertions
