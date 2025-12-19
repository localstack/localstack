import base64
import gzip
import json

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    Scope,
)
from localstack.services.cloudformation.engine.v2.change_set_model_serializer import (
    ChangeSetModelSerializer,
    Graph,
)


def test_serialization_builds_graph_from_template():
    before_template: dict[str, object] = {}
    after_template: dict[str, object] = {}
    change_set_model = ChangeSetModel(
        before_template=before_template,
        after_template=after_template,
        before_parameters=None,
        after_parameters=None,
    )
    update_model = change_set_model.get_update_model()

    serializer = ChangeSetModelSerializer()
    serialized = serializer.serialize(update_model)

    graph = Graph.deserialize(serialized)

    assert "" in graph.nodes
    assert "/Transform" in graph.nodes
    assert "/Mappings" in graph.nodes
    assert "/Parameters" in graph.nodes
    assert "/Conditions" in graph.nodes
    assert "/Resources" in graph.nodes
    assert "/Outputs" in graph.nodes

    assert ["", "/Transform"] in graph.edges
    assert ["", "/Mappings"] in graph.edges
    assert ["", "/Parameters"] in graph.edges
    assert ["", "/Conditions"] in graph.edges
    assert ["", "/Resources"] in graph.edges
    assert ["", "/Outputs"] in graph.edges

    assert graph.nodes[""].get("type") == "NodeTemplate"
    assert graph.nodes[""].get("change_type") == "Unchanged"
