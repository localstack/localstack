import base64
import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    NodeTemplate,
    UpdateModel,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)


@dataclass
class Graph:
    nodes: dict = field(default_factory=dict)
    edges: list[tuple[str, str]] = field(default_factory=list)

    def serialize(self) -> bytes:
        serialized = str(self)
        return base64.b64encode(gzip.compress(serialized.encode()))

    @classmethod
    def deserialize(cls, serialized: bytes) -> Self:
        decompressed = gzip.decompress(base64.b64decode(serialized))
        data = json.loads(decompressed.decode())
        return cls(nodes=data["nodes"], edges=data["edges"])

    def __str__(self) -> str:
        return json.dumps({"nodes": self.nodes, "edges": self.edges})


class ChangeSetModelSerializer(ChangeSetModelVisitor):
    graph: Graph
    _stack: list[str]

    def __init__(self):
        self.graph = Graph()
        self._stack = []

    def serialize(self, model: UpdateModel) -> bytes:
        self.visit(model.node_template)
        return self.graph.serialize()

    def visit(self, change_set_entity: ChangeSetEntity):
        node_id = change_set_entity.scope
        if node_id not in self.graph.nodes:
            # We use the class name and some other properties for the node data
            node_data = {
                "type": change_set_entity.__class__.__name__,
                "change_type": str(change_set_entity.change_type),
            }
            for k, v in change_set_entity.__dict__.items():
                if k in ("scope", "change_type"):
                    continue
                if isinstance(v, (ChangeSetEntity, list, dict)):
                    continue
                if is_nothing(v):
                    continue
                node_data[k] = v
            self.graph.nodes[node_id] = node_data

        if self._stack:
            parent_id = self._stack[-1]
            edge = (parent_id, node_id)
            if edge not in self.graph.edges:
                self.graph.edges.append(edge)

        self._stack.append(node_id)
        try:
            return super().visit(change_set_entity)
        finally:
            self._stack.pop()

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.transform)
        self.visit(node_template.mappings)
        self.visit(node_template.parameters)
        self.visit(node_template.conditions)
        self.visit(node_template.resources)
        self.visit(node_template.outputs)
