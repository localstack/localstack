import io
import random
from dataclasses import dataclass
from pathlib import Path

import yaml

from localstack.services.cloudformation.autogen.visitors.base import random_short_string

NodeId = str
EdgeId = str


def gen_id() -> NodeId | EdgeId:
    return random_short_string()


@dataclass
class Node:
    id: NodeId


@dataclass
class Edge:
    id: EdgeId

    from_: NodeId
    to: NodeId


class CyclicGraphError(RuntimeError):
    pass


class Graph:
    nodes: dict[NodeId, Node]
    edges: dict[EdgeId, Edge]

    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def add_node(self) -> NodeId:
        node_id = gen_id()
        node = Node(id=node_id)
        self.nodes[node_id] = node
        return node_id

    def add_edge(self, from_: NodeId, to: NodeId) -> EdgeId:
        edge_id = gen_id()
        edge = Edge(id=edge_id, from_=from_, to=to)

        if self.contains_cycle(edge):
            raise CyclicGraphError("Graph contains cycle")

        self.edges[edge_id] = edge
        return edge_id

    def random_node(self, excluding: set[NodeId] | None = None) -> NodeId:
        # TODO: assume we have added all nodes
        excluding = excluding or set()
        valid_nodes = set(self.nodes.keys()) - excluding
        if not valid_nodes:
            raise RuntimeError("no nodes available to target")

        return random.choice(list(valid_nodes))

    def contains_cycle(self, new_edge: Edge) -> bool:
        for edge in self.edges.values():
            if new_edge.to == edge.from_ and new_edge.from_ == edge.to:
                return True

        return False

    def __str__(self) -> str:
        return self.to_dot()

    def to_dot(self) -> str:
        out = io.StringIO()

        def render(text: str | None = None):
            if text is None:
                return print(file=out)
            else:
                return print(text, file=out)

        render("digraph G {")

        for node in self.nodes.values():
            render(f"\t{node.id};")

        render()

        for edge in self.edges.values():
            render(f"\t{edge.from_} -> {edge.to};")

        render("}")

        return out.getvalue()

    def render_template(self) -> str:
        template = {"Resources": {}}

        for node in self.nodes.values():
            resource_definition = {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": node.id,
                },
            }
            for edge in self.edges.values():
                if edge.from_ == node.id:
                    resource_definition["Properties"]["Description"] = {"Ref": edge.to}
            template["Resources"][node.id] = resource_definition

        return yaml.safe_dump(template)


def generate_templates(output_path: Path, count: int = 10):
    # TODO: clear_files(output_path)
    g = generate_new_graph()
    for i in range(count):
        with (output_path / f"template_{i}.yml").open("w") as outfile:
            print(g.render_template(), file=outfile)
        g = permute_existing_graph(g)


def generate_new_graph() -> Graph:
    g = Graph()
    n_nodes = random.randint(5, 20)
    node_ids = []
    for _ in range(n_nodes):
        node_ids.append(g.add_node())

    n_edges = random.randint(2, n_nodes - 1)
    for _ in range(n_edges):
        success = False
        for _ in range(10):
            from_ = g.random_node()
            to = g.random_node(excluding={from_})
            try:
                g.add_edge(from_, to)
                success = True
                break
            except CyclicGraphError:
                continue

        if not success:
            raise RuntimeError("Could not find non-acyclic graph combination")

    return g


def permute_existing_graph(g: Graph) -> Graph:
    return g
