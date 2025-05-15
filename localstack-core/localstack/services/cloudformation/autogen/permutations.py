import enum
import io
import random
import subprocess as sp
from dataclasses import dataclass
from pathlib import Path

import yaml

from localstack.services.cloudformation.autogen.visitors.base import random_short_string

NodeId = str
EdgeId = str


def gen_id() -> NodeId | EdgeId:
    return random_short_string()


class Operation(enum.Enum):
    Add = enum.auto()
    Remove = enum.auto()
    Modify = enum.auto()


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

        return new_edge.to == new_edge.from_

    def apply_operation(self, op: Operation):
        print(f"Applying operation {op}")
        match op:
            case Operation.Add:
                node_id = self.add_node()
                if random.uniform(0.0, 1.0) < 0.5:
                    # add random edge
                    target = self.random_node()
                    self.add_edge(node_id, target)
            case Operation.Remove:
                if len(self.nodes) == 1:
                    raise RuntimeError("No nodes left to remove")

                chosen_node_id = random.choice(list(self.nodes.keys()))

                edge_ids_to_remove = []
                for edge in self.edges.values():
                    if edge.from_ == chosen_node_id or edge.to == chosen_node_id:
                        edge_ids_to_remove.append(edge.id)

                for edge_id in edge_ids_to_remove:
                    del self.edges[edge_id]

                # TODO: retarget edges rather than just removing them

            case Operation.Modify:
                # TODO: update node edges
                pass

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

    def render_png(self, output_path: Path):
        dot = self.to_dot()
        sp.run(
            ["dot", "-Tpng", "-o", str(output_path)],
            input=dot,
            text=True,
            capture_output=False,
            check=True,
        )


def generate_templates(output_path: Path, count: int = 10):
    # TODO: clear_files(output_path)
    g = generate_new_graph()
    for i in range(count):
        with (output_path / f"template_{i}.yml").open("w") as outfile:
            print(g.render_template(), file=outfile)
        g.render_png(output_path / f"template_{i}.png")
        g = permute_existing_graph(g, count)


def generate_new_graph() -> Graph:
    print("Generating new graph")
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


OPERATIONS = [
    Operation.Add,
    Operation.Remove,
    # Operation.Modify,
]


def permute_existing_graph(g: Graph, count: int) -> Graph:
    print("Permuting existing graph")
    ops = random.choices(OPERATIONS, k=random.randint(1, count))
    for op in ops:
        g.apply_operation(op)
    return g
