import logging
import math
import random
import re
from datetime import date, datetime
from functools import lru_cache, singledispatch
from typing import Dict, List, Optional, Set, Tuple, Union, cast

import botocore
import networkx
import rstr
from botocore.model import ListShape, MapShape, OperationModel, Shape, StringShape, StructureShape

from localstack.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localstack.aws.skeleton import DispatchTable, ServiceRequestDispatcher, Skeleton
from localstack.aws.spec import load_service
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

types = {
    "timestamp",
    "string",
    "blob",
    "map",
    "list",
    "long",
    "structure",
    "integer",
    "double",
    "float",
    "boolean",
}

Instance = Union[
    Dict[str, "Instance"],
    List["Instance"],
    str,
    bytes,
    map,
    list,
    float,
    int,
    bool,
    date,
]

# https://github.com/boto/botocore/issues/2623
StringShape.METADATA_ATTRS.append("pattern")

words = [
    # a few snazzy six-letter words
    "snazzy",
    "mohawk",
    "poncho",
    "proton",
    "foobar",
    "python",
    "umlaut",
    "except",
    "global",
    "latest",
]


class ShapeGraph(networkx.DiGraph):
    root: Union[ListShape, StructureShape, MapShape]
    cycle: List[Tuple[str, str]]
    cycle_shapes: List[str]


def populate_graph(graph: networkx.DiGraph, root: Shape):
    stack: List[Shape] = [root]
    visited: Set[str] = set()

    while stack:
        cur = stack.pop()
        if cur is None:
            continue

        if cur.name in visited:
            continue

        visited.add(cur.name)
        graph.add_node(cur.name, shape=cur)

        if isinstance(cur, ListShape):
            graph.add_edge(cur.name, cur.member.name)
            stack.append(cur.member)
        elif isinstance(cur, StructureShape):
            for member in cur.members.values():
                stack.append(member)
                graph.add_edge(cur.name, member.name)
        elif isinstance(cur, MapShape):
            stack.append(cur.key)
            stack.append(cur.value)
            graph.add_edge(cur.name, cur.key.name)
            graph.add_edge(cur.name, cur.value.name)

        else:  # leaf types (int, string, bool, ...)
            pass


def shape_graph(root: Shape) -> ShapeGraph:
    graph = networkx.DiGraph()
    graph.root = root
    populate_graph(graph, root)

    cycles = list()
    shapes = set()
    for node in graph.nodes:
        try:
            cycle = networkx.find_cycle(graph, source=node)
            for k, v in cycle:
                shapes.add(k)
                shapes.add(v)

            if cycle not in cycles:
                cycles.append(cycle)
        except networkx.NetworkXNoCycle:
            pass

    graph.cycles = cycles
    graph.cycle_shapes = list(shapes)

    return cast(ShapeGraph, graph)


def sanitize_pattern(pattern: str) -> str:
    pattern = pattern.replace("\\p{XDigit}", "[A-Fa-f0-9]")
    pattern = pattern.replace("\\p{P}", "[.,;]")
    pattern = pattern.replace("\\p{Punct}", "[.,;]")
    pattern = pattern.replace("\\p{N}", "[0-9]")
    pattern = pattern.replace("\\p{L}", "[A-Z]")
    pattern = pattern.replace("\\p{LD}", "[A-Z]")
    pattern = pattern.replace("\\p{Z}", "[ ]")
    pattern = pattern.replace("\\p{S}", "[+\\u-*]")
    pattern = pattern.replace("\\p{M}", "[`]")
    pattern = pattern.replace("\\p{IsLetter}", "[a-zA-Z]")
    pattern = pattern.replace("[:alnum:]", "[a-zA-Z0-9]")
    return pattern


def sanitize_arn_pattern(pattern: str) -> str:
    # clown emoji

    # some devs were just lazy ...
    if pattern in [
        ".*",
        "arn:.*",
        "arn:.+",
        "^arn:.+",
        "arn:aws.*:*",
        "^arn:aws.*",
        "^arn:.*",
        ".*\\S.*",
        "^[A-Za-z0-9:\\/_-]*$",
        "^arn[\\/\\:\\-\\_\\.a-zA-Z0-9]+$",
        ".{0,1600}",
        "^arn:[!-~]+$",
        "[\\S]+",
        "[\\s\\S]*",
        "^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$",
        "[a-zA-Z0-9_:\\-\\/]+",
    ]:
        pattern = "arn:aws:[a-z]{4}:us-east-1:[0-9]{12}:[a-z]{8}"

    # common pattern to describe a partition
    pattern = pattern.replace("arn:[^:]*:", "arn:aws:")
    pattern = pattern.replace("arn:[a-z\\d-]+", "arn:aws")
    pattern = pattern.replace("arn:[\\w+=\\/,.@-]+", "arn:aws")
    pattern = pattern.replace("arn:[a-z-]+?", "arn:aws")
    pattern = pattern.replace("arn:[a-z0-9][-.a-z0-9]{0,62}", "arn:aws")
    pattern = pattern.replace(":aws(-\\w+)*", ":aws")
    pattern = pattern.replace(":aws[a-z\\-]*", ":aws")
    pattern = pattern.replace(":aws(-[\\w]+)*", ":aws")
    pattern = pattern.replace(":aws[^:\\s]*", ":aws")
    pattern = pattern.replace(":aws[A-Za-z0-9-]{0,64}", ":aws")
    # often the account-id
    pattern = pattern.replace(":[0-9]+:", ":[0-9]{13}:")
    pattern = pattern.replace(":\\w{12}:", ":[0-9]{13}:")
    # substitutions
    pattern = pattern.replace("[a-z\\-\\d]", "[a-z0-9]")
    pattern = pattern.replace(
        "[\\u0020-\\uD7FF\\uE000-\\uFFFD\\uD800\\uDC00-\\uDBFF\\uDFFF\\r\\n\\t]", "[a-z0-9]"
    )
    pattern = pattern.replace("[\\w\\d-]", "[a-z0-9]")
    pattern = pattern.replace("[\\w+=/,.@-]", "[a-z]")
    pattern = pattern.replace("[^:]", "[a-z]")
    pattern = pattern.replace("[^/]", "[a-z]")
    pattern = pattern.replace("\\d+", "[0-9]+")
    pattern = pattern.replace("\\d*", "[0-9]*")
    pattern = pattern.replace("\\S+", "[a-z]{4}")
    pattern = pattern.replace("\\d]", "0-9]")
    pattern = pattern.replace("[a-z\\d", "[a-z0-9")
    pattern = pattern.replace("[a-zA-Z\\d", "[a-z0-9")
    pattern = pattern.replace("^$|", "")
    pattern = pattern.replace("(^$)|", "")
    pattern = pattern.replace("[:/]", "[a-z]")
    pattern = pattern.replace("/.{", "/[a-z]{")
    pattern = pattern.replace(".{", "[a-z]{")
    pattern = pattern.replace("-*", "-")
    pattern = pattern.replace("\\n", "")
    pattern = pattern.replace("\\r", "")
    # quantifiers
    pattern = pattern.replace("{11}{0,1011}", "{11}")
    pattern = pattern.replace("}+", "}")
    pattern = pattern.replace("]*", "]{6}")
    pattern = pattern.replace("]+", "]{6}")
    pattern = pattern.replace(".*", "[a-z]{6}")
    pattern = pattern.replace(".+", "[a-z]{6}")

    return pattern


custom_arns = {
    "DeviceFarmArn": "arn:aws:devicefarm:us-east-1:1234567890123:mydevicefarm",
    "KmsKeyArn": "arn:aws:kms:us-east-1:1234567890123:key/somekmskeythatisawesome",
}


@singledispatch
def generate_instance(shape: Shape, graph: ShapeGraph) -> Optional[Instance]:
    if shape is None:
        return None
    raise ValueError("could not generate shape for type %s" % shape.type_name)


@generate_instance.register
def _(shape: StructureShape, graph: ShapeGraph) -> Dict[str, Instance]:
    if shape.is_tagged_union:
        k, v = random.choice(list(shape.members.items()))
        members = {k: v}
    else:
        members = shape.members

    if shape.name in graph.cycle_shapes:
        return {}

    return {
        name: generate_instance(member_shape, graph)
        for name, member_shape in members.items()
        if member_shape.name != shape.name
    }


@generate_instance.register
def _(shape: ListShape, graph: ShapeGraph) -> List[Instance]:
    if shape.name in graph.cycle_shapes:
        return []
    return [generate_instance(shape.member, graph) for _ in range(shape.metadata.get("min", 1))]


@generate_instance.register
def _(shape: MapShape, graph: ShapeGraph) -> Dict[str, Instance]:
    if shape.name in graph.cycle_shapes:
        return {}
    return {generate_instance(shape.key, graph): generate_instance(shape.value, graph)}


def generate_arn(shape: StringShape):
    if not shape.metadata:
        return "arn:aws:ec2:us-east-1:1234567890123:instance/i-abcde0123456789f"

    def _generate_arn():
        # some custom hacks
        if shape.name in custom_arns:
            return custom_arns[shape.name]

        max_len = shape.metadata.get("max") or math.inf
        min_len = shape.metadata.get("min") or 0

        pattern = shape.metadata.get("pattern")
        if pattern:
            # FIXME: also conforming to length may be difficult
            pattern = sanitize_arn_pattern(pattern)
            arn = rstr.xeger(pattern)
        else:
            arn = "arn:aws:ec2:us-east-1:1234567890123:instance/i-abcde0123456789f"

        # if there's a value set for the region, replace with a randomly picked region
        # TODO: splitting the ARNs here by ":" sometimes fails for some reason (e.g. or dynamodb for some reason)
        arn_parts = arn.split(":")
        if len(arn_parts) >= 4:
            region = arn_parts[3]
            if region:
                # TODO: check service in ARN and try to get the actual region for the service
                regions = botocore.session.Session().get_available_regions("lambda")
                picked_region = random.choice(regions)
                arn_parts[3] = picked_region
                arn = ":".join(arn_parts)

        if len(arn) > max_len:
            arn = arn[:max_len]

        if len(arn) < min_len or len(arn) > max_len:
            raise ValueError(
                f"generated arn {arn} for shape {shape.name} does not match constraints {shape.metadata}"
            )

        return arn

    return retry(_generate_arn, retries=10, sleep_before=0, sleep=0)


custom_strings = {"DailyTime": "12:10", "WeeklyTime": "1:12:10"}


@generate_instance.register
def _(shape: StringShape, graph: ShapeGraph) -> str:
    if shape.enum:
        return shape.enum[0]

    if shape.name in custom_strings:
        return custom_strings[shape.name]

    if (
        shape.name.endswith("ARN")
        or shape.name.endswith("Arn")
        or shape.name == "AmazonResourceName"
    ):
        return generate_arn(shape)

    max_len: int = shape.metadata.get("max") or 256
    min_len: int = shape.metadata.get("min") or 0
    str_len = min(min_len or 6, max_len)

    pattern = shape.metadata.get("pattern")

    if not pattern or pattern in [".*", "^.*$", ".+"]:
        if min_len <= 6 and max_len >= 6:
            # pick a random six-letter word, to spice things up. this will be the case most of the time.
            return random.choice(words)
        else:
            return "a" * str_len

    pattern = sanitize_pattern(pattern)

    try:
        # try to return something simple first
        random_string = "a" * str_len
        if re.match(pattern, random_string):
            return random_string

        val = rstr.xeger(pattern)
        # TODO: this will break the pattern if the string needs to end with something that we may cut off.
        return val[: min(max_len, len(val))]
    except re.error:
        # TODO: this will likely break the pattern
        return "0" * str_len


@generate_instance.register
def _(shape: Shape, graph: ShapeGraph) -> Union[int, float, bool, bytes, date]:
    if shape.type_name in ["integer", "long"]:
        return shape.metadata.get("min", 1)
    if shape.type_name in ["float", "double"]:
        return shape.metadata.get("min", 1.0)
    if shape.type_name == "boolean":
        return True
    if shape.type_name == "blob":
        # TODO: better blob generator
        return b"0" * shape.metadata.get("min", 1)
    if shape.type_name == "timestamp":
        return datetime.now()

    raise ValueError("unknown type %s" % shape.type_name)


def is_cyclic_shape(shape: Shape) -> bool:
    return True if shape_graph(shape).cycle else False


def generate_response(operation: OperationModel):
    graph = shape_graph(operation.output_shape)
    response = generate_instance(graph.root, graph)
    response.pop("nextToken", None)
    return response


def generate_request(operation: OperationModel):
    graph = shape_graph(operation.input_shape)
    return generate_instance(graph.root, graph)


def return_mock_response(context: RequestContext, request: ServiceRequest) -> ServiceResponse:
    return generate_response(context.operation)


def create_mocking_dispatch_table(service) -> DispatchTable:
    dispatch_table = {}

    for operation in service.operation_names:
        # resolve the bound function of the delegate
        # create a dispatcher
        dispatch_table[operation] = ServiceRequestDispatcher(
            return_mock_response,
            operation=operation,
            pass_context=True,
            expand_parameters=False,
        )

    return dispatch_table


@lru_cache()
def get_mocking_skeleton(service: str) -> Skeleton:
    service = load_service(service)
    return Skeleton(service, create_mocking_dispatch_table(service))
