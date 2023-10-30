import io
import keyword
import re
from functools import cached_property
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, List, Optional, Set

import click
from botocore import xform_name
from botocore.exceptions import UnknownServiceError
from botocore.model import (
    ListShape,
    MapShape,
    OperationModel,
    ServiceModel,
    Shape,
    StringShape,
    StructureShape,
)
from typing_extensions import OrderedDict

from localstack.aws.spec import load_service
from localstack.utils.common import camel_to_snake_case, snake_to_camel_case

# Some minification packages might treat "type" as a keyword, some specs define shapes called like the type "Optional"
KEYWORDS = list(keyword.kwlist) + ["type", "Optional", "Union"]
is_keyword = KEYWORDS.__contains__


def is_bad_param_name(name: str) -> bool:
    if name == "context":
        return True

    if is_keyword(name):
        return True

    return False


def to_valid_python_name(spec_name: str) -> str:
    sanitized = re.sub(r"[^0-9a-zA-Z_]+", "_", spec_name)

    if sanitized[0].isnumeric():
        sanitized = "i_" + sanitized

    if is_keyword(sanitized):
        sanitized += "_"

    if sanitized.startswith("__"):
        sanitized = sanitized[1:]

    return sanitized


def html_to_rst(html: str):
    import pypandoc

    doc = pypandoc.convert_text(html, "rst", format="html")
    doc = doc.replace("\_", "_")  # noqa: W605
    doc = doc.replace("\|", "|")  # noqa: W605
    doc = doc.replace("\ ", " ")  # noqa: W605
    doc = doc.replace("\\", "\\\\")  # noqa: W605
    rst = doc.strip()
    return rst


class ShapeNode:
    service: ServiceModel
    shape: Shape

    def __init__(self, service: ServiceModel, shape: Shape) -> None:
        super().__init__()
        self.service = service
        self.shape = shape

    @cached_property
    def request_operation(self) -> Optional[OperationModel]:
        for operation_name in self.service.operation_names:
            operation = self.service.operation_model(operation_name)
            if operation.input_shape is None:
                continue

            if to_valid_python_name(self.shape.name) == to_valid_python_name(
                operation.input_shape.name
            ):
                return operation

        return None

    @cached_property
    def response_operation(self) -> Optional[OperationModel]:
        for operation_name in self.service.operation_names:
            operation = self.service.operation_model(operation_name)
            if operation.output_shape is None:
                continue

            if to_valid_python_name(self.shape.name) == to_valid_python_name(
                operation.output_shape.name
            ):
                return operation

        return None

    @cached_property
    def is_request(self):
        return self.request_operation is not None

    @cached_property
    def is_response(self):
        return self.response_operation is not None

    @property
    def name(self) -> str:
        return to_valid_python_name(self.shape.name)

    @cached_property
    def is_exception(self):
        metadata = self.shape.metadata
        return metadata.get("error") or metadata.get("exception")

    @property
    def is_primitive(self):
        return self.shape.type_name in ["integer", "boolean", "float", "double", "string"]

    @property
    def is_enum(self):
        return isinstance(self.shape, StringShape) and self.shape.enum

    @property
    def dependencies(self) -> List[str]:
        shape = self.shape

        if isinstance(shape, StructureShape):
            return [to_valid_python_name(v.name) for v in shape.members.values()]
        if isinstance(shape, ListShape):
            return [to_valid_python_name(shape.member.name)]
        if isinstance(shape, MapShape):
            return [to_valid_python_name(shape.key.name), to_valid_python_name(shape.value.name)]

        return []

    def _print_structure_declaration(self, output, doc=True, quote_types=False):
        if self.is_exception:
            self._print_as_class(output, "ServiceException", doc)
            return

        if any(map(is_keyword, self.shape.members.keys())):
            self._print_as_typed_dict(output)
            return

        if self.is_request:
            base = "ServiceRequest"
        else:
            base = "TypedDict, total=False"

        self._print_as_class(output, base, doc, quote_types)

    def _print_as_class(self, output, base: str, doc=True, quote_types=False):
        output.write(f"class {to_valid_python_name(self.shape.name)}({base}):\n")

        q = '"' if quote_types else ""

        if doc:
            self.print_shape_doc(output, self.shape)

        if self.is_exception:
            error_spec = self.shape.metadata.get("error", {})
            output.write(f'    code: str = "{error_spec.get("code", self.shape.name)}"\n')
            output.write(f'    sender_fault: bool = {error_spec.get("senderFault", False)}\n')
            output.write(f'    status_code: int = {error_spec.get("httpStatusCode", 400)}\n')
        elif not self.shape.members:
            output.write("    pass\n")

        # Avoid generating members for the common error members:
        # - The message will always be the exception message (first argument of the exception class init)
        # - The code is already set above
        # - The type is the sender_fault which is already set above
        remaining_members = {
            k: v
            for k, v in self.shape.members.items()
            if not self.is_exception or k.lower() not in ["message", "code"]
        }

        # render any streaming payload first
        if self.is_request and self.request_operation.has_streaming_input:
            member: str = self.request_operation.input_shape.serialization.get("payload")
            shape: Shape = self.request_operation.get_streaming_input()
            if member in self.shape.required_members:
                output.write(f"    {member}: IO[{q}{to_valid_python_name(shape.name)}{q}]\n")
            else:
                output.write(
                    f"    {member}: Optional[IO[{q}{to_valid_python_name(shape.name)}{q}]]\n"
                )
            del remaining_members[member]
        # render the streaming payload first
        if self.is_response and self.response_operation.has_streaming_output:
            member: str = self.response_operation.output_shape.serialization.get("payload")
            shape: Shape = self.response_operation.get_streaming_output()
            shape_name = to_valid_python_name(shape.name)
            if member in self.shape.required_members:
                output.write(
                    f"    {member}: Union[{q}{shape_name}{q}, IO[{q}{shape_name}{q}], Iterable[{q}{shape_name}{q}]]\n"
                )
            else:
                output.write(
                    f"    {member}: Optional[Union[{q}{shape_name}{q}, IO[{q}{shape_name}{q}], Iterable[{q}{shape_name}{q}]]]\n"
                )
            del remaining_members[member]

        for k, v in remaining_members.items():
            if k in self.shape.required_members:
                if v.serialization.get("eventstream"):
                    output.write(f"    {k}: Iterator[{q}{to_valid_python_name(v.name)}{q}]\n")
                else:
                    output.write(f"    {k}: {q}{to_valid_python_name(v.name)}{q}\n")
            else:
                if v.serialization.get("eventstream"):
                    output.write(f"    {k}: Iterator[{q}{to_valid_python_name(v.name)}{q}]\n")
                else:
                    output.write(f"    {k}: Optional[{q}{to_valid_python_name(v.name)}{q}]\n")

    def _print_as_typed_dict(self, output, doc=True, quote_types=False):
        name = to_valid_python_name(self.shape.name)
        q = '"' if quote_types else ""
        output.write('%s = TypedDict("%s", {\n' % (name, name))
        for k, v in self.shape.members.items():
            if k in self.shape.required_members:
                if v.serialization.get("eventstream"):
                    output.write(f'    "{k}": Iterator[{q}{to_valid_python_name(v.name)}{q}],\n')
                else:
                    output.write(f'    "{k}": {q}{to_valid_python_name(v.name)}{q},\n')
            else:
                if v.serialization.get("eventstream"):
                    output.write(f'    "{k}": Iterator[{q}{to_valid_python_name(v.name)}{q}],\n')
                else:
                    output.write(f'    "{k}": Optional[{q}{to_valid_python_name(v.name)}{q}],\n')
        output.write("}, total=False)")

    def print_shape_doc(self, output, shape):
        html = shape.documentation
        rst = html_to_rst(html)
        if rst:
            output.write('    """')
            output.write(f"{rst}\n")
            output.write('    """\n')

    def print_declaration(self, output, doc=True, quote_types=False):
        shape = self.shape

        q = '"' if quote_types else ""

        if isinstance(shape, StructureShape):
            self._print_structure_declaration(output, doc, quote_types)
        elif isinstance(shape, ListShape):
            output.write(
                f"{to_valid_python_name(shape.name)} = List[{q}{to_valid_python_name(shape.member.name)}{q}]"
            )
        elif isinstance(shape, MapShape):
            output.write(
                f"{to_valid_python_name(shape.name)} = Dict[{q}{to_valid_python_name(shape.key.name)}{q}, {q}{to_valid_python_name(shape.value.name)}{q}]"
            )
        elif isinstance(shape, StringShape):
            if shape.enum:
                output.write(f"class {to_valid_python_name(shape.name)}(str):\n")
                for value in shape.enum:
                    name = to_valid_python_name(value)
                    output.write(f'    {name} = "{value}"\n')
            else:
                output.write(f"{to_valid_python_name(shape.name)} = str")
        elif shape.type_name == "string":
            output.write(f"{to_valid_python_name(shape.name)} = str")
        elif shape.type_name == "integer":
            output.write(f"{to_valid_python_name(shape.name)} = int")
        elif shape.type_name == "long":
            output.write(f"{to_valid_python_name(shape.name)} = int")
        elif shape.type_name == "double":
            output.write(f"{to_valid_python_name(shape.name)} = float")
        elif shape.type_name == "float":
            output.write(f"{to_valid_python_name(shape.name)} = float")
        elif shape.type_name == "boolean":
            output.write(f"{to_valid_python_name(shape.name)} = bool")
        elif shape.type_name == "blob":
            # blobs are often associated with streaming payloads, but we handle that on operation level,
            # not on shape level
            output.write(f"{to_valid_python_name(shape.name)} = bytes")
        elif shape.type_name == "timestamp":
            output.write(f"{to_valid_python_name(shape.name)} = datetime")
        else:
            output.write(
                f"# unknown shape type for {to_valid_python_name(shape.name)}: {shape.type_name}"
            )
        # TODO: BoxedInteger?

        output.write("\n")

    def get_order(self):
        """
        Defines a basic order in which to sort the stack of shape nodes before printing.
        First all non-enum primitives are printed, then enums, then exceptions, then all other types.
        """
        if self.is_primitive:
            if self.is_enum:
                return 1
            else:
                return 0

        if self.is_exception:
            return 2

        return 3


def generate_service_types(output, service: ServiceModel, doc=True):
    output.write(
        "from typing import Dict, List, Optional, Iterator, Iterable, IO, Union, TypedDict\n"
    )
    output.write("from datetime import datetime\n")
    output.write("\n")
    output.write(
        "from localstack.aws.api import handler, RequestContext, ServiceException, ServiceRequest"
    )
    output.write("\n")

    # ==================================== print type declarations
    nodes: Dict[str, ShapeNode] = {}

    for shape_name in service.shape_names:
        shape = service.shape_for(shape_name)
        nodes[to_valid_python_name(shape_name)] = ShapeNode(service, shape)

    # output.write("__all__ = [\n")
    # for name in nodes.keys():
    #     output.write(f'    "{name}",\n')
    # output.write("]\n")

    printed: Set[str] = set()
    visited: Set[str] = set()
    stack: List[str] = list(nodes.keys())

    stack = sorted(stack, key=lambda name: nodes[name].get_order())
    stack.reverse()

    while stack:
        name = stack.pop()
        if name in printed:
            continue
        node = nodes[name]

        dependencies = [dep for dep in node.dependencies if dep not in printed]

        if not dependencies:
            node.print_declaration(output, doc=doc)
            printed.add(name)
        elif name in visited:
            # break out of circular dependencies
            node.print_declaration(output, doc=doc, quote_types=True)
            printed.add(name)
        else:
            stack.append(name)
            stack.extend(dependencies)
            visited.add(name)


def generate_service_api(output, service: ServiceModel, doc=True):
    service_name = service.service_name.replace("-", "_")
    class_name = service_name + "_api"
    class_name = snake_to_camel_case(class_name)

    output.write(f"class {class_name}:\n")
    output.write("\n")
    output.write(f'    service = "{service.service_name}"\n')
    output.write(f'    version = "{service.api_version}"\n')
    for op_name in service.operation_names:
        operation: OperationModel = service.operation_model(op_name)

        fn_name = camel_to_snake_case(op_name)

        if operation.output_shape:
            output_shape = to_valid_python_name(operation.output_shape.name)
        else:
            output_shape = "None"

        output.write("\n")
        parameters = OrderedDict()
        param_shapes = OrderedDict()

        if input_shape := operation.input_shape:
            members = list(input_shape.members)

            streaming_payload_member = None
            if operation.has_streaming_input:
                streaming_payload_member = operation.input_shape.serialization.get("payload")

            for m in input_shape.required_members:
                members.remove(m)
                m_shape = input_shape.members[m]
                type_name = to_valid_python_name(m_shape.name)
                if m == streaming_payload_member:
                    type_name = f"IO[{type_name}]"
                parameters[xform_name(m)] = type_name
                param_shapes[xform_name(m)] = m_shape

            for m in members:
                m_shape = input_shape.members[m]
                param_shapes[xform_name(m)] = m_shape
                type_name = to_valid_python_name(m_shape.name)
                if m == streaming_payload_member:
                    type_name = f"IO[{type_name}]"
                parameters[xform_name(m)] = f"{type_name} = None"

        if any(map(is_bad_param_name, parameters.keys())):
            # if we cannot render the parameter name, don't expand the parameters in the handler
            param_list = f"request: {to_valid_python_name(input_shape.name)}" if input_shape else ""
            output.write(f'    @handler("{operation.name}", expand=False)\n')
        else:
            param_list = ", ".join([f"{k}: {v}" for k, v in parameters.items()])
            output.write(f'    @handler("{operation.name}")\n')

        output.write(
            f"    def {fn_name}(self, context: RequestContext, {param_list}) -> {output_shape}:\n"
        )

        # convert html documentation to rst and print it into to the signature
        if doc:
            html = operation.documentation
            rst = html_to_rst(html)
            output.write('        """')
            output.write(f"{rst}\n")
            output.write("\n")

            # parameters
            for param_name, shape in param_shapes.items():
                # FIXME: this doesn't work properly
                rst = html_to_rst(shape.documentation)
                rst = rst.strip().split(".")[0] + "."
                output.write(f":param {param_name}: {rst}\n")

            # return value
            if operation.output_shape:
                output.write(f":returns: {to_valid_python_name(operation.output_shape.name)}\n")

            # errors
            for error in operation.error_shapes:
                output.write(f":raises {to_valid_python_name(error.name)}:\n")

            output.write('        """\n')

        output.write("        raise NotImplementedError\n")


@click.group()
def scaffold():
    pass


@scaffold.command(name="generate")
@click.argument("service", type=str)
@click.option("--doc/--no-doc", default=False, help="whether or not to generate docstrings")
@click.option(
    "--save/--print",
    default=False,
    help="whether or not to save the result into the api directory",
)
@click.option(
    "--path", default="./localstack/aws/api", help="the path where the api should be saved"
)
def generate(service: str, doc: bool, save: bool, path: str):
    """
    Generate types and API stubs for a given AWS service.

    SERVICE is the service to generate the stubs for (e.g., sqs, or cloudformation)
    """
    from click import ClickException

    try:
        code = generate_code(service, doc=doc)
    except UnknownServiceError:
        raise ClickException(f"unknown service {service}")

    if not save:
        # either just print the code to stdout
        click.echo(code)
        return

    # or find the file path and write the code to that location
    create_code_directory(service, code, path)
    click.echo("done!")


def generate_code(service_name: str, doc: bool = False) -> str:
    model = load_service(service_name)
    output = io.StringIO()
    generate_service_types(output, model, doc=doc)
    generate_service_api(output, model, doc=doc)
    return output.getvalue()


def create_code_directory(service_name: str, code: str, base_path: str):
    service_name = service_name.replace("-", "_")
    # handle service names which are reserved keywords in python (f.e. lambda)
    if is_keyword(service_name):
        service_name += "_"
    path = Path(base_path, service_name)

    if not path.exists():
        click.echo(f"creating directory {path}")
        path.mkdir()

    file = path / "__init__.py"
    click.echo(f"writing to file {file}")
    file.write_text(code)


@scaffold.command()
@click.option("--doc/--no-doc", default=False, help="whether or not to generate docstrings")
@click.option(
    "--path",
    default="./localstack/aws/api",
    help="the path in which to upgrade ASF APIs",
)
def upgrade(path: str, doc: bool = False):
    """
    Execute the code generation for all existing APIs.
    """
    services = [
        d.name.rstrip("_").replace("_", "-")
        for d in Path(path).iterdir()
        if d.is_dir() and not d.name.startswith("__")
    ]

    with Pool() as pool:
        pool.starmap(_do_generate_code, [(service, path, doc) for service in services])

    click.echo("done!")


def _do_generate_code(service: str, path: str, doc: bool):
    try:
        code = generate_code(service, doc)
    except UnknownServiceError:
        click.echo(f"unknown service {service}! skipping...")
        return
    create_code_directory(service, code, base_path=path)


if __name__ == "__main__":
    scaffold()
