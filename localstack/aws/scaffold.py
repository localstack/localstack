import io
import keyword
import os
from typing import Dict, List, Set

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
from localstack.utils.common import camel_to_snake_case, mkdir, snake_to_camel_case


def to_valid_python_name(spec_name: str) -> str:
    sanitized = spec_name.replace("-", "_")

    if sanitized in keyword.kwlist:
        sanitized += "_"

    return sanitized


class ShapeNode:
    service: ServiceModel
    shape: Shape

    def __init__(self, service: ServiceModel, shape: Shape) -> None:
        super().__init__()
        self.service = service
        self.shape = shape

    @property
    def is_request(self):
        for operation_name in self.service.operation_names:
            operation = self.service.operation_model(operation_name)
            if operation.input_shape is None:
                continue
            if self.shape.name == operation.input_shape.name:
                return True

        return False

    @property
    def name(self) -> str:
        return self.shape.name

    @property
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
            return [v.name for v in shape.members.values()]
        if isinstance(shape, ListShape):
            return [shape.member.name]
        if isinstance(shape, MapShape):
            return [shape.key.name, shape.value.name]

        return []

    def print_declaration(self, output, doc=True):
        code = ""

        shape = self.shape

        if isinstance(shape, StructureShape):
            base = "TypedDict, total=False"
            members = ""

            if self.is_exception:
                base = "ServiceException"
            if self.is_request:
                base = "ServiceRequest"

            if not shape.members:
                members = "    pass"

            for k, v in shape.members.items():
                if k in shape.required_members:
                    members += f"    {k}: {v.name}\n"
                else:
                    members += f"    {k}: Optional[{v.name}]\n"

            code = f"class {shape.name}({base}):\n"

            if doc:
                html = shape.documentation
                import pypandoc

                doc = pypandoc.convert_text(html, "rst", format="html")
                rst = doc.strip()
                if rst:
                    code += '    """'
                    code += f"{doc.strip()}\n"
                    code += '    """\n'

            code += f"{members}\n"

        elif isinstance(shape, ListShape):
            code = f"{shape.name} = List[{shape.member.name}]\n"
        elif isinstance(shape, MapShape):
            code = f"{shape.name} = Dict[{shape.key.name}, {shape.value.name}]"
        elif isinstance(shape, StringShape):
            if shape.enum:
                code += f"class {shape.name}(str):\n"
                for value in shape.enum:
                    name = to_valid_python_name(value)
                    code += f'    {name} = "{value}"\n'
                code += "\n"
            else:
                code = f"{shape.name} = str"
        elif shape.type_name == "string":
            code = f"{shape.name} = str"
        elif shape.type_name == "integer":
            code = f"{shape.name} = int"
        elif shape.type_name == "long":
            code = f"{shape.name} = int"
        elif shape.type_name == "double":
            code = f"{shape.name} = float"
        elif shape.type_name == "float":
            code = f"{shape.name} = float"
        elif shape.type_name == "boolean":
            code = f"{shape.name} = bool"
        elif shape.type_name == "blob":
            code = f"{shape.name} = bytes"  # FIXME check what type blob really is
        elif shape.type_name == "timestamp":
            code = f"{shape.name} = str"  # FIXME
        else:
            code = f"# unknown shape type for {shape.name}: {shape.type_name}"
        # TODO: BoxedInteger?

        output.write(code)
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
    output.write("import sys\n")
    output.write("from typing import Dict, List, Optional\n")
    output.write("if sys.version_info >= (3, 8):\n")
    output.write("    from typing import TypedDict\n")
    output.write("else:\n")
    output.write("    from typing_extensions import TypedDict\n")
    output.write("\n")
    output.write(
        "from localstack.aws.api import handler, RequestContext, ServiceException, ServiceRequest"
    )
    output.write("\n")

    # ==================================== print type declarations
    nodes: Dict[str, ShapeNode] = dict()

    for shape_name in service.shape_names:
        shape = service.shape_for(shape_name)
        nodes[shape_name] = ShapeNode(service, shape)

    # output.write("__all__ = [\n")
    # for name in nodes.keys():
    #     output.write(f'    "{name}",\n')
    # output.write("]\n")

    printed: Set[str] = set()
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
        else:
            stack.append(name)
            stack.extend(dependencies)
            # TODO: circular dependencies (do they exist?)


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
            output_shape = operation.output_shape.name
        else:
            output_shape = "None"

        output.write("\n")
        parameters = OrderedDict()
        param_shapes = OrderedDict()

        input_shape = operation.input_shape
        if input_shape is not None:
            members = list(input_shape.members)
            for m in input_shape.required_members:
                members.remove(m)
                m_shape = input_shape.members[m]
                parameters[xform_name(m)] = m_shape.name
                param_shapes[xform_name(m)] = m_shape
            for m in members:
                m_shape = input_shape.members[m]
                param_shapes[xform_name(m)] = m_shape
                parameters[xform_name(m)] = f"{m_shape.name} = None"

        param_list = ", ".join([f"{k}: {v}" for k, v in parameters.items()])
        output.write(f'    @handler("{operation.name}")\n')
        output.write(
            f"    def {fn_name}(self, context: RequestContext, {param_list}) -> {output_shape}:\n"
        )

        # convert html documentation to rst and print it into to the signature
        if doc:
            html = operation.documentation
            import pypandoc

            doc = pypandoc.convert_text(html, "rst", format="html")
            output.write('        """')
            output.write(f"{doc.strip()}\n")
            output.write("\n")

            # parameters
            for param_name, shape in param_shapes.items():
                # FIXME: this doesn't work properly
                pdoc = pypandoc.convert_text(shape.documentation, "rst", format="html")
                pdoc = pdoc.strip().split(".")[0] + "."
                output.write(f":param {param_name}: {pdoc}\n")

            # return value
            if operation.output_shape:
                output.write(f":returns: {operation.output_shape.name}\n")

            # errors
            for error in operation.error_shapes:
                output.write(f":raises {error.name}:\n")

            output.write('        """\n')

        output.write("        raise NotImplementedError\n")


@click.command()
@click.argument("service", type=str)
@click.option("--doc/--no-doc", default=False, help="whether or not to generate docstrings")
@click.option(
    "--save/--print",
    default=False,
    help="whether or not to save the result into the api directory",
)
def generate(service: str, doc: bool, save: bool):
    """
    Generate types and API stubs for a given AWS service.

    SERVICE is the service to generate the stubs for (e.g., sqs, or cloudformation)
    """
    from click import ClickException

    try:
        model = load_service(service)
    except UnknownServiceError:
        raise ClickException("unknown service %s" % service)

    output = io.StringIO()
    generate_service_types(output, model, doc=doc)
    generate_service_api(output, model, doc=doc)

    code = output.getvalue()

    try:
        # try to format with black
        from black import FileMode, format_str

        code = format_str(code, mode=FileMode())
    except Exception:
        pass

    if not save:
        # either just print the code to stdout
        click.echo(code)
        return

    # or find the file path and write the code to that location
    here = os.path.dirname(__file__)
    path = os.path.join(here, "api", service)

    if not os.path.exists(path):
        click.echo("creating directory %s" % path)
        mkdir(path)

    file = os.path.join(path, "__init__.py")
    click.echo("writing to file %s" % file)
    with open(file, "w") as fd:
        fd.write(code)
    click.echo("done!")


if __name__ == "__main__":
    generate()
