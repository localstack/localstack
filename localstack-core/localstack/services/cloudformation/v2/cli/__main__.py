import click
from click import ClickException

from localstack.services.cloudformation.engine import template_preparer
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeSetModel,
    ChangeType,
    NodeProperty,
    NodeResource,
    NodeResources,
    NodeTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)


class ChangeSetModelPrettyPrinter(ChangeSetModelVisitor):
    indent_count = 2

    def __init__(self):
        self._depth: int = 0

    def print(self, update_graph: NodeTemplate):
        self.visit(update_graph)

    # overridden methods
    def visit(self, entity: ChangeSetEntity):
        self._pretty_print_entity(entity)
        return super().visit(entity)

    def visit_node_resource(self, node_resource: NodeResource):
        super().visit_node_resource(node_resource)
        self._depth -= self.indent_count

    def _pretty_print_entity(self, entity: ChangeSetEntity):
        entity_type = entity.__class__.__name__
        method_name = f"_pretty_print_{entity_type}"
        if method := getattr(self, method_name, None):
            method(entity)

    def _pretty_print_NodeResources(self, resource: NodeResources):
        self.print_styled(f"{self.prefix}Resources", resource.change_type)
        self._depth += self.indent_count

    def _pretty_print_NodeResource(self, resource: NodeResource):
        resource_name = resource.name
        resource_type = resource.type_.value
        self.print_styled(f"{self.prefix}{resource_name} ({resource_type})", resource.change_type)
        self._depth += self.indent_count

    def _pretty_print_NodeProperty(self, property: NodeProperty):
        self.print_styled(f"{self.prefix}{property.name}", property.change_type)

    @property
    def prefix(self) -> str:
        return " " * self._depth

    @staticmethod
    def colour(change_type: ChangeType) -> str:
        colour = {
            ChangeType.CREATED: "green",
            ChangeType.REMOVED: "red",
            ChangeType.MODIFIED: "blue",
        }.get(change_type, "bright_white")
        return colour

    def print_styled(self, text: str, change_type: ChangeType):
        click.echo(click.style(text, fg=self.colour(change_type)))


@click.group()
def cli():
    pass


@cli.command()
@click.argument("templates", nargs=2, type=click.File())
def pretty_print(templates: list[click.File]):
    """
    Pretty print an update graph given two templates
    """
    # Should neve happen but in case click's interface breaks
    if len(templates) != 2:
        raise ClickException(
            f"Invalid number of templates provided, expected 2 got {len(templates)}"
        )

    def parse_template(file: click.File) -> dict:
        contents = file.read()
        structured_template = template_preparer.parse_template(contents)
        return structured_template

    t1, t2 = (parse_template(templates[0]), parse_template(templates[1]))

    # TODO: parameters
    model = ChangeSetModel(
        before_template=t1, after_template=t2, before_parameters=None, after_parameters=None
    )
    update_graph = model.get_update_model()

    pretty_printer = ChangeSetModelPrettyPrinter()
    pretty_printer.print(update_graph)


def __main__():
    cli()


if __name__ == "__main__":
    __main__()
