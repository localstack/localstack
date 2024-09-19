import os

from jinja2 import Environment, FileSystemLoader
from rolo import route

from localstack.config import external_service_url
from localstack.http import Response


class SwaggerUIApi:
    init_path: str

    def __init__(self) -> None:
        self.init_path = f"{external_service_url()}/openapi.yaml"

    @route("/_localstack/swagger", methods=["GET"])
    def server_swagger_ui(self, _request):
        oas_path = os.path.join(os.path.dirname(__file__), "templates")
        env = Environment(loader=FileSystemLoader(oas_path))
        template = env.get_template("index.html")
        rendered_template = template.render()
        return Response(rendered_template, content_type="text/html")

    @route("/_localstack/swagger-initializer.js", methods=["GET"])
    def serve_swagger_initializer(self, _request):
        oas_path = os.path.join(os.path.dirname(__file__), "static")
        env = Environment(loader=FileSystemLoader(oas_path))
        template = env.get_template("swagger-initializer.js")

        rendered_template = template.render(swagger_url=self.init_path)
        return Response(rendered_template, content_type="application/javascript")
