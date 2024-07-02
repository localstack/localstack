import importlib
import logging
import mimetypes
import os
import typing as t
from pathlib import Path

from rolo.router import RuleAdapter

from localstack.constants import APPLICATION_OCTET_STREAM
from localstack.extensions.api import http
from localstack.extensions.patterns.baseui import WebAppBaseExtension
from localstack.http import Response

LOG = logging.getLogger(__name__)

_default = object()


class ReactExtension(WebAppBaseExtension):
    """
    EXPERIMENTAL! This class is experimental and the API may change without notice.

    A webapp extension serves routes, templates, and static files via a submount and a subdomain through
    localstack.

    It assumes you have the following directory layout::

        my_extension
        ├── extension.py
        ├── __init__.py
        └──  frontend
            ├── __init__.py
            └── build               <-- make sure everything built is also packaged
                └── index.html

    Given this layout, you can define your extensions in ``my_extension.extension`` like this. Routes defined in the
    extension itself are automatically registered::

        class MyExtension(ReactExtension):
            name = "my-extension"

            @route("/")
            def index(request: Request) -> Response:
                # reference `static/style.css` to serve the static file from your package
                return self.render_template_response("index.html")

            @route("/hello")
            def hello(request: Request):
                return {"message": "Hello World!"}

    This will create an extension that localstack serves via:

    * Submount: https://localhost.localstack.cloud:4566/_extension/my-extension
    * Subdomain: https://my-extension.localhost.localstack.cloud:4566/

    Both are created for full flexibility:

    * Subdomains: create a domain namespace that can be helpful for some extensions, especially when
      running on the local machine
    * Submounts: for some environments, like in ephemeral instances where subdomains are harder to control,
      submounts are more convenient

    Any routes added by the extension will be served relative to these URLs.
    """

    def _add_superclass_routes(self, routes: list[t.Any]):
        routes.append(RuleAdapter("/<path:path>", self._serve_static_file))
        routes.append(RuleAdapter("/", self._serve_static_file))

    def _serve_static_file(self, request: http.Request, path=None):
        """Route for serving static files, for ``/_extension/my-extension/<path:path>``."""
        if not path:
            path = request.path

        self.static_resource_module = importlib.import_module(
            self.get_extension_module_root() + "." + "frontend"
        )
        build_dir = os.path.join(self.static_resource_module.__path__[0], "build")
        file_path = os.path.join(build_dir, path.lstrip("/"))

        if not os.path.exists(file_path):
            file_path = os.path.join(build_dir, "index.html")

        mime_type = mimetypes.guess_type(file_path)[0] or APPLICATION_OCTET_STREAM

        return Response(Path(file_path).open(mode="rb"), mimetype=mime_type)
