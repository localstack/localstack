import json
import logging
import os

import requests
from rolo import Response

from localstack import constants
from localstack.utils.files import load_file
from localstack.utils.json import parse_json_or_yaml

LOG = logging.getLogger(__name__)


class CloudFormationUi:
    def on_get(self, request):
        from localstack.utils.aws.aws_stack import get_valid_regions

        deploy_html_file = os.path.join(
            constants.MODULE_MAIN_PATH, "services", "cloudformation", "deploy.html"
        )
        deploy_html = load_file(deploy_html_file)
        req_params = request.values
        params = {
            "stackName": "stack1",
            "templateBody": "{}",
            "errorMessage": "''",
            "regions": json.dumps(sorted(get_valid_regions())),
        }

        download_url = req_params.get("templateURL")
        if download_url:
            try:
                LOG.debug("Attempting to download CloudFormation template URL: %s", download_url)
                template_body = requests.get(download_url).text
                template_body = parse_json_or_yaml(template_body)
                params["templateBody"] = json.dumps(template_body)
            except Exception as e:
                msg = f"Unable to download CloudFormation template URL: {e}"
                LOG.info(msg)
                params["errorMessage"] = json.dumps(msg.replace("\n", " - "))

        # using simple string replacement here, for simplicity (could be replaced with, e.g., jinja)
        for key, value in params.items():
            deploy_html = deploy_html.replace(f"<{key}>", value)

        return Response(deploy_html, mimetype="text/html")
