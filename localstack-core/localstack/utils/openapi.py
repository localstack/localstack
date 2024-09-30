import copy
import logging
import textwrap
from typing import Any

import yaml
from plux import PluginManager

from localstack import version

LOG = logging.getLogger(__name__)

spec_top_info = textwrap.dedent("""
openapi: 3.1.0
info:
  contact:
    email: info@localstack.cloud
    name: LocalStack Support
    url: https://www.localstack.cloud/contact
  summary: The LocalStack REST API exposes functionality related to diagnostics, health
    checks, plugins, initialisation hooks, service introspection, and more.
  termsOfService: https://www.localstack.cloud/legal/tos
  title: LocalStack REST API
  version: 1.0
externalDocs:
  description: LocalStack Documentation
  url: https://docs.localstack.cloud
servers:
  - url: http://{host}:{port}
    variables:
      port:
        default: '4566'
      host:
        default: 'localhost.localstack.cloud'
""")


def _merge_openapi_specs(specs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Merge a list of OpenAPI specs into a single specification.
    :param specs:  a list of OpenAPI specs loaded in a dictionary
    :return: the dictionary of a merged spec.
    """
    merged_spec = {}
    for idx, spec in enumerate(specs):
        if idx == 0:
            merged_spec = copy.deepcopy(spec)
        else:
            # Merge paths
            if "paths" in spec:
                merged_spec.setdefault("paths", {}).update(spec.get("paths", {}))

            # Merge components
            if "components" in spec:
                if "components" not in merged_spec:
                    merged_spec["components"] = {}
                for component_type, component_value in spec["components"].items():
                    if component_type not in merged_spec["components"]:
                        merged_spec["components"][component_type] = component_value
                    else:
                        merged_spec["components"][component_type].update(component_value)

    # Update the initial part of the spec, i.e., info and correct LocalStack version
    top_content = yaml.safe_load(spec_top_info)
    # Set the correct version
    top_content["info"]["version"] = version.version
    merged_spec.update(top_content)
    return merged_spec


def get_localstack_openapi_spec() -> dict[str, Any]:
    """
    Collects all the declared OpenAPI specs in LocalStack.
    Specs are declared by implementing a OASPlugin.
    :return: the entire LocalStack OpenAPI spec in a Python dictionary.
    """
    specs = PluginManager("localstack.openapi.spec").load_all()
    try:
        return _merge_openapi_specs([spec.spec for spec in specs])
    except Exception as e:
        LOG.debug("An error occurred while trying to merge the collected OpenAPI specs %s", e)
        # In case of an error while merging the spec, we return the first collected one.
        return specs[0].spec
