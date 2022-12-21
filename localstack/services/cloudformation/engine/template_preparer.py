import json
import logging
import os
import re
from typing import Optional
from urllib.parse import urlparse

import boto3
import moto.cloudformation.utils
import yaml
from requests.structures import CaseInsensitiveDict
from samtranslator.translator.managed_policy_translator import ManagedPolicyLoader
from samtranslator.translator.transform import transform as transform_sam

from localstack import config, constants
from localstack.services.s3 import s3_listener, s3_utils
from localstack.utils.aws import aws_stack
from localstack.utils.functions import run_safe
from localstack.utils.http import safe_requests
from localstack.utils.json import clone_safe
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)

# create safe yaml loader that parses date strings as string, not date objects
NoDatesSafeLoader = yaml.SafeLoader
NoDatesSafeLoader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"]
    for k, v in NoDatesSafeLoader.yaml_implicit_resolvers.items()
}

policy_loader = None


def _create_loader():
    global policy_loader
    if not policy_loader:
        iam_client = aws_stack.connect_to_service("iam")
        policy_loader = ManagedPolicyLoader(iam_client=iam_client)
    return policy_loader


def transform_template(req_data) -> Optional[str]:
    """only returns string when parsing SAM template, otherwise None"""
    template_body = get_template_body(req_data)
    parsed = parse_template(template_body)
    if parsed.get("Transform") == "AWS::Serverless-2016-10-31":

        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        region_before = os.environ.get("AWS_DEFAULT_REGION")
        if boto3.session.Session().region_name is None:
            os.environ["AWS_DEFAULT_REGION"] = aws_stack.get_region()
        loader = _create_loader()
        try:
            transformed = transform_sam(parsed, {}, loader)
            return json.dumps(transformed)
        finally:
            os.environ.pop("AWS_DEFAULT_REGION", None)
            if region_before is not None:
                os.environ["AWS_DEFAULT_REGION"] = region_before


def prepare_template_body(req_data) -> str | bytes | None:  # TODO: mutating and returning
    template_url = req_data.get("TemplateURL")
    if template_url:
        req_data["TemplateURL"] = convert_s3_to_local_url(template_url)
    url = req_data.get("TemplateURL", "")
    if is_local_service_url(url):
        modified_template_body = get_template_body(req_data)
        if modified_template_body:
            req_data.pop("TemplateURL", None)
            req_data["TemplateBody"] = modified_template_body
    modified_template_body = transform_template(req_data)
    if modified_template_body:
        req_data["TemplateBody"] = modified_template_body
    return modified_template_body


def validate_template(req_data):
    # TODO implement actual validation logic
    # Note: if we enable this via moto, ensure that we have cfnlint module available (adds ~58MB in size :/)
    response_content = """
        <Capabilities></Capabilities>
        <CapabilitiesReason></CapabilitiesReason>
        <DeclaredTransforms></DeclaredTransforms>
        <Description>{description}</Description>
        <Parameters>
            {parameters}
        </Parameters>
    """
    template_body = get_template_body(req_data)
    valid_template = json.loads(template_to_json(template_body))
    parameters = "".join(
        [
            """
        <member>
            <ParameterKey>{pk}</ParameterKey>
            <DefaultValue>{dv}</DefaultValue>
            <NoEcho>{echo}</NoEcho>
            <Description>{desc}</Description>
        </member>
        """.format(
                pk=k, dv=v.get("Default", ""), echo=False, desc=v.get("Description", "")
            )
            for k, v in valid_template.get("Parameters", {}).items()
        ]
    )

    resp = response_content.format(
        parameters=parameters, description=valid_template.get("Description", "")
    )
    return resp


def get_template_body(req_data):
    body = req_data.get("TemplateBody")
    if body:
        return body
    url = req_data.get("TemplateURL")
    if url:
        response = run_safe(lambda: safe_requests.get(url, verify=False))
        # check error codes, and code 301 - fixes https://github.com/localstack/localstack/issues/1884
        status_code = 0 if response is None else response.status_code
        if response is None or status_code == 301 or status_code >= 400:
            # check if this is an S3 URL, then get the file directly from there
            url = convert_s3_to_local_url(url)
            if is_local_service_url(url):
                parsed_path = urlparse(url).path.lstrip("/")
                parts = parsed_path.partition("/")
                client = aws_stack.connect_to_service("s3")
                LOG.debug(
                    "Download CloudFormation template content from local S3: %s - %s",
                    parts[0],
                    parts[2],
                )
                result = client.get_object(Bucket=parts[0], Key=parts[2])
                body = to_str(result["Body"].read())
                return body
            raise Exception(
                "Unable to fetch template body (code %s) from URL %s" % (status_code, url)
            )
        return to_str(response.content)
    raise Exception("Unable to get template body from input: %s" % req_data)


def parse_template(template):
    try:
        return json.loads(template)
    except Exception:
        yaml.add_multi_constructor(
            "", moto.cloudformation.utils.yaml_tag_constructor, Loader=NoDatesSafeLoader
        )  # TODO: remove moto dependency here
        try:
            return clone_safe(yaml.safe_load(template))
        except Exception:
            try:
                return clone_safe(yaml.load(template, Loader=NoDatesSafeLoader))
            except Exception as e:
                LOG.debug("Unable to parse CloudFormation template (%s): %s", e, template)
                raise


def template_to_json(template):
    template = parse_template(template)
    return json.dumps(template)


def is_local_service_url(url):
    if not url:
        return False
    candidates = (
        constants.LOCALHOST,
        constants.LOCALHOST_HOSTNAME,
        config.LOCALSTACK_HOSTNAME,
        config.HOSTNAME_EXTERNAL,
    )
    if any(re.match(r"^[^:]+://[^:/]*%s([:/]|$)" % host, url) for host in candidates):
        return True
    host = url.split("://")[-1].split("/")[0]
    return "localhost" in host


def convert_s3_to_local_url(url):
    url_parsed = urlparse(url)
    path = url_parsed.path

    headers = CaseInsensitiveDict({"Host": url_parsed.netloc})
    bucket_name = s3_utils.extract_bucket_name(headers, path)
    key_name = s3_utils.extract_key_name(headers, path)

    # note: make sure to normalize the bucket name here!
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    local_url = f"{config.service_url('s3')}/{bucket_name}/{key_name}"
    return local_url
