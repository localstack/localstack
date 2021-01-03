import re
import os
import json
import yaml
import logging
import boto3
import moto.cloudformation.utils
from six.moves.urllib import parse as urlparse
from samtranslator.translator.transform import transform as transform_sam
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.services.s3 import s3_listener
from localstack.utils.common import to_str, safe_requests, run_safe, clone_safe

LOG = logging.getLogger(__name__)

# create safe yaml loader that parses date strings as string, not date objects
NoDatesSafeLoader = yaml.SafeLoader
NoDatesSafeLoader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != 'tag:yaml.org,2002:timestamp'] for
    k, v in NoDatesSafeLoader.yaml_implicit_resolvers.items()
}


def transform_template(req_data):
    template_body = get_template_body(req_data)
    parsed = parse_template(template_body)

    policy_map = {
        # SAM Transformer expects this map to be non-empty, but apparently the content doesn't matter (?)
        'dummy': 'entry'
        # 'AWSLambdaBasicExecutionRole': 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
    }

    class MockPolicyLoader(object):
        def load(self):
            return policy_map

    if parsed.get('Transform') == 'AWS::Serverless-2016-10-31':
        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        region_before = os.environ.get('AWS_DEFAULT_REGION')
        if boto3.session.Session().region_name is None:
            os.environ['AWS_DEFAULT_REGION'] = aws_stack.get_region()
        try:
            transformed = transform_sam(parsed, {}, MockPolicyLoader())
            return json.dumps(transformed)
        finally:
            os.environ.pop('AWS_DEFAULT_REGION', None)
            if region_before is not None:
                os.environ['AWS_DEFAULT_REGION'] = region_before


def prepare_template_body(req_data):
    do_replace_url = is_real_s3_url(req_data.get('TemplateURL'))
    if do_replace_url:
        req_data['TemplateURL'] = convert_s3_to_local_url(req_data['TemplateURL'])
    url = req_data.get('TemplateURL', '')
    if is_local_service_url(url):
        modified_template_body = get_template_body(req_data)
        if modified_template_body:
            req_data.pop('TemplateURL', None)
            req_data['TemplateBody'] = modified_template_body
    modified_template_body = transform_template(req_data)
    if modified_template_body:
        req_data['TemplateBody'] = modified_template_body
    return modified_template_body or do_replace_url


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
    parameters = ''.join([
        """
        <member>
            <ParameterKey>{pk}</ParameterKey>
            <DefaultValue>{dv}</DefaultValue>
            <NoEcho>{echo}</NoEcho>
            <Description>{desc}</Description>
        </member>
        """.format(
            pk=k,
            dv=v.get('Default', ''),
            echo=False,
            desc=v.get('Description', '')

        )
        for k, v in valid_template.get('Parameters', {}).items()
    ])

    resp = response_content.format(
        parameters=parameters, description=valid_template.get('Description', '')
    )
    return resp


def get_template_body(req_data):
    body = req_data.get('TemplateBody')
    if body:
        return body
    url = req_data.get('TemplateURL')
    if url:
        response = run_safe(lambda: safe_requests.get(url, verify=False))
        # check error codes, and code 301 - fixes https://github.com/localstack/localstack/issues/1884
        status_code = 0 if response is None else response.status_code
        if response is None or status_code == 301 or status_code >= 400:
            # check if this is an S3 URL, then get the file directly from there
            url = convert_s3_to_local_url(url)
            if is_local_service_url(url):
                parsed_path = urlparse.urlparse(url).path.lstrip('/')
                parts = parsed_path.partition('/')
                client = aws_stack.connect_to_service('s3')
                LOG.debug('Download CloudFormation template content from local S3: %s - %s' % (parts[0], parts[2]))
                result = client.get_object(Bucket=parts[0], Key=parts[2])
                body = to_str(result['Body'].read())
                return body
            raise Exception('Unable to fetch template body (code %s) from URL %s' % (status_code, url))
        return response.content
    raise Exception('Unable to get template body from input: %s' % req_data)


def parse_template(template):
    try:
        return json.loads(template)
    except Exception:
        yaml.add_multi_constructor('', moto.cloudformation.utils.yaml_tag_constructor, Loader=NoDatesSafeLoader)
        try:
            return clone_safe(yaml.safe_load(template))
        except Exception:
            return clone_safe(yaml.load(template, Loader=NoDatesSafeLoader))


def template_to_json(template):
    template = parse_template(template)
    return json.dumps(template)


def is_local_service_url(url):
    candidates = ('localhost', config.LOCALSTACK_HOSTNAME, config.HOSTNAME_EXTERNAL, config.HOSTNAME)
    return url and any('://%s:' % host in url for host in candidates)


def is_real_s3_url(url):
    return re.match(r'.*s3(\-website)?\.([^\.]+\.)?amazonaws.com.*', url or '')


def convert_s3_to_local_url(url):
    if not is_real_s3_url(url):
        return url
    url_parsed = urlparse.urlparse(url)
    path = url_parsed.path
    bucket_name, _, key = path.lstrip('/').replace('//', '/').partition('/')
    # note: make sure to normalize the bucket name here!
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    local_url = '%s/%s/%s' % (config.TEST_S3_URL, bucket_name, key)
    return local_url
