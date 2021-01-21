import json
import time
from requests.models import Request
from localstack.utils.common import to_str
from localstack.utils.aws import aws_stack
from localstack.utils.persistence import PersistingProxyListener

ACTION_PUT_PARAM = 'AmazonSSM.PutParameter'
ACTION_GET_PARAM = 'AmazonSSM.GetParameter'
ACTION_GET_PARAMS = 'AmazonSSM.GetParameters'


def normalize_name(param_name):
    param_name = param_name.strip('/')
    param_name = param_name.replace('//', '/')
    if '/' in param_name:
        param_name = '/%s' % param_name
    return param_name


def get_secrets_information(name, resource_name):
    client = aws_stack.connect_to_service('secretsmanager')
    try:
        secret_info = client.get_secret_value(SecretId=resource_name)
        del secret_info['ResponseMetadata']
        created_date_timestamp = time.mktime(secret_info['CreatedDate'].timetuple())
        secret_info['CreatedDate'] = created_date_timestamp
        result = {'Parameter': {'SourceResult': secret_info, 'Name': name, 'Value':
                secret_info.get('SecretString'), 'Type': 'SecureString',
                            'LastModifiedDate': created_date_timestamp}}
        return result
    except client.exceptions.ResourceNotFoundException:
        return None


def has_secrets(names):
    for name in names:
        if name.startswith('/aws/reference/secretsmanager'):
            return True


def get_params_and_secrets(names):
    ssm_client = aws_stack.connect_to_service('ssm')
    result = {'Parameters': [], 'InvalidParameters': []}
    secrets_prefix = '/aws/reference/secretsmanager'

    for name in names:
        if name.startswith(secrets_prefix):
            secret = get_secrets_information(name, name[len(secrets_prefix) + 1:])
            if secret is not None:
                secret = secret['Parameter']
                result['Parameters'].append(secret)
            else:
                result['InvalidParameters'].append(name)
        else:
            try:
                param = ssm_client.get_parameter(Name=name)
                param['Parameter']['LastModifiedDate'] = time.mktime(param['Parameter']['LastModifiedDate'].timetuple())
                result['Parameters'].append(param['Parameter'])
            except ssm_client.exceptions.ParameterNotFound:
                result['InvalidParameters'].append(name)

    return result


class ProxyListenerSSM(PersistingProxyListener):
    def api_name(self):
        return 'ssm'

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        target = headers.get('X-Amz-Target')
        data_orig = data

        if method == 'POST' and target:
            data = json.loads(to_str(data))

            if target == ACTION_GET_PARAMS:
                names = data['Names'] = data.get('Names') or []
                if has_secrets(names):
                    return get_params_and_secrets(names)
                else:
                    for i in range(len(names)):
                        names[i] = normalize_name(names[i])
            elif target in [ACTION_PUT_PARAM, ACTION_GET_PARAM]:
                name = data.get('Name') or ''
                data['Name'] = normalize_name(name)

                if target == ACTION_GET_PARAM:
                    details = name.split('/')

                    if len(details) > 4:
                        service = details[3]

                        if service == 'secretsmanager':
                            resource_name = '/'.join(details[4:])
                            secret = get_secrets_information(name, resource_name)
                            if secret is not None:
                                return secret

            data = json.dumps(data)
            if data != data_orig:
                return Request(data=data, headers=headers, method=method)

        return True


# instantiate listener
UPDATE_SSM = ProxyListenerSSM()
