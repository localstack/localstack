import json
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
    secret_info = client.get_secret_value(SecretId=resource_name)
    del secret_info['ResponseMetadata']

    result = {'Parameter': {'SourceResult': secret_info, 'Name': name, 'Value':
              secret_info.get('SecretString'), 'Type': 'SecureString',
                            'LastModifiedDate': secret_info.get('CreatedDate')}}

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
                for i in range(len(names)):
                    names[i] = normalize_name(names[i])
            elif target in [ACTION_PUT_PARAM, ACTION_GET_PARAM]:
                name = data.get('Name') or ''
                data['Name'] = normalize_name(name)

                if target == ACTION_GET_PARAM:
                    details = name.split('/')

                    if len(details) > 4:
                        service = details[3]
                        resource_name = details[4]

                        if service == 'secretsmanager':
                            return get_secrets_information(name, resource_name)

            data = json.dumps(data)
            if data != data_orig:
                return Request(data=data, headers=headers, method=method)

        return True


# instantiate listener
UPDATE_SSM = ProxyListenerSSM()
