import json
from requests.models import Request
from localstack.utils.common import to_str
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

            data = json.dumps(data)
            if data != data_orig:
                return Request(data=data, headers=headers, method=method)

        return True


# instantiate listener
UPDATE_SSM = ProxyListenerSSM()
