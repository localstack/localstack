from localstack.services.generic_proxy import ProxyListener


class ProxyListenerCloudWatch(ProxyListener):

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect response content-type header from cloudwatch logs #1343
        print('Deepak')
        print(response.content)
        if 'nextToken' in response.content:
            response.headers['content-length'] = str(len(response._content))


# instantiate listener
UPDATE_CLOUD_WATCH = ProxyListenerCloudWatch()
