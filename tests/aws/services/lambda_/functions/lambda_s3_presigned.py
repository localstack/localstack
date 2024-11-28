import os
import json
import boto3
import urllib3

http = urllib3.PoolManager()


def handler(event, context):
    presigned_url = event['url']

    response_body = {
        **event['data']
    }

    json_response_body = json.dumps(response_body)

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    http.request('PUT', presigned_url, headers=headers, body=json_response_body)

    return {"statusCode": 200}
