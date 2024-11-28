import urllib3

http = urllib3.PoolManager()


def handler(event, context):
    presigned_url = event["url"]

    body = event["data"]

    headers = {"content-type": "", "content-length": str(len(body))}

    http.request("PUT", presigned_url, headers=headers, body=body)

    return {"statusCode": 200}
