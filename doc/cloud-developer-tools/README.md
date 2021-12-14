# LocalStack Cloud Developer Tools

LocalStack provides a number of tools that are designed to make local testing and development of cloud applications easier and more efficient.

## Hot-deploying Lambda code

Instead of re-deploying a Lambda every time your code changes, you can mount the source folder of your lambda directly. First, ensure that `LAMBDA_REMOTE_DOCKER` is set to `false`.
Then, set the S3 bucket name to `__local__` or `BUCKET_MARKER_LOCAL` if it is set, and the S3 key to your local source folder path:

```shell
awslocal lambda create-function --function-name myLambda \
    --code S3Bucket="__local__",S3Key="/my/local/lambda/folder" \
    --handler index.myHandler \
    --runtime nodejs8.10 \
    --role whatever
```

## Custom API Gateway IDs

To provide custom IDs for API Gateway REST API, you can specify `tags={"_custom_id_":"myid123"}` on creation of an API Gateway REST API, to assign it the custom ID `"myid123"` (can be useful to have a static API GW endpoint URL for testing).

**Note:** When using `LAMBDA_REMOTE_DOCKER=false`, make sure to properly set the `HOST_TMP_FOLDER` environment variable for the LocalStack container (see Configuration section above).
