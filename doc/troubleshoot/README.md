# Troubleshoot

* If you're using AWS Java libraries with Kinesis, please, refer to [CBOR protocol issues with the Java SDK guide](https://github.com/mhart/kinesalite#cbor-protocol-issues-with-the-java-sdk) how to disable CBOR protocol which is not supported by kinesalite.

* Accessing local S3: To avoid domain name resolution issues, you need to enable **path style access** on your S3 SDK client. Most AWS SDKs provide a config to achieve that, e.g., for Java:

```shell
s3.setS3ClientOptions(S3ClientOptions.builder().setPathStyleAccess(true).build());
// There is also an option to do this if you're using any of the client builder classes:
AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
builder.withPathStyleAccessEnabled(true);
...
```

* Mounting the temp. directory: Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR docker-compose up` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.
(See details here: https://bitbucket.org/atlassian/localstack/issues/40/getting-mounts-failed-on-docker-compose-up)

* If you're seeing Lambda errors like `Cannot find module ...` when using `LAMBDA_REMOTE_DOCKER=false`, make sure to properly set the `HOST_TMP_FOLDER` environment variable and mount the temporary folder from the host into the LocalStack container.

* If you run into file permission issues on `pip install` under Mac OS (e.g., `Permission denied: '/Library/Python/2.7/site-packages/six.py'`), then you may have to re-install `pip` via Homebrew (see [this discussion thread](https://github.com/localstack/localstack/issues/260#issuecomment-334458631)). Alternatively, try installing
with the `--user` flag: `pip install --user localstack`

* If you are deploying within OpenShift, please be aware: the pod must run as `root`, and the user must have capabilities added to the running pod, in order to allow Elasticsearch to be run as the non-root `localstack` user.

* If you are experiencing slow performance with Lambdas in Mac OS, you could either (1) try [mounting local code directly into the Lambda container](https://github.com/localstack/localstack#using-local-code-with-lambda), or (2) disable mounting the temporary directory into the LocalStack container in docker-compose. (See also https://github.com/localstack/localstack/issues/2515)

* The environment variable `no_proxy` is rewritten by LocalStack. (Internal requests will go straight via localhost, bypassing any proxy configuration).

* For troubleshooting LocalStack start issues, you can check debug logs by running `DEBUG=1 localstack start`

* In case you get errors related to node/nodejs, you may find (this issue comment: https://github.com/localstack/localstack/issues/227#issuecomment-319938530) helpful.

* If you are using AWS Java libraries and need to disable SSL certificate checking, add `-Dcom.amazonaws.sdk.disableCertChecking` to the java invocation.

* If you are using LAMBDA_REMOTE_DOCKER=true and running in a docker container in CI, do NOT set `DOCKER_HOST` as an environment variable passed into the localstack container. Any calls to lambda CLI operations will fail (https://github.com/localstack/localstack/issues/4801)
