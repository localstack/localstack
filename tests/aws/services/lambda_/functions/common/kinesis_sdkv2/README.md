## Java Lambda with AWS SDK v2  -> Kinesis

This lambda function is used to ensure the compatibility of Kinesis with the Java AWS SDK v2,
especially the CBOR content encoding (which is enabled by default).

This Lambda is not directly being used for the multi-runtime lambda tests, but it is here in this folder in order to
benefit from the caching mechanisms in CI.
The JAR file is too big to be directly commited to the Git repo (~10MB).

Initially introduced with https://github.com/localstack/localstack/pull/11286.
