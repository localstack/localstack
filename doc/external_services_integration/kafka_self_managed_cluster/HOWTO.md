## Using Localstack lambda with self-managed kafka cluster

This is a guide to use your own custom Kafka cluster endpoint, please note this is not a how-to configure or setup Kafka, to do that refer to the [official documentation](https://kafka.apache.org/documentation/)

## Why is this useful?

Localstack OSS does not currently support AWS MSK out of the box, but you can run your own self-managed kafka cluster and integrate it with your own applications.

## How to run it?

You can find the [example docker compose](docker-compose.yml) file which contains a single-noded zookeeper and kafka cluster and a simple localstack setup as well as [kowl](https://github.com/cloudhut/kowl), an Apache Kafka Web UI.

1. Run docker compose:
```
$ docker-compose up -d
```

2. Create the lambda function:
```
$ awslocal lambda create-function \
    --function-name fun1 \
    --handler lambda.handler \
    --runtime python3.8 \
    --role r1 \
    --zip-file fileb://lambda.zip
{
    "FunctionName": "fun1",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:fun1",
    "Runtime": "python3.8",
    "Role": "r1",
    "Handler": "lambda.handler",
    "CodeSize": 294,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-05-19T02:01:06.617+0000",
    "CodeSha256": "/GPsiNXaq4tBA4QpxPCwgpeVfP7j+1tTH6zdkJ3jiU4=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "d85469d2-8558-4d75-bc0e-5926f373e12c",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

3. Create an example secret:
```
$ awslocal secretsmanager create-secret --name localstack
{
    "ARN": "arn:aws:secretsmanager:us-east-1:000000000000:secret:localstack-TDIuI",
    "Name": "localstack",
    "VersionId": "32bbb8e2-46ee-4322-b3d5-b6459d54513b"
}
```

4. Create an example kafka topic:
```
$ docker exec -ti kafka kafka-topics --zookeeper zookeeper:2181 --create --replication-factor 1 --partitions 1 --topic t1
Created topic t1.
```

5. Create the event source mapping to your local kafka cluster:
```
$ awslocal lambda create-event-source-mapping \
    --topics t1 \
    --source-access-configuration Type=SASL_SCRAM_512_AUTH,URI=arn:aws:secretsmanager:us-east-1:000000000000:secret:localstack-TDIuI \
    --function-name arn:aws:lambda:us-east-1:000000000000:function:fun1 \
    --self-managed-event-source '{"Endpoints":{"KAFKA_BOOTSTRAP_SERVERS":["localhost:9092"]}}'
{
    "UUID": "4a2b0ea6-960c-4847-8684-465876dd6dbd",
    "BatchSize": 100,
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:fun1",
    "LastModified": "2021-05-19T04:02:49+02:00",
    "LastProcessingResult": "OK",
    "State": "Enabled",
    "StateTransitionReason": "User action",
    "Topics": [
        "t1"
    ],
    "SourceAccessConfigurations": [
        {
            "Type": "SASL_SCRAM_512_AUTH",
            "URI": "arn:aws:secretsmanager:us-east-1:000000000000:secret:localstack-TDIuI"
        }
    ],
    "SelfManagedEventSource": {
        "Endpoints": {
            "KAFKA_BOOTSTRAP_SERVERS": [
                "localhost:9092"
            ]
        }
    }
}
```

6. Aditionally check `http://localhost:8080` for kowl's UI.