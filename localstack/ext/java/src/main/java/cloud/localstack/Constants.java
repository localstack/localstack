package cloud.localstack;

import java.util.HashMap;
import java.util.Map;

public class Constants {
    public static final Map<String, Integer> DEFAULT_PORTS = new HashMap<>();

    static {
        DEFAULT_PORTS.put("apigateway", 4567);
        DEFAULT_PORTS.put("kinesis", 4568);
        DEFAULT_PORTS.put("dynamodb", 4569);
        DEFAULT_PORTS.put("dynamodbstreams", 4570);
        DEFAULT_PORTS.put("s3", 4572);
        DEFAULT_PORTS.put("firehose", 4573);
        DEFAULT_PORTS.put("lambda", 4574);
        DEFAULT_PORTS.put("sns", 4575);
        DEFAULT_PORTS.put("sqs", 4576);
        DEFAULT_PORTS.put("redshift", 4577);
        DEFAULT_PORTS.put("es", 4578);
        DEFAULT_PORTS.put("ses", 4579);
        DEFAULT_PORTS.put("route53", 4580);
        DEFAULT_PORTS.put("cloudformation", 4581);
        DEFAULT_PORTS.put("cloudwatch", 4582);
        DEFAULT_PORTS.put("ssm", 4583);
        DEFAULT_PORTS.put("secretsmanager", 4584);
        DEFAULT_PORTS.put("stepfunctions", 4585);
        DEFAULT_PORTS.put("logs", 4586);
        DEFAULT_PORTS.put("events", 4587);
        DEFAULT_PORTS.put("sts", 4592);
        DEFAULT_PORTS.put("iam", 4593);
        DEFAULT_PORTS.put("ec2", 4597);
        DEFAULT_PORTS.put("kms", 4599);
    }
}
