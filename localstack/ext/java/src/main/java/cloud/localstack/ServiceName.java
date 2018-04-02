package cloud.localstack;

import java.util.HashMap;
import java.util.Map;

public class ServiceName {
    public static final String API_GATEWAY = "apigateway";
    public static final String KINESIS = "kinesis";
    public static final String DYNAMO = "dynamodb";
    public static final String DYNAMO_STREAMS = "dynamodbstreams";
    public static final String ELASTICSEARCH = "elasticsearch";
    public static final String S3 = "s3";
    public static final String FIREHOSE = "firehose";
    public static final String LAMBDA = "lambda";
    public static final String SNS = "sns";
    public static final String SQS = "sqs";
    public static final String REDSHIFT = "redshift";
    public static final String ELASTICSEARCH_SERVICE = "es";
    public static final String SES = "ses";
    public static final String ROUTE53 = "route53";
    public static final String CLOUDFORMATION = "cloudformation";
    public static final String CLOUDWATCH = "cloudwatch";
    public static final String SSM = "ssm";

    private static Map<String, String> serviceMap = new HashMap<>();
    public static String getServiceUrl(String service) {
        return serviceMap.get(service);
    }

    static {
        serviceMap.put(API_GATEWAY, "http://localhost:4567");
        serviceMap.put(KINESIS, "http://localhost:4568");
        serviceMap.put(DYNAMO, "http://localhost:4569");
        serviceMap.put(DYNAMO_STREAMS, "http://localhost:4570");
        serviceMap.put(ELASTICSEARCH, "http://localhost:4571");
        serviceMap.put(S3, "http://localhost:4572");
        serviceMap.put(FIREHOSE, "http://localhost:4573");
        serviceMap.put(LAMBDA, "http://localhost:4574");
        serviceMap.put(SNS, "http://localhost:4575");
        serviceMap.put(SQS, "http://localhost:4576");
        serviceMap.put(REDSHIFT, "http://localhost:4577");
        serviceMap.put(ELASTICSEARCH_SERVICE, "http://localhost:4578");
        serviceMap.put(SES, "http://localhost:4579");
        serviceMap.put(ROUTE53, "http://localhost:4580");
        serviceMap.put(CLOUDFORMATION, "http://localhost:4581");
        serviceMap.put(CLOUDWATCH, "http://localhost:4582");
        serviceMap.put(SSM, "http://localhost:4583");
    }

}
