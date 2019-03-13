package cloud.localstack;

import static cloud.localstack.TestUtils.getCredentialsProvider;
import static cloud.localstack.TestUtils.getEndpointConfiguration;

import java.util.function.Supplier;

import cloud.localstack.docker.LocalstackDocker;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.AmazonCloudFormationClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBStreams;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBStreamsClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.kinesisfirehose.AmazonKinesisFirehose;
import com.amazonaws.services.kinesisfirehose.AmazonKinesisFirehoseClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.stepfunctions.AWSStepFunctions;
import com.amazonaws.services.stepfunctions.AWSStepFunctionsClientBuilder;

import cloud.localstack.docker.LocalstackDockerTestRunner;

public class DockerTestUtils {

    public static AmazonSQS getClientSQS() {
        return AmazonSQSClientBuilder.standard().
                withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointSQS)).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonSNS getClientSNS() {
        return AmazonSNSClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointSNS))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AWSLambda getClientLambda() {
        return AWSLambdaClientBuilder.standard().
                withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointLambda)).
                withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonS3 getClientS3() {
        AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointS3))
                .withCredentials(getCredentialsProvider());
        builder.setPathStyleAccessEnabled(true);
        return builder.build();
    }

    public static AWSSecretsManager getClientSecretsManager() {
        return AWSSecretsManagerClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointSecretsmanager))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonKinesis getClientKinesis() {
        return AmazonKinesisClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointKinesis))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonDynamoDB getClientDynamoDb() {
        return AmazonDynamoDBClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointDynamoDB))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonCloudWatch getClientCloudWatch() {
        return AmazonCloudWatchClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointCloudWatch))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonKinesisFirehose getClientFirehose() {
        return AmazonKinesisFirehoseClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointFirehose))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonDynamoDBStreams getClientDynamoDbStreams() {
        return AmazonDynamoDBStreamsClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointDynamoDBStreams))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AmazonCloudFormation getClientCloudFormation() {
        return AmazonCloudFormationClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointCloudFormation))
                .withCredentials(getCredentialsProvider()).build();
    }

    public static AWSStepFunctions getClientStepFunctions() {
        return AWSStepFunctionsClientBuilder.standard()
          .withEndpointConfiguration(createEndpointConfiguration(LocalstackDocker.INSTANCE::getEndpointStepFunctions))
          .withCredentials(getCredentialsProvider()).build();
    }

    private static AwsClientBuilder.EndpointConfiguration createEndpointConfiguration(Supplier<String> supplier) {
        return getEndpointConfiguration(supplier.get());
    }
}
