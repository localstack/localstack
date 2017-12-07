package cloud.localstack;

import static cloud.localstack.TestUtils.getCredentialsProvider;
import static cloud.localstack.TestUtils.getEndpointConfiguration;

import java.util.function.Supplier;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;

import cloud.localstack.docker.LocalstackDockerTestRunner;

public class DockerTestUtils {


    public static AmazonSQS getClientSQS() {
        return AmazonSQSClientBuilder.standard().
                withEndpointConfiguration(createEndpointConfiguration(LocalstackDockerTestRunner::getEndpointSQS)).
                withCredentials(getCredentialsProvider()).build();
    }


    public static AWSLambda getClientLambda() {
        return AWSLambdaClientBuilder.standard().
                withEndpointConfiguration(createEndpointConfiguration(LocalstackDockerTestRunner::getEndpointLambda)).
                withCredentials(getCredentialsProvider()).build();
    }


    public static AmazonS3 getClientS3() {
        AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDockerTestRunner::getEndpointS3))
                .withCredentials(getCredentialsProvider());
        builder.setPathStyleAccessEnabled(true);
        return builder.build();
    }


    public static AmazonKinesis getClientKinesis() {
        return AmazonKinesisClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDockerTestRunner::getEndpointKinesis))
                .withCredentials(getCredentialsProvider()).build();
    }


    public static AmazonDynamoDB getClientDynamoDb() {
        return AmazonDynamoDBClientBuilder.standard()
                .withEndpointConfiguration(createEndpointConfiguration(LocalstackDockerTestRunner::getEndpointDynamoDB))
                .withCredentials(getCredentialsProvider()).build();
    }


    private static AwsClientBuilder.EndpointConfiguration createEndpointConfiguration(Supplier<String> supplier) {
        return getEndpointConfiguration(supplier.get());
    }
}
