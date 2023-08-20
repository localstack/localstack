package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.ListQueuesRequest;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;



import java.net.URI;
import java.util.*;

public class Handler implements RequestHandler<Map<String, String>, String> {

    private AmazonSQS getSqsClient() {
        if (Objects.equals(System.getenv("CONFIGURE_CLIENT"), "1")) {
            String endpointUrl = "http://" + System.getenv("LOCALSTACK_HOSTNAME") + ":" + System.getenv("EDGE_PORT");
            return AmazonSQSClientBuilder.standard()
                                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(endpointUrl, "us-east-1"))
                                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("test", "test")))
                                .build();
        } else {
            return AmazonSQSClientBuilder.standard()
                               .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("test", "test")))
                               .withRegion(Regions.US_EAST_1)
                               .build();
        }
    }

    public String handleRequest(Map<String, String> event, Context context) {
        System.out.println("my ssl property" + System.getProperty("com.amazonaws.sdk.disableCertChecking"));
        this.getSqsClient().listQueues(new ListQueuesRequest());

        return "ok";
    }
}
