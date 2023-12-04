package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.ListQueuesRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
// v2
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.SqsClientBuilder;
import software.amazon.awssdk.services.sqs.SqsAsyncClientBuilder;
import software.amazon.awssdk.services.sqs.model.ListQueuesResponse;

import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;


public class Handler implements RequestHandler<Map<String, String>, String> {

    public String handleRequest(Map<String, String> event, Context context) {
        // Inspect ssl property for the Java AWS SDK v1 client. Removed in v2.
        System.out.println("com.amazonaws.sdk.disableCertChecking=" + System.getProperty("com.amazonaws.sdk.disableCertChecking"));

        // v1
        ListQueuesResult responseV1 = this.getSqsClientV1().listQueues(new ListQueuesRequest());
        System.out.println("QueueUrls (SDK v1)=" + responseV1.getQueueUrls().toString());

        // v2 synchronous: test both apache and urlconnection http clients to ensure both are instrumented
        ListQueuesResponse response = this.getSqsClient().listQueues();
        System.out.println("QueueUrls (SDK v2 sync SQS)=" + response.queueUrls().toString());
        response = this.getUrlConnectionSqsClient().listQueues();
        System.out.println("QueueUrls (SDK v2 sync Url)=" + response.queueUrls().toString());

        // v2 asynchronous: test both CRT and netty http client
        Future<ListQueuesResponse> listQueuesFutureCrt = this.getAsyncCRTSqsClient().listQueues();
        Future<ListQueuesResponse> listQueuesFutureNetty = this.getAsyncNettySqsClient().listQueues();
        try {
            System.out.println("QueueUrls (SDK v2 async Crt)=" + listQueuesFutureCrt.get());
            System.out.println("QueueUrls (SDK v2 async Netty)=" + listQueuesFutureNetty.get());
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }

        return "ok";
    }

    private AmazonSQS getSqsClientV1() {
        String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
        String region = System.getenv("AWS_REGION");
        if (endpointUrl != null) {
            return AmazonSQSClientBuilder.standard()
                    .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(endpointUrl, region))
                    .build();
        }
        return AmazonSQSClientBuilder.standard().build();
    }

    private SqsClient getSqsClient() {
        return this.getSqsClientBuilder()
                .httpClient(ApacheHttpClient.builder().build())
                .build();
    }

    private SqsClient getUrlConnectionSqsClient() {
        return this.getSqsClientBuilder()
                .httpClient(UrlConnectionHttpClient.builder().socketTimeout(Duration.ofMinutes(5)).build())
                .build();
    }

    private SqsClientBuilder getSqsClientBuilder() {
        String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
        if (endpointUrl != null) {
            // Choosing a specific endpoint
            // https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/region-selection.html
            return SqsClient.builder()
                    .endpointOverride(URI.create(endpointUrl));
        }
        return SqsClient.builder();
    }

    private SqsAsyncClient getAsyncCRTSqsClient() {
        return this.getSqsAsyncClientBuilder()
                .httpClientBuilder(AwsCrtAsyncHttpClient
                        .builder()
                        .connectionTimeout(Duration.ofSeconds(3))
                        .maxConcurrency(10))
                .build();
    }

    private SqsAsyncClient getAsyncNettySqsClient() {
        return this.getSqsAsyncClientBuilder()
                .httpClientBuilder(NettyNioAsyncHttpClient
                        .builder()
                        .connectionTimeout(Duration.ofSeconds(3))
                        .maxConcurrency(10))
                .build();
    }

    private SqsAsyncClientBuilder getSqsAsyncClientBuilder() {
        String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
        if (endpointUrl != null) {
            return SqsAsyncClient.builder()
                    .endpointOverride(URI.create(endpointUrl));
        }
        return SqsAsyncClient.builder();
    }
}
