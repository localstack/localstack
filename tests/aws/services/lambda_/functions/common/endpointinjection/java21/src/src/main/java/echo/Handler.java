package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
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
        // Test only the Java AWS SDK v2 clients because v1 is not shipped by default in the Java runtimes >=java17

        // v2 synchronous: test both apache and urlconnection http clients to ensure both are instrumented
        ListQueuesResponse response = this.getSqsClient().listQueues();
        System.out.println(response.queueUrls().toString());
        response = this.getUrlConnectionSqsClient().listQueues();
        System.out.println(response.queueUrls().toString());

         // v2 asynchronous: test both CRT and netty http client
         Future<ListQueuesResponse> listQueuesFutureCrt = this.getAsyncCRTSqsClient().listQueues();
         Future<ListQueuesResponse> listQueuesFutureNetty = this.getAsyncNettySqsClient().listQueues();
         try {
             System.out.println(listQueuesFutureCrt.get());
             System.out.println(listQueuesFutureNetty.get());
         } catch (InterruptedException | ExecutionException e) {
             throw new RuntimeException(e);
         }

        return "ok";
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
        if (Objects.equals(System.getenv("CONFIGURE_CLIENT"), "1")) {
            String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
            // Choosing a specific endpoint
            // https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/region-selection.html
            return SqsClient.builder()
                    .endpointOverride(URI.create(endpointUrl));
        } else {
            return SqsClient.builder();
        }
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
        if (Objects.equals(System.getenv("CONFIGURE_CLIENT"), "1")) {
            String endpointUrl = System.getenv("AWS_ENDPOINT_URL");
            return SqsAsyncClient.builder()
                    .endpointOverride(URI.create(endpointUrl));
        } else {
            return SqsAsyncClient.builder();
        }
    }
}
