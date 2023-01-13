package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.ListQueuesRequest;



import java.net.URI;
import java.util.*;

public class Handler implements RequestHandler<Map<String, String>, String> {

    private SqsClient getSqsClient() {
        if (Objects.equals(System.getenv("CONFIGURE_CLIENT"), "1")) {
            String endpointUrl = "http://" + System.getenv("LOCALSTACK_HOSTNAME") + ":" + System.getenv("EDGE_PORT");
            URI uri = URI.create(endpointUrl);
            return SqsClient.builder()
                    .region(Region.US_EAST_1)
                    .endpointOverride(uri)
                    .build();
        } else {
            return SqsClient.builder().region(Region.US_EAST_1).build();
        }
    }


    public String handleRequest(Map<String, String> event, Context context) {
        try (
                SqsClient sqsClient = this.getSqsClient()
        ) {
            sqsClient.listQueues(ListQueuesRequest.builder().build());
        }

        return "ok";
    }
}
