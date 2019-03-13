package cloud.localstack;

import cloud.localstack.utils.PromiseAsyncHandler;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSAsync;
import com.amazonaws.services.sns.model.CreateTopicRequest;
import com.amazonaws.services.sns.model.CreateTopicResult;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.jms.JMSException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Test integration of SNS messaging with LocalStack
 */
@RunWith(LocalstackTestRunner.class)
public class SNSMessagingTest {
    private static final String TOPIC = "topic";

    @Test
    public void testSendMessage() throws JMSException {
        final AmazonSNS clientSNS = TestUtils.getClientSNS();
        final CreateTopicResult createTopicResult = clientSNS.createTopic(TOPIC);
        final PublishResult publishResult = clientSNS.publish(createTopicResult.getTopicArn(), "message");
        Assert.assertNotNull(publishResult);
    }

    @Test
    public void testSendMessageAsync() throws Exception {
        final AmazonSNSAsync clientSNSAsync = TestUtils.getClientSNSAsync();
        final PromiseAsyncHandler<CreateTopicRequest, CreateTopicResult> createTopicPromise = new PromiseAsyncHandler<>();
        clientSNSAsync.createTopicAsync(TOPIC, createTopicPromise);

        final CompletableFuture<PublishResult> publishResult = createTopicPromise.thenCompose(createTopicResult -> {
            final PromiseAsyncHandler<PublishRequest, PublishResult> publishPromise = new PromiseAsyncHandler<>();
            clientSNSAsync.publishAsync(createTopicResult.getTopicArn(), "message", publishPromise);
            return publishPromise;
        });

        final PublishResult result = publishResult.get(3, TimeUnit.SECONDS);
        Assert.assertNotNull(result);
    }

}