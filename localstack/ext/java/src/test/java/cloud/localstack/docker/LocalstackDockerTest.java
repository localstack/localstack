package cloud.localstack.docker;

import cloud.localstack.DockerTestUtils;
import cloud.localstack.docker.annotation.LocalstackDockerConfiguration;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageResult;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;

import static org.junit.Assert.assertNotNull;

public class LocalstackDockerTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void startup() {
        LocalstackDocker localstackDocker = LocalstackDocker.INSTANCE;
        LocalstackDocker.INSTANCE.startup(new LocalstackDockerConfiguration(
                false,
                true,
                "localhost",
                Collections.emptyMap()

        ));

        AmazonSQS amazonSQS = DockerTestUtils.getClientSQS();
        String queueUrl = amazonSQS.createQueue("test-queue").getQueueUrl();

        SendMessageResult sendMessageResult = amazonSQS.sendMessage(queueUrl, "test-message");
        assertNotNull(sendMessageResult);

        String messageId = sendMessageResult.getMessageId();
        assertNotNull(messageId);

        thrown.expect(IllegalStateException.class);

        LocalstackDocker.INSTANCE.startup(new LocalstackDockerConfiguration(
                false,
                true,
                "localhost",
                Collections.emptyMap()

        ));
        localstackDocker.stop();
    }

    @Test
    public void stop() {
        LocalstackDocker.INSTANCE.startup(new LocalstackDockerConfiguration(
                false,
                true,
                "localhost",
                Collections.emptyMap()

        ));
        LocalstackDocker.INSTANCE.stop();

        AmazonSQS amazonSQS = DockerTestUtils.getClientSQS();
        thrown.expect(SdkClientException.class);
        amazonSQS.createQueue("test-queue").getQueueUrl();
    }

    @After
    public void tearDown() {
        LocalstackDocker.INSTANCE.stop();
    }
}