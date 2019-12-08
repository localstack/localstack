package cloud.localstack.docker;

import cloud.localstack.Localstack;
import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.TestUtils;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.junit.Assert;
import org.junit.Test;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;

@RunWith(LocalstackTestRunner.class)
@ExtendWith(LocalstackDockerExtension.class)
@LocalstackDockerProperties(randomizePorts = false, services = { "sqs:12345" })
public class PortBindingTest {

    @Test
    public void testAccessPredefinedPort() {
        String endpoint = Localstack.INSTANCE.endpointForPort(12345);
        AmazonSQS amazonSQS = TestUtils.getClientSQS(endpoint);
        String url = amazonSQS.createQueue("test-queue").getQueueUrl();
        Assert.assertTrue(url.contains("://localhost:12345/queue/test-queue"));
    }

}
