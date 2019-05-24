package cloud.localstack.docker;

import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import org.junit.Assert;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(LocalstackDockerExtension.class)
@LocalstackDockerProperties(randomizePorts = true, services = "sqs")
public class Junit5NestedTest {

    @Nested
    class NestedClass {

        @Test
        public void ShouldNotStartNewContainerInNestedTest() {
            // This should not trigger an error by calling the beforeAll twice
            Assert.assertTrue(true);
        }
    }
}
