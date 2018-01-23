package cloud.localstack.docker;

import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class ContainerTest {

    @Test
    public void createLocalstackContainer() throws Exception {

        String externalHostName = "localhost";
        Container localStackContainer = Container.createLocalstackContainer(externalHostName);

        try {
            localStackContainer.waitForAllPorts(externalHostName);

            // Test that environment variables are actually loaded
            ArrayList<String> args = new ArrayList<>();
            args.add("bash");
            args.add("-c");
            args.add(String.format("echo $%s", Container.LOCALSTACK_EXTERNAL_HOSTNAME));

            assertEquals(externalHostName, localStackContainer.executeCommand(args));
        }
        finally {
            localStackContainer.stop();
        }

    }

}