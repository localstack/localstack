package cloud.localstack.docker;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class ContainerTest {

    private static final String EXTERNAL_HOST_NAME = "localhost";
    private static final String MY_PROPERTY = "MY_PROPERTY";
    private static final String MY_VALUE = "MyValue";

    @Test
    public void createLocalstackContainer() throws Exception {

        HashMap<String, String> environmentVariables = new HashMap<>();
        environmentVariables.put(MY_PROPERTY, MY_VALUE);
        Container localStackContainer = Container.createLocalstackContainer(EXTERNAL_HOST_NAME, true, true, environmentVariables);

        try {
            localStackContainer.waitForAllPorts(EXTERNAL_HOST_NAME);

            // Test that environment variables are actually loaded

            ArrayList<String> echoDefaultEnv = buildEchoStatement(Container.LOCALSTACK_EXTERNAL_HOSTNAME);
            ArrayList<String> echoExternalEnv = buildEchoStatement(MY_PROPERTY);
            assertEquals(EXTERNAL_HOST_NAME, localStackContainer.executeCommand(echoDefaultEnv));
            assertEquals(MY_VALUE, localStackContainer.executeCommand(echoExternalEnv));
        }
        finally {
            localStackContainer.stop();
        }
    }

    private ArrayList<String> buildEchoStatement(String valueToEcho) {
        ArrayList<String> args = new ArrayList<>();
        args.add("bash");
        args.add("-c");
        args.add(String.format("echo $%s", valueToEcho));
        return args;
    }


    @Test
    public void createLocalstackContainerWithRandomPorts() throws Exception {
        Container container = Container.createLocalstackContainer(EXTERNAL_HOST_NAME, true, true, new HashMap<>());

        try {
            container.waitForAllPorts(EXTERNAL_HOST_NAME);

            assertNotEquals(4567, container.getExternalPortFor(4567));
            assertNotEquals(4575, container.getExternalPortFor(4575));
            assertNotEquals(4583, container.getExternalPortFor(4583));
        }
        finally {
            container.stop();
        }
    }


    @Test
    public void createLocalstackContainerWithStaticPorts() throws Exception {
        Container container = Container.createLocalstackContainer(EXTERNAL_HOST_NAME, true, false, new HashMap<>());

        try {
            container.waitForAllPorts(EXTERNAL_HOST_NAME);

            assertEquals(4567, container.getExternalPortFor(4567));
            assertEquals(4575, container.getExternalPortFor(4575));
            assertEquals(4583, container.getExternalPortFor(4583));
        }
        finally {
            container.stop();
        }
    }

}