package cloud.localstack.docker;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import cloud.localstack.docker.command.ExecCommand;
import cloud.localstack.docker.command.LogCommand;
import cloud.localstack.docker.command.PortCommand;
import cloud.localstack.docker.command.PullCommand;
import cloud.localstack.docker.command.RunCommand;
import cloud.localstack.docker.command.StopCommand;

/**
 * An abstraction of the localstack docker container.  Provides port mappings,
 * a way to poll the logs until a specified token appears, and the ability to stop the container
 */
public class Container {

    private static final Logger LOG = Logger.getLogger(Container.class.getName());

    private static final String LOCALSTACK_NAME = "localstack/localstack";
    private static final String LOCALSTACK_PORTS = "4567-4583";
    private static final String LOCALSTACK_EXTERNAL_HOSTNAME = "HOSTNAME_EXTERNAL";

    private static final int MAX_PORT_CONNECTION_ATTEMPTS = 10;

    private static final int MAX_LOG_COLLECTION_ATTEMPTS = 120;
    private static final long POLL_INTERVAL = 1000;
    private static final int NUM_LOG_LINES = 10;


    private final String containerId;
    private final List<PortMapping> ports;


    public static Container createLocalstackContainer(String externalHostName) {
        LOG.info("Pulling latest image...");
        new PullCommand(LOCALSTACK_NAME).execute();

        String containerId = new RunCommand(LOCALSTACK_NAME)
                .withExposedPorts(LOCALSTACK_PORTS)
                .withEnvironmentVariable(LOCALSTACK_EXTERNAL_HOSTNAME, externalHostName)
                .execute();
        LOG.info("Started container: " + containerId);

        List<PortMapping> portMappings = new PortCommand(containerId).execute();
        return new Container(containerId, portMappings);
    }


    private Container(String containerId, List<PortMapping> ports) {
        this.containerId = containerId;
        this.ports = Collections.unmodifiableList(ports);
    }


    /**
     * Given an internal port, retrieve the publicly addressable port that maps to it
     */
    public int getExternalPortFor(int internalPort) {
        return ports.stream()
                .filter(port -> port.getInternalPort() == internalPort)
                .map(PortMapping::getExternalPort)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Port: " + internalPort + " does not exist"));
    }


    public void waitForAllPorts(String ip) {
        ports.forEach(port -> waitForPort(ip, port));
    }


    private void waitForPort(String ip, PortMapping port) {
        int attempts = 0;
        do {
            if(isPortOpen(ip, port)) {
                return;
            }
            attempts++;
        }
        while(attempts < MAX_PORT_CONNECTION_ATTEMPTS);

        throw new IllegalStateException("Could not open port:" + port.getExternalPort() + " on ip:" + port.getIp());
    }


    private boolean isPortOpen(String ip, PortMapping port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port.getExternalPort()), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }


    /**
     * Poll the docker logs until a specific token appears, then return.  Primarily used to look
     * for the "Ready." token in the localstack logs.
     */
    public void waitForLogToken(Pattern pattern) {
        int attempts = 0;
        do {
            if(logContainsPattern(pattern)) {
                return;
            }
            waitForLogs();
            attempts++;
        }
        while(attempts < MAX_LOG_COLLECTION_ATTEMPTS);

        throw new IllegalStateException("Could not find token: " + pattern.toString() + " in docker logs.");
    }


    private boolean logContainsPattern(Pattern pattern) {
        String logs = new LogCommand(containerId).withNumberOfLines(NUM_LOG_LINES).execute();
        return pattern.matcher(logs).find();
    }


    private void waitForLogs(){
        try {
            Thread.sleep(POLL_INTERVAL);
        }
        catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }
    }


    /**
     * Stop the container
     */
    public void stop(){
        new StopCommand(containerId).execute();
        LOG.info("Stopped container: " + containerId);
    }


    /**
     * Run a command on the container via docker exec
     */
    public String executeCommand(List<String> command) {
        return new ExecCommand(containerId).execute(command);
    }
}
