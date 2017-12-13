package cloud.localstack.docker;

/**
 * Keeps track of the external to internal port mapping for a container
 */
public class PortMapping {
    private final String ip;
    private final int externalPort;
    private final int internalPort;

    public PortMapping(String ip, String externalPort, String internalPort) {
        this.ip = ip;
        this.externalPort = Integer.parseInt(externalPort);
        this.internalPort = Integer.parseInt(internalPort);
    }

    public String getIp() {
        return ip;
    }

    public int getExternalPort() {
        return externalPort;
    }

    public int getInternalPort() {
        return internalPort;
    }

    @Override
    public String toString() {
        return String.format("%s:%s -> %s", ip, externalPort, internalPort);
    }
}
