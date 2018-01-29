package cloud.localstack.docker.annotation;

/**
 * A default host name resolver
 */
public class LocalHostNameResolver implements IHostNameResolver {

    @Override
    public String getHostName() {
        return "localhost";
    }
}
