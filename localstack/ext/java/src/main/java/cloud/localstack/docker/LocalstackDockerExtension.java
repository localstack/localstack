package cloud.localstack.docker;

import cloud.localstack.Localstack;
import cloud.localstack.docker.annotation.LocalstackDockerAnnotationProcessor;
import cloud.localstack.docker.annotation.LocalstackDockerConfiguration;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * JUnit test runner that automatically pulls and runs the latest localstack docker image
 * and then terminates when tests are complete.
 *
 * Having docker installed is a prerequisite for this test runner to execute.  If docker
 * is not installed in one of the default locations (C:\program files\docker\docker\resources\bin\, usr/local/bin or
 * usr/bin)
 * then use the DOCKER_LOCATION environment variable to specify the location.
 *
 * Since ports are dynamically allocated, the external port needs to be resolved based on the default localstack port.
 *
 * The hostname defaults to localhost, but in some environments that is not sufficient, so the HostName can be specified
 * by using the LocalstackDockerProperties annotation with an IHostNameResolver.
 *
 * @author Alan Bevier
 * @author Patrick Allain
 * @author Omar Khammassi
 */
public class LocalstackDockerExtension implements BeforeAllCallback {

    private static final LocalstackDockerAnnotationProcessor PROCESSOR = new LocalstackDockerAnnotationProcessor();
    private static final ExtensionContext.Namespace NAMESPACE = ExtensionContext.Namespace.create(LocalstackDockerExtension.class);

    @Override
    public void beforeAll(final ExtensionContext context) throws Exception {
        final ExtensionContext.Store store;
        if (isUseSingleDockerContainer(context)) {
            store = context.getRoot().getStore(ExtensionContext.Namespace.GLOBAL);
        } else {
            store = context.getStore(NAMESPACE);
        }
        store.getOrComputeIfAbsent("localstack", key -> new LocalstackDockerExtension.StartedLocalStack(context));
    }

    private boolean isUseSingleDockerContainer(final ExtensionContext context) {
        return PROCESSOR.process(context.getRequiredTestClass()).isUseSingleDockerContainer();
    }

    static class StartedLocalStack implements ExtensionContext.Store.CloseableResource {

        private Localstack localstackDocker = Localstack.INSTANCE;

        StartedLocalStack(ExtensionContext context) {
            final LocalstackDockerConfiguration dockerConfig = PROCESSOR.process(context.getRequiredTestClass());
            localstackDocker.startup(dockerConfig);
        }

        @Override
        public void close() throws Throwable {
            localstackDocker.stop();
        }
    }
}
