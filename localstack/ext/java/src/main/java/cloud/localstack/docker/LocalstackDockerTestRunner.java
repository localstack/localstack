package cloud.localstack.docker;

import cloud.localstack.Localstack;
import cloud.localstack.docker.annotation.LocalstackDockerAnnotationProcessor;
import cloud.localstack.docker.annotation.LocalstackDockerConfiguration;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * JUnit test runner that automatically pulls and runs the latest localstack docker image
 * and then terminates when tests are complete.
 *
 * Having docker installed is a prerequisite for this test runner to execute.  If docker
 * is not installed in one of the default locations (C:\program files\docker\docker\resources\bin\, usr/local/bin or usr/bin)
 * then use the DOCKER_LOCATION environment variable to specify the location.
 *
 * Since ports are dynamically allocated, the external port needs to be resolved based on the default localstack port.
 *
 * The hostname defaults to localhost, but in some environments that is not sufficient, so the HostName can be specified
 * by using the LocalstackDockerProperties annotation with an IHostNameResolver.
 *
 * @author Alan Bevier
 * @author Patrick Allain
 */
public class LocalstackDockerTestRunner extends BlockJUnit4ClassRunner {


    private final LocalstackDockerConfiguration dockerConfiguration;

    private LocalstackDocker localstackDocker = LocalstackDocker.INSTANCE;


    public LocalstackDockerTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
        this.dockerConfiguration = new LocalstackDockerAnnotationProcessor(klass).process();
    }

    @Override
    public void run(RunNotifier notifier) {
        Localstack.teardownInfrastructure();
        try {
            localstackDocker.startup(dockerConfiguration);
            super.run(notifier);
        }
        finally {
            localstackDocker.stop();
        }
    }


}