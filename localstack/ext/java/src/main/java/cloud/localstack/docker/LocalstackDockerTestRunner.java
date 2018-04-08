package cloud.localstack.docker;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.ServiceName;
import cloud.localstack.docker.annotation.IEnvironmentVariableProvider;
import cloud.localstack.docker.annotation.IHostNameResolver;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;
import cloud.localstack.docker.command.RegexStream;

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
 */
public class LocalstackDockerTestRunner extends BlockJUnit4ClassRunner {

    private static final Logger LOG = Logger.getLogger(LocalstackDockerTestRunner.class.getName());

    private static String externalHostName = "localhost";
    private static boolean pullNewImage = true;
    private static boolean randomizePorts = false;
    private static Map<String, String> environmentVariables = new HashMap<>();

    @Getter
    private static LocalstackDocker localstackDocker = LocalstackDocker.getLocalstackDocker();


    public LocalstackDockerTestRunner(Class<?> klass) throws InitializationError {
        super(klass);
        processAnnotations(klass.getAnnotations());
    }

    @Override
    public void run(RunNotifier notifier) {
        LocalstackTestRunner.teardownInfrastructure();

        localstackDocker.setExternalHostName(externalHostName);
        localstackDocker.setPullNewImage(pullNewImage);
        localstackDocker.setRandomizePorts(randomizePorts);
        localstackDocker.setEnvironmentVariables(environmentVariables);

        try {
            localstackDocker.startup();
            super.run(notifier);
        }
        finally {
            localstackDocker.stop();
        }
    }

    private void processAnnotations(Annotation[] annotations) {
        for(Annotation annotation : annotations) {
            if(annotation instanceof LocalstackDockerProperties) {
                processDockerPropertiesAnnotation((LocalstackDockerProperties)annotation);
            }
        }
    }


    private void processDockerPropertiesAnnotation(LocalstackDockerProperties properties) {
        pullNewImage = properties.pullNewImage();
        randomizePorts = properties.randomizePorts();

        try {
            IHostNameResolver hostNameResolver = properties.hostNameResolver().newInstance();
            String resolvedName = hostNameResolver.getHostName();
            if(StringUtils.isNotBlank(resolvedName)) {
                externalHostName = resolvedName;
            }
            LOG.info("External host name is set to: " + externalHostName);
        }
        catch(InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to resolve hostname", ex);
        }

        try {
            IEnvironmentVariableProvider environmentProvider = properties.environmentVariableProvider().newInstance();
            environmentVariables = environmentProvider.getEnvironmentVariables();
        }
        catch(InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to get environment variables", ex);
        }

        String services = String.join(",", properties.services());
        if(StringUtils.isNotEmpty(services)) {
            environmentVariables.put("SERVICES", services);
        }
    }
}