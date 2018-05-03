package cloud.localstack.docker.annotation;

import cloud.localstack.docker.LocalstackDockerTestRunner;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Processor to retrieve docker configuration based on {@link LocalstackDockerProperties} annotation.
 *
 * @author Alan Bevier
 * @author Patrick Allain - 5/3/18.
 */
public class LocalstackDockerAnnotationProcessor {

    private static final Logger LOG = Logger.getLogger(LocalstackDockerTestRunner.class.getName());

    private final Class<?> klass;

    public LocalstackDockerAnnotationProcessor(final Class<?> klass) {
        this.klass = klass;
    }

    public LocalstackDockerConfiguration process() {
        return Stream.of(this.klass.getAnnotations())
                .filter(annotation -> annotation instanceof LocalstackDockerProperties)
                .map(i -> (LocalstackDockerProperties) i)
                .map(this::processDockerPropertiesAnnotation)
                .findFirst()
                .orElse(LocalstackDockerConfiguration.DEFAULT);
    }

    private LocalstackDockerConfiguration processDockerPropertiesAnnotation(LocalstackDockerProperties properties) {
        final boolean pullNewImage = properties.pullNewImage();
        final boolean randomizePorts = properties.randomizePorts();

        final String externalHostName;
        try {
            IHostNameResolver hostNameResolver = properties.hostNameResolver().newInstance();
            String resolvedName = hostNameResolver.getHostName();

            externalHostName = StringUtils.defaultIfBlank(resolvedName, "localhost");

            LOG.info("External host name is set to: " + externalHostName);
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to resolve hostname", ex);
        }

        Map<String, String> environmentVariables = new HashMap<>();
        try {
            IEnvironmentVariableProvider environmentProvider = properties.environmentVariableProvider().newInstance();
            environmentVariables.putAll(environmentProvider.getEnvironmentVariables());
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to get environment variables", ex);
        }

        String services = String.join(",", properties.services());
        if (StringUtils.isNotEmpty(services)) {
            environmentVariables.put("SERVICES", services);
        }

        return new LocalstackDockerConfiguration(
                pullNewImage,
                randomizePorts,
                externalHostName,
                environmentVariables
        );
    }

}
