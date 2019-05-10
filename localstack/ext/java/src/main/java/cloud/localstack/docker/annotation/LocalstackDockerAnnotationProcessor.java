package cloud.localstack.docker.annotation;

import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Processor to retrieve docker configuration based on {@link LocalstackDockerProperties} annotation.
 *
 * @author Alan Bevier
 * @author Patrick Allain
 */
public class LocalstackDockerAnnotationProcessor {

    private static final Logger LOG = Logger.getLogger(LocalstackDockerAnnotationProcessor.class.getName());

    public LocalstackDockerConfiguration process(final Class<?> klass) {
        return Stream.of(klass.getAnnotations())
                .filter(annotation -> annotation instanceof LocalstackDockerProperties)
                .map(i -> (LocalstackDockerProperties) i)
                .map(this::processDockerPropertiesAnnotation)
                .findFirst()
                .orElse(LocalstackDockerConfiguration.DEFAULT);
    }

    private LocalstackDockerConfiguration processDockerPropertiesAnnotation(LocalstackDockerProperties properties) {
        return LocalstackDockerConfiguration.builder()
                .environmentVariables(this.getEnvironments(properties))
                .externalHostName(this.getExternalHostName(properties))
                .pullNewImage(properties.pullNewImage())
                .randomizePorts(properties.randomizePorts())
                .imageTag(StringUtils.isEmpty(properties.imageTag()) ? null : properties.imageTag())
                .build();
    }

    private Map<String, String> getEnvironments(final LocalstackDockerProperties properties) {
        final Map<String, String> environmentVariables = new HashMap<>();
        try {
            IEnvironmentVariableProvider environmentProvider = properties.environmentVariableProvider().newInstance();
            environmentVariables.putAll(environmentProvider.getEnvironmentVariables());
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to get environment variables", ex);
        }

        final String services = String.join(",", properties.services());
        if (StringUtils.isNotEmpty(services)) {
            environmentVariables.put("SERVICES", services);
        }
        return environmentVariables;
    }

    private String getExternalHostName(final LocalstackDockerProperties properties) {
        try {
            IHostNameResolver hostNameResolver = properties.hostNameResolver().newInstance();
            String resolvedName = hostNameResolver.getHostName();

            final String externalHostName = StringUtils.defaultIfBlank(resolvedName, "localhost");

            LOG.info("External host name is set to: " + externalHostName);
            return externalHostName;
        } catch (InstantiationException | IllegalAccessException ex) {
            throw new IllegalStateException("Unable to resolve hostname", ex);
        }
    }

}
