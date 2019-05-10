package cloud.localstack.docker.annotation;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

import java.util.Collections;
import java.util.Map;

/**
 * Bean to specify the docker configuration.
 *
 * @author Patrick Allain.
 */
@Data
@Builder
public class LocalstackDockerConfiguration {

    public static final LocalstackDockerConfiguration DEFAULT = LocalstackDockerConfiguration.builder().build();

    private final boolean pullNewImage;

    private final boolean randomizePorts;

    private final String imageTag;

    @Builder.Default
    private final String externalHostName = "localhost";

    @Builder.Default
    private final Map<String, String> environmentVariables = Collections.emptyMap();

}
