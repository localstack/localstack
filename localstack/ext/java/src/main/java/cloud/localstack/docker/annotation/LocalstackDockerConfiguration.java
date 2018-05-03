package cloud.localstack.docker.annotation;

import lombok.Data;

import java.util.Collections;
import java.util.Map;

/**
 * @author Patrick Allain - 5/3/18.
 */
@Data
public class LocalstackDockerConfiguration {

    static final LocalstackDockerConfiguration DEFAULT = new LocalstackDockerConfiguration(
            false,
            false,
            "localhost",
            Collections.emptyMap());

    private final boolean pullNewImage;

    private final boolean randomizePorts;

    private final String externalHostName;

    private final Map<String, String> environmentVariables;

    public LocalstackDockerConfiguration(final boolean pullNewImage, final boolean randomizePorts, final String
            externalHostName, final Map<String, String> environmentVariables) {
        this.pullNewImage = pullNewImage;
        this.randomizePorts = randomizePorts;
        this.externalHostName = externalHostName;
        this.environmentVariables = environmentVariables;
    }

    public boolean isPullNewImage() {
        return pullNewImage;
    }

    public boolean isRandomizePorts() {
        return randomizePorts;
    }

    public String getExternalHostName() {
        return externalHostName;
    }

    public Map<String, String> getEnvironmentVariables() {
        return environmentVariables;
    }

}
