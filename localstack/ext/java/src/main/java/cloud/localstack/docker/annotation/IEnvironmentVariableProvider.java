package cloud.localstack.docker.annotation;

import java.util.Map;

public interface IEnvironmentVariableProvider {

    Map<String, String> getEnvironmentVariables();
}
