package cloud.localstack.docker.annotation;

import java.util.HashMap;
import java.util.Map;

public class DefaultEnvironmentVariableProvider implements IEnvironmentVariableProvider {

    @Override
    public Map<String, String> getEnvironmentVariables() {
        return new HashMap<>();
    }

}
