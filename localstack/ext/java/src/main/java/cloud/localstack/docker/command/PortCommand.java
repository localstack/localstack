package cloud.localstack.docker.command;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.regex.MatchResult;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import cloud.localstack.docker.PortMapping;

public class PortCommand extends Command {

    private static final Pattern PORT_MAPPING_PATTERN = Pattern.compile("(\\d+)/tcp -> ((\\d)(\\.(\\d)){3}):(\\d+)");
    private static final int INTERNAL_PORT_GROUP = 1;
    private static final int EXTERNAL_PORT_GROUP = 6;
    private static final int IP_GROUP = 2;

    private final String containerId;

    public PortCommand(String containerId) {
        this.containerId = containerId;
    }


    public List<PortMapping> execute() {
        String output = dockerExe.execute(Arrays.asList("port", containerId));

        return new RegexStream(PORT_MAPPING_PATTERN.matcher(output)).stream()
                .map(matchToPortMapping)
                .collect(Collectors.toList());
    }


    private Function<MatchResult, PortMapping> matchToPortMapping = m -> new PortMapping(m.group(IP_GROUP), m.group(EXTERNAL_PORT_GROUP), m.group(INTERNAL_PORT_GROUP));

}
