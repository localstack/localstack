package cloud.localstack.docker.command;

import java.util.ArrayList;
import java.util.List;

public class RunCommand extends Command {

    private final String imageName;

    public RunCommand(String imageName) {
        this.imageName = imageName;
    }

    public String execute() {
        List<String> args = new ArrayList<>();
        args.add("run");
        args.add("-d");
        args.addAll(options);
        args.add(imageName);

        return dockerExe.execute(args);
    }

    public RunCommand withExposedPorts(String portsToExpose) {
        addOptions("-p", ":" + portsToExpose);
        return this;
    }

    public RunCommand withEnvironmentVariable(String name, String value) {
        addOptions("-e", String.format("\"%s=%s\"", name, value));
        return this;
    }
}
