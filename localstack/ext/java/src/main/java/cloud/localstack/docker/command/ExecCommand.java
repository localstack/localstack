package cloud.localstack.docker.command;

import java.util.ArrayList;
import java.util.List;

public class ExecCommand extends Command {

    private final String containerId;

    public ExecCommand(String containerId) {
        this.containerId = containerId;
    }

    public String execute(List<String> command) {
        List<String> args = new ArrayList<>();
        args.add("exec");
        args.add(containerId);
        args.addAll(command);
        return dockerExe.execute(args);
    }
}
