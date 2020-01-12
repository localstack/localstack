package cloud.localstack.docker.command;

import java.util.*;

public class ListImagesCommand extends Command {

    public List<String> execute() {
        List<String> params = Arrays.asList("images", "--format", "{{.Repository}}:{{.Tag}}");
        return Arrays.asList(dockerExe.execute(params).split("\n"));
    }
}
