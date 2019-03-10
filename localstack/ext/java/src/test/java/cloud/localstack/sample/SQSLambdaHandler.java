package cloud.localstack.sample;

import cloud.localstack.TestUtils;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.s3.AmazonS3;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;

public class SQSLambdaHandler implements RequestHandler<SQSEvent, Object> {

    public static final String[] fileName = { "sqsLambda", "test" };
    public static final String DID_YOU_GET_THE_MESSAGE = "Did you get the message?";
    protected AmazonS3 clientS3;

    public SQSLambdaHandler() {
        clientS3 = TestUtils.getClientS3();
    }

    @Override
    public Object handleRequest(SQSEvent event, Context context) {
        for (SQSEvent.SQSMessage message : event.getRecords()) {
            File file = getFile(DID_YOU_GET_THE_MESSAGE);
            clientS3.putObject(message.getBody(), file.getName(), file);
        }

        return "{}";
    }

    private File getFile(String message) {
        File file = null;
        try {
            file = Files.createTempFile(fileName[0], fileName[1]).toFile();
            file.deleteOnExit();
            BufferedWriter bw = new BufferedWriter(new FileWriter(file));
            bw.write(message);
            bw.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return file;
    }

}
