package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;

import java.io.*;
import java.util.stream.Collectors;

/**
 * Test Lambda stream handler class
 */
public class LambdaStreamHandler implements RequestStreamHandler {

    @Override
    public void handleRequest(InputStream inputStream, OutputStream output, Context context) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String input = reader.lines().collect(Collectors.joining());
            System.err.println(input);
            output.write("{}".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
