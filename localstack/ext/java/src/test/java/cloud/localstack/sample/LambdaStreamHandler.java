package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.apache.commons.io.IOUtils;

/**
 * Test Lambda stream handler class
 */
public class LambdaStreamHandler implements RequestStreamHandler {

    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context) {
        try {
            System.err.println(new String(IOUtils.toByteArray(input)));
            output.write("{}".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
