package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Handler implements RequestStreamHandler {
  @Override
  public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {
    int n;
    byte[] buffer = new byte[1024];
    while((n = input.read(buffer)) > -1) {
      output.write(buffer,0, n);
    }
    output.close();
  }
}
