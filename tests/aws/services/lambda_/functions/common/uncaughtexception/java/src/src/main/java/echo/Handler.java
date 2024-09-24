package echo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

import java.util.Map;

public class Handler implements RequestHandler<Map<String, String>, Map<String, String>> {

    public Map<String, String> handleRequest(Map<String, String> event, Context context) {
        throw new RuntimeException("Error: " + event.get("error_msg"));
    }
}
