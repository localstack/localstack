package cloud.localstack.sample;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.util.Map;
import com.google.gson.Gson;

public class LambdaHandlerWithLib implements RequestHandler<Map, String>{
  public String handleRequest(Map echo, Context context) {
    Gson gson = new Gson();
    return gson.toJson(echo);
  }
}
