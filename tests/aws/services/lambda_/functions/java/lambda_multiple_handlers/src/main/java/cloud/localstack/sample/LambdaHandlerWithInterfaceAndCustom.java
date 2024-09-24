package cloud.localstack.sample;

import java.util.Map;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class LambdaHandlerWithInterfaceAndCustom implements RequestHandler<Map<String,String>, String> {
  Gson gson = new GsonBuilder().setPrettyPrinting().create();

  public String handleRequestCustom(Map<String,String> event, Context context)
  {
    LambdaLogger logger = context.getLogger();
    logger.log("CUSTOM HANDLER");
    logger.log("ENV: " + gson.toJson(System.getenv()));
    logger.log("EVENT: " + gson.toJson(event));
    logger.log("EVENT CLASS: " + event.getClass());
    logger.log("CONTEXT: " + gson.toJson(context));
    return "CUSTOM";
  }
  public String handleRequest(Map<String,String> event, Context context) {
    LambdaLogger logger = context.getLogger();
    logger.log("INTERFACE HANDLER");
    logger.log("ENV: " + gson.toJson(System.getenv()));
    logger.log("EVENT: " + gson.toJson(event));
    logger.log("EVENT CLASS: " + event.getClass());
    logger.log("CONTEXT: " + gson.toJson(context));
    return "INTERFACE";
  }
}
