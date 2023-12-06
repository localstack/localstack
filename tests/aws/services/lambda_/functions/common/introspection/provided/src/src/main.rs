use std::collections::HashMap;
use lambda_runtime::{service_fn, LambdaEvent, Error};
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::run(service_fn(func)).await?;
    Ok(())
}

async fn func(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let (_event, context) = event.into_parts();

    let env: HashMap<String, String> = std::env::vars().collect();
    Ok(json!({ "environment": env, "ctx": {
            "function_name": context.env_config.function_name,
            "function_version": context.env_config.version,
            "invoked_function_arn": context.invoked_function_arn,
            "memory_limit_in_mb": context.env_config.memory,
            "aws_request_id": context.request_id,
            "log_group_name": context.env_config.log_group,
            "log_stream_name": context.env_config.log_stream,
            "deadline": context.deadline.to_string()
    }, "packages": [] }))
}
