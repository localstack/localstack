use lambda_runtime::{service_fn, LambdaEvent, Error};
use serde_json::{Value};

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::run(service_fn(func)).await?;
    Ok(())
}

async fn func(event: LambdaEvent<Value>) -> Result<Value, Error> {
    let (event, _context) = event.into_parts();
    Err(Error::try_from(format!("Error: {}", event.get("error_msg").unwrap())).unwrap())
}
