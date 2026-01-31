use std::env;
use tracing_subscriber::{fmt, EnvFilter};

fn init_logger() {
    // Check if the environment variable ERST_LOG_FORMAT is set to "json"
    let use_json = env::var("ERST_LOG_FORMAT")
        .map(|val| val.to_lowercase() == "json")
        .unwrap_or(false);

    // Default to "info" level logging if not specified
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(std::io::stderr); // Write logs to stderr

    if use_json {
        // Output machine-parsable JSON
        subscriber.json().flatten_event(true).init();
    } else {
        // Output human-readable text
        subscriber.compact().init();
    }
}

fn main() {
    // 1. Initialize the logger immediately
    init_logger();

    // 2. Log that we started
    tracing::info!(event = "simulator_started", "Simulator initializing...");

    // ... The rest of your existing main function code goes here ...
}