use cb_common::config::JWT_ENV;
use cb_common::config::METRICS_SERVER_URL;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Deserialize, Serialize)]
struct RegisterMetricRequest {
    name: String,
    description: String,
}

#[derive(Deserialize, Serialize)]
struct UpdateMetricRequest {
    name: String,
    value: f64,
    labels: Vec<(String, String)>,
}

pub async fn register_custom_metric(name: &str, description: &str) -> Result<(), reqwest::Error> {
    let server_url = env::var(METRICS_SERVER_URL).expect(&format!("{METRICS_SERVER_URL} is not set"));
    let jwt_token = env::var(JWT_ENV).expect(&format!("{JWT_ENV} must be set"));

    let client = Client::new();
    let req = RegisterMetricRequest {
        name: name.to_string(),
        description: description.to_string(),
    };

    client.post(format!("http://{}/register_custom_metric", server_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn update_custom_metric(name: &str, value: f64, labels: Vec<(String, String)>) -> Result<(), reqwest::Error> {
    let server_url = env::var(METRICS_SERVER_URL).expect(&format!("{METRICS_SERVER_URL} is not set"));
    let jwt_token = env::var(JWT_ENV).expect(&format!("{JWT_ENV} must be set"));

    let client = Client::new();
    let req = UpdateMetricRequest {
        name: name.to_string(),
        value,
        labels,
    };

    client.post(format!("http://{}/update_custom_metric", server_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
