use dotenv::dotenv;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;

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
    dotenv().ok();
    let server_url = env::var("SERVER_URL").expect("SERVER_URL must be set");

    let jwt_file_path = env::var("JWT_FILE_PATH").expect("JWT_TOKEN must be set");
    let jwt_token = fs::read_to_string(jwt_file_path).expect("Failed to read JWT token file");

    let client = Client::new();
    let req = RegisterMetricRequest {
        name: name.to_string(),
        description: description.to_string(),
    };

    client.post(format!("{}/register_custom_metric", server_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn update_custom_metric(name: &str, value: f64, labels: Vec<(String, String)>) -> Result<(), reqwest::Error> {
    dotenv().ok();
    let server_url = env::var("SERVER_URL").expect("SERVER_URL must be set");
    
    let jwt_file_path = env::var("JWT_FILE_PATH").expect("JWT_TOKEN must be set");
    let jwt_token = fs::read_to_string(jwt_file_path).expect("Failed to read JWT token file");

    let client = Client::new();
    let req = UpdateMetricRequest {
        name: name.to_string(),
        value,
        labels,
    };

    client.post(format!("{}/update_custom_metric", server_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
