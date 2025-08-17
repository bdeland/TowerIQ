use serde::{Deserialize, Serialize};
use tauri::State;
use std::sync::Mutex;

// API response types
#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    message: Option<String>,
    #[serde(flatten)]
    data: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: String,
    session: SessionState,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionState {
    is_connected: bool,
    current_device: Option<String>,
    current_process: Option<serde_json::Value>,
    test_mode: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConnectionRequest {
    device_serial: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestModeRequest {
    test_mode: bool,
    test_mode_replay: bool,
    test_mode_generate: bool,
}

// State for managing the API client
struct ApiClient {
    base_url: String,
}

impl ApiClient {
    fn new() -> Self {
        Self {
            base_url: "http://127.0.0.1:8000".to_string(),
        }
    }

    async fn get_status(&self) -> Result<StatusResponse, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/api/status", self.base_url))
            .send()
            .await?;
        
        let status_response: StatusResponse = response.json().await?;
        Ok(status_response)
    }

    async fn connect_device(&self, device_serial: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let request = ConnectionRequest { device_serial };
        
        let response = client
            .post(&format!("{}/api/connect-device", self.base_url))
            .json(&request)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn set_test_mode(&self, test_mode: bool, test_mode_replay: bool, test_mode_generate: bool) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let request = TestModeRequest {
            test_mode,
            test_mode_replay,
            test_mode_generate,
        };
        
        let response = client
            .post(&format!("{}/api/test-mode", self.base_url))
            .json(&request)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }
}

// Tauri commands
#[tauri::command]
async fn get_backend_status() -> Result<StatusResponse, String> {
    let client = ApiClient::new();
    client.get_status().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect_device(device_serial: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.connect_device(device_serial).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_test_mode(test_mode: bool, test_mode_replay: bool, test_mode_generate: bool) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.set_test_mode(test_mode, test_mode_replay, test_mode_generate).await.map_err(|e| e.to_string())
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            get_backend_status,
            connect_device,
            set_test_mode
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
