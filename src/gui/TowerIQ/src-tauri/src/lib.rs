use serde::{Deserialize, Serialize};

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
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // 10 second timeout
            .build()?;
        let response = client
            .get(&format!("{}/api/status", self.base_url))
            .send()
            .await?;
        
        let status_response: StatusResponse = response.json().await?;
        Ok(status_response)
    }

    async fn connect_device(&self, device_serial: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/connect", self.base_url))
            .json(&serde_json::json!({
                "device_serial": device_serial
            }))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn disconnect_device(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/disconnect", self.base_url))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn set_test_mode(&self, test_mode: bool, test_mode_replay: bool, test_mode_generate: bool) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // 10 second timeout
            .build()?;
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

    async fn scan_devices(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .get(&format!("{}/api/devices", self.base_url))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn get_processes(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .get(&format!("{}/api/devices/{}/processes", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn get_hook_scripts(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // 10 second timeout
            .build()?;
        let response = client
            .get(&format!("{}/api/hook-scripts", self.base_url))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn get_frida_status(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .get(&format!("{}/api/devices/{}/frida-status", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn provision_frida_server(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/devices/{}/frida-provision", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn start_frida_server(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/devices/{}/frida-start", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn stop_frida_server(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/devices/{}/frida-stop", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn install_frida_server(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120)) // 2 minute timeout for installation
            .build()?;
        let response = client
            .post(&format!("{}/api/devices/{}/frida-install", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn remove_frida_server(&self, device_id: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        let response = client
            .post(&format!("{}/api/devices/{}/frida-remove", self.base_url, device_id))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn activate_hook(&self, device_id: String, process_info: serde_json::Value, script_content: String) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        
        let request_body = serde_json::json!({
            "device_id": device_id,
            "process_info": process_info,
            "script_content": script_content
        });
        
        let response = client
            .post(&format!("{}/api/activate-hook", self.base_url))
            .json(&request_body)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn deactivate_hook(&self, device_id: String, process_info: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)) // 30 second timeout
            .build()?;
        
        let request_body = serde_json::json!({
            "device_id": device_id,
            "process_info": process_info
        });
        
        let response = client
            .post(&format!("{}/api/deactivate-hook", self.base_url))
            .json(&request_body)
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        Ok(result)
    }

    async fn get_script_status(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // 10 second timeout
            .build()?;
        
        let response = client
            .get(&format!("{}/api/script-status", self.base_url))
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
async fn disconnect_device() -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.disconnect_device().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_test_mode(test_mode: bool, test_mode_replay: bool, test_mode_generate: bool) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.set_test_mode(test_mode, test_mode_replay, test_mode_generate).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_devices() -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    
    // Add timeout to prevent hanging
    match tokio::time::timeout(
        std::time::Duration::from_secs(60), // 60 second timeout
        client.scan_devices()
    ).await {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(_) => Err("Device scanning timed out after 60 seconds".to_string())
    }
}

#[tauri::command]
async fn get_processes(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.get_processes(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_hook_scripts() -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.get_hook_scripts().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_frida_status(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.get_frida_status(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn provision_frida_server(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.provision_frida_server(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_frida_server(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.start_frida_server(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn stop_frida_server(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.stop_frida_server(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn install_frida_server(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.install_frida_server(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_frida_server(device_id: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.remove_frida_server(device_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn activate_hook(device_id: String, process_info: serde_json::Value, script_content: String) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.activate_hook(device_id, process_info, script_content).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn deactivate_hook(device_id: String, process_info: serde_json::Value) -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.deactivate_hook(device_id, process_info).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_script_status() -> Result<serde_json::Value, String> {
    let client = ApiClient::new();
    client.get_script_status().await.map_err(|e| e.to_string())
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
            disconnect_device,
            set_test_mode,
            scan_devices,
            get_processes,
            get_hook_scripts,
            get_frida_status,
            provision_frida_server,
            start_frida_server,
            stop_frida_server,
            install_frida_server,
            remove_frida_server,
            activate_hook,
            deactivate_hook,
            get_script_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
