use httpmock::prelude::*;
use pt_journal::chatbot::ChatRequest;
use pt_journal::chatbot::{AzureOpenAIProvider, ChatProvider, OpenAIProvider};
use pt_journal::config::{AzureOpenAIProviderConfig, ModelProfile, OpenAIProviderConfig};

#[test]
fn test_openai_provider_configuration() {
    let config = OpenAIProviderConfig {
        api_key: Some("sk-test123".to_string()),
        endpoint: "https://api.openai.com/v1".to_string(),
        timeout_seconds: 60,
    };

    let provider = OpenAIProvider::new(config);
    assert_eq!(provider.provider_name(), "openai");
}

#[test]
fn test_openai_provider_missing_api_key() {
    let config = OpenAIProviderConfig {
        api_key: None,
        endpoint: "https://api.openai.com/v1".to_string(),
        timeout_seconds: 60,
    };

    let provider = OpenAIProvider::new(config);

    let request = ChatRequest::new(
        pt_journal::chatbot::StepContext::default(),
        vec![],
        "test".to_string(),
        ModelProfile::for_openai("gpt-4", "GPT-4"),
    );

    let result = provider.send_message(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("API key"));
}

#[test]
fn test_openai_provider_successful_request() {
    let server = MockServer::start();

    let mock_response = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Hello from OpenAI!"
            }
        }]
    });

    server.mock(|when, then| {
        when.method(POST)
            .path("/chat/completions")
            .header("Authorization", "Bearer test-key")
            .header("Content-Type", "application/json");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(mock_response);
    });

    let config = OpenAIProviderConfig {
        api_key: Some("test-key".to_string()),
        endpoint: server.url(""),
        timeout_seconds: 60,
    };

    let provider = OpenAIProvider::new(config);
    let request = ChatRequest::new(
        pt_journal::chatbot::StepContext::default(),
        vec![],
        "Hello".to_string(),
        ModelProfile::for_openai("gpt-4", "GPT-4"),
    );

    let result = provider.send_message(&request);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().content, "Hello from OpenAI!");
}

#[test]
fn test_azure_openai_provider_configuration() {
    let config = AzureOpenAIProviderConfig {
        api_key: Some("azure-test123".to_string()),
        endpoint: Some("https://test.openai.azure.com".to_string()),
        deployment_name: Some("gpt-4".to_string()),
        api_version: Some("2024-02-15-preview".to_string()),
        timeout_seconds: 60,
    };

    let provider = AzureOpenAIProvider::new(config);
    assert_eq!(provider.provider_name(), "azure-openai");
}

#[test]
fn test_azure_openai_provider_missing_api_key() {
    let config = AzureOpenAIProviderConfig {
        api_key: None,
        endpoint: Some("https://test.openai.azure.com".to_string()),
        deployment_name: Some("gpt-4".to_string()),
        api_version: Some("2024-02-15-preview".to_string()),
        timeout_seconds: 60,
    };

    let provider = AzureOpenAIProvider::new(config);

    let request = ChatRequest::new(
        pt_journal::chatbot::StepContext::default(),
        vec![],
        "test".to_string(),
        ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
    );

    let result = provider.send_message(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("API key"));
}

#[test]
fn test_azure_openai_provider_missing_endpoint() {
    let config = AzureOpenAIProviderConfig {
        api_key: Some("azure-test123".to_string()),
        endpoint: None,
        deployment_name: Some("gpt-4".to_string()),
        api_version: Some("2024-02-15-preview".to_string()),
        timeout_seconds: 60,
    };

    let provider = AzureOpenAIProvider::new(config);

    let request = ChatRequest::new(
        pt_journal::chatbot::StepContext::default(),
        vec![],
        "test".to_string(),
        ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
    );

    let result = provider.send_message(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("endpoint"));
}

#[test]
fn test_azure_openai_provider_successful_request() {
    let server = MockServer::start();

    let mock_response = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Hello from Azure OpenAI!"
            }
        }]
    });

    server.mock(|when, then| {
        when.method(POST)
            .path("/openai/deployments/gpt-4/chat/completions")
            .header("api-key", "test-key")
            .header("Content-Type", "application/json")
            .query_param("api-version", "2024-02-15-preview");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(mock_response);
    });

    let config = AzureOpenAIProviderConfig {
        api_key: Some("test-key".to_string()),
        endpoint: Some(server.url("")),
        deployment_name: Some("gpt-4".to_string()),
        api_version: Some("2024-02-15-preview".to_string()),
        timeout_seconds: 60,
    };

    let provider = AzureOpenAIProvider::new(config);
    let request = ChatRequest::new(
        pt_journal::chatbot::StepContext::default(),
        vec![],
        "Hello".to_string(),
        ModelProfile::for_azure_openai("gpt-4", "GPT-4"),
    );

    let result = provider.send_message(&request);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().content, "Hello from Azure OpenAI!");
}

#[test]
fn test_provider_model_profiles() {
    let openai_profile = ModelProfile::for_openai("gpt-4", "GPT-4 (OpenAI)");
    assert_eq!(openai_profile.id, "gpt-4");
    assert_eq!(openai_profile.display_name, "GPT-4 (OpenAI)");
    assert!(matches!(
        openai_profile.provider,
        pt_journal::config::ModelProviderKind::OpenAI
    ));

    let azure_profile = ModelProfile::for_azure_openai("gpt-4", "GPT-4 (Azure)");
    assert_eq!(azure_profile.id, "gpt-4");
    assert_eq!(azure_profile.display_name, "GPT-4 (Azure)");
    assert!(matches!(
        azure_profile.provider,
        pt_journal::config::ModelProviderKind::AzureOpenAI
    ));
}

#[test]
fn test_openai_provider_availability_check() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET)
            .path("/models")
            .header("Authorization", "Bearer test-key");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({
                "data": [
                    {"id": "gpt-4"},
                    {"id": "gpt-3.5-turbo"}
                ]
            }));
    });

    let config = OpenAIProviderConfig {
        api_key: Some("test-key".to_string()),
        endpoint: server.url(""),
        timeout_seconds: 60,
    };

    let provider = OpenAIProvider::new(config);
    let result = provider.check_availability();
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_azure_openai_provider_availability_check() {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(GET)
            .path("/openai/deployments")
            .header("api-key", "test-key")
            .query_param("api-version", "2024-02-15-preview");
        then.status(200)
            .header("Content-Type", "application/json")
            .json_body(serde_json::json!({
                "data": [
                    {
                        "id": "gpt-4",
                        "model": {
                            "id": "gpt-4",
                            "type": "text-generation"
                        }
                    }
                ]
            }));
    });

    let config = AzureOpenAIProviderConfig {
        api_key: Some("test-key".to_string()),
        endpoint: Some(server.url("")),
        deployment_name: None,
        api_version: Some("2024-02-15-preview".to_string()),
        timeout_seconds: 60,
    };

    let provider = AzureOpenAIProvider::new(config);
    let result = provider.check_availability();
    assert!(result.is_ok());
    assert!(result.unwrap());
}
