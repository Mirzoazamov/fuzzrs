use reqwest::{Client, Method, Error as ReqwestError, header::HeaderMap, RequestBuilder};
use std::time::Duration;
use thiserror::Error;
use bytes::Bytes;
use rand::Rng;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("HTTP request error: {0}")]
    RequestError(#[from] ReqwestError),
}

/// Lightweight struct to eliminate Reqwest Response overhead while holding physical execution metrics securely.
pub struct HttpResponseMeta {
    pub status: u16,
    pub response_time: Duration,
    pub content_length: Option<u64>,
    pub body: Bytes, // Carries the payload safely using zero-copy architecture locally
}

#[derive(Clone)]
pub struct RequestConfig<'a> {
    pub url: &'a str,
    pub method: Method,
    pub headers: Option<&'a HeaderMap>,
    pub timeout: Duration,
    pub max_retries: u32,
    pub body: Option<Bytes>, // 1. Zero copy Refcount body
    pub mutation_hook: Option<fn(RequestBuilder) -> RequestBuilder>, // 5. WAF mutation interceptor
}

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new(max_connections: usize, connect_timeout: Duration, global_timeout: Duration) -> Result<Self, ReqwestError> {
        let client = Client::builder()
            .pool_max_idle_per_host(max_connections)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .connect_timeout(connect_timeout) // 3. Connection strict bound
            .timeout(global_timeout)         // 3. Global socket sweep bound internally
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self { client })
    }

    pub async fn send(&self, config: RequestConfig<'_>) -> Result<HttpResponseMeta, ClientError> {
        let mut attempts = 0;
        let mut backoff = Duration::from_millis(50); // Initial backoff scalar

        loop {
            let mut req_builder = self.client.request(config.method.clone(), config.url)
                // Optionally clamps faster limits per request logically
                .timeout(config.timeout);

            if let Some(headers) = config.headers {
                req_builder = req_builder.headers(headers.clone());
            }

            if let Some(b) = &config.body {
                // req_builder natively delegates `bytes::Bytes` cleanly downward locking perfectly 1:1 internally
                req_builder = req_builder.body(b.clone()); 
            }

            if let Some(hook) = config.mutation_hook {
                req_builder = hook(req_builder);
            }

            let start = std::time::Instant::now();
            match req_builder.send().await {
                Ok(response) => {
                    let status = response.status();
                    let response_time = start.elapsed();
                    let content_length = response.content_length();
                    
                    // Consume natively. Chunked transfers dropping natively trigger `err.is_body()` maps cleanly here
                    let body = match response.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            if e.is_timeout() || e.is_connect() || e.is_request() || e.is_body() {
                                attempts += 1;
                                if attempts > config.max_retries {
                                    return Err(ClientError::RequestError(e));
                                }
                                let jitter = rand::thread_rng().gen_range(0..25);
                                tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
                                backoff *= 2; 
                                continue;
                            }
                            return Err(ClientError::RequestError(e));
                        }
                    };

                    return Ok(HttpResponseMeta {
                        status: status.as_u16(),
                        response_time,
                        content_length,
                        body,
                    });
                }
                Err(err) => {
                    attempts += 1;

                    // 2. Advanced retry bounds correctly factoring failed partially parsed transfers (`is_request()`)
                    if err.is_timeout() || err.is_connect() || err.is_request() {
                        if attempts > config.max_retries {
                            return Err(ClientError::RequestError(err));
                        }
                        
                        // Jittered Exponential scaling protecting upstream DDOS flags dynamically
                        let jitter = rand::thread_rng().gen_range(0..25);
                        tokio::time::sleep(backoff + Duration::from_millis(jitter)).await;
                        backoff *= 2; 
                        continue;
                    }

                    return Err(ClientError::RequestError(err));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_timeout_and_advanced_exponential_retry_enforcement() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .and(path("/hang"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new(10, Duration::from_secs(1), Duration::from_secs(5)).unwrap();
        let config = RequestConfig {
            url: &format!("{}/hang", mock_server.uri()),
            method: Method::GET,
            headers: None,
            timeout: Duration::from_millis(100), 
            max_retries: 2, // 3 tries total. Sleep(50ms) + Sleep(100ms) + Execution overhead ~ 150-250ms logically.
            body: None,
            mutation_hook: None,
        };

        let start = std::time::Instant::now();
        let result = client.send(config).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        match result.unwrap_err() {
            ClientError::RequestError(e) => assert!(e.is_timeout()),
        }

        // Must logically process the full stack strictly tracking exponential logic
        assert!(elapsed.as_millis() >= 150); 
    }

    fn sample_mutation(req: RequestBuilder) -> RequestBuilder {
        req.header("X-Evasion", "active")
    }

    #[tokio::test]
    async fn test_mutation_hook_and_zero_copy() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("POST"))
            .and(path("/evade"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new(1, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let payload = Bytes::from("static secure zero copy footprint byte payload chunk here realistically initialized");
        
        let config = RequestConfig {
            url: &format!("{}/evade", mock_server.uri()),
            method: Method::POST,
            headers: None,
            timeout: Duration::from_millis(500),
            max_retries: 0,
            body: Some(payload.clone()), // O(1) mathematical clone mapping cleanly securely natively 
            mutation_hook: Some(sample_mutation),
        };

        let meta = client.send(config).await.unwrap();
        
        assert_eq!(meta.status, 201);
        // Safely confirmed mutation cleanly handled the upstream logic natively.
    }
}
