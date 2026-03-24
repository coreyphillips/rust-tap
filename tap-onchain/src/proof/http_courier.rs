// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! HTTP-based proof courier implementation.
//!
//! Delivers and receives proofs via a REST API. Stream IDs are derived
//! from the recipient's script key using [`derive_stream_id`].
//!
//! Endpoints:
//! - `PUT  /proof/{stream_id_hex}` — upload a proof
//! - `GET  /proof/{stream_id_hex}` — download a proof

use std::io::Read;
use std::time::Duration;

use tap_primitives::proof;

use super::backoff::BackoffCfg;
use super::courier::{
    AnnotatedProof, Courier, CourierError, CourierLocator, Recipient,
    derive_stream_id,
};

/// Configuration for the HTTP courier.
#[derive(Clone, Debug)]
pub struct HttpCourierCfg {
    /// Base URL for the courier service (e.g., `https://courier.example.com/v1`).
    pub base_url: String,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Backoff configuration for retries.
    pub backoff: BackoffCfg,
}

impl HttpCourierCfg {
    pub fn new(base_url: String) -> Self {
        HttpCourierCfg {
            base_url,
            timeout: Duration::from_secs(30),
            backoff: BackoffCfg::default(),
        }
    }
}

/// HTTP-based proof courier.
///
/// Sends and receives proofs via REST endpoints. Uses `ureq` for
/// synchronous HTTP and exponential backoff for transient failures.
pub struct HttpCourier {
    cfg: HttpCourierCfg,
}

impl HttpCourier {
    pub fn new(cfg: HttpCourierCfg) -> Self {
        HttpCourier { cfg }
    }

    fn proof_url(&self, stream_id: &[u8; 32]) -> String {
        format!("{}/proof/{}", self.cfg.base_url, hex_encode(stream_id))
    }
}

impl Courier for HttpCourier {
    fn deliver_proof(
        &self,
        recipient: &Recipient,
        proof: &AnnotatedProof,
    ) -> Result<(), CourierError> {
        let stream_id = derive_stream_id(&recipient.script_key);
        let url = self.proof_url(&stream_id);
        let encoded = proof.proof_file.encode();

        let mut delay = self.cfg.backoff.initial_backoff;

        for attempt in 0..self.cfg.backoff.max_retries {
            let result = ureq::put(&url)
                .timeout(self.cfg.timeout)
                .set("Content-Type", "application/octet-stream")
                .send_bytes(&encoded);

            match result {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if !is_retryable(&e) || attempt + 1 >= self.cfg.backoff.max_retries {
                        return Err(ureq_to_courier_error(e));
                    }
                    std::thread::sleep(delay);
                    delay = std::cmp::min(
                        delay * 2,
                        self.cfg.backoff.max_backoff,
                    );
                }
            }
        }

        Err(CourierError::Timeout)
    }

    fn receive_proof(
        &self,
        recipient: &Recipient,
        locator: &CourierLocator,
    ) -> Result<AnnotatedProof, CourierError> {
        let stream_id = derive_stream_id(&recipient.script_key);
        let url = self.proof_url(&stream_id);

        let mut delay = self.cfg.backoff.initial_backoff;

        for attempt in 0..self.cfg.backoff.max_retries {
            let result = ureq::get(&url)
                .timeout(self.cfg.timeout)
                .call();

            match result {
                Ok(response) => {
                    let mut body = Vec::new();
                    response
                        .into_reader()
                        .take(4 * 1024 * 1024) // 4 MiB limit
                        .read_to_end(&mut body)
                        .map_err(|e| CourierError::Transport(e.to_string()))?;

                    let proof_file = proof::File::decode(&body)
                        .map_err(|e| CourierError::Encoding(e.to_string()))?;

                    return Ok(AnnotatedProof {
                        locator: locator.clone(),
                        proof_file,
                    });
                }
                Err(e) => {
                    if !is_retryable(&e) || attempt + 1 >= self.cfg.backoff.max_retries {
                        return Err(ureq_to_courier_error(e));
                    }
                    std::thread::sleep(delay);
                    delay = std::cmp::min(
                        delay * 2,
                        self.cfg.backoff.max_backoff,
                    );
                }
            }
        }

        Err(CourierError::Timeout)
    }
}

/// Returns true if the error is transient and worth retrying.
fn is_retryable(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::Status(code, _) => *code >= 500,
        ureq::Error::Transport(_) => true,
    }
}

/// Converts a `ureq::Error` to a `CourierError`.
fn ureq_to_courier_error(err: ureq::Error) -> CourierError {
    match &err {
        ureq::Error::Status(404, _) => CourierError::ProofNotFound,
        ureq::Error::Status(code, _) => {
            CourierError::Transport(format!("HTTP {}", code))
        }
        ureq::Error::Transport(t) => {
            CourierError::Transport(t.to_string())
        }
    }
}

/// Hex-encodes a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

    fn test_recipient() -> Recipient {
        Recipient {
            script_key: SerializedKey([0x02; 33]),
            asset_id: AssetId([0xAA; 32]),
            amount: 100,
        }
    }

    fn test_locator() -> CourierLocator {
        CourierLocator {
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]),
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout: 0,
            },
        }
    }

    fn test_proof() -> AnnotatedProof {
        let mut file = proof::File::new();
        file.append_proof(vec![0x01, 0x02, 0x03]);
        AnnotatedProof {
            locator: test_locator(),
            proof_file: file,
        }
    }

    /// Spins up a minimal HTTP server that stores one proof in memory.
    fn mock_server() -> (String, Arc<Mutex<Option<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let store: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let store_clone = store.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }

                // Read headers until empty line.
                let mut content_length: usize = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        content_length = line.split(':').nth(1)
                            .unwrap_or("0").trim().parse().unwrap_or(0);
                    }
                }

                if request_line.starts_with("PUT") {
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 {
                        use std::io::Read;
                        reader.read_exact(&mut body).ok();
                    }
                    *store_clone.lock().unwrap() = Some(body);
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                    stream.write_all(response.as_bytes()).ok();
                } else if request_line.starts_with("GET") {
                    let data = store_clone.lock().unwrap();
                    if let Some(ref body) = *data {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        stream.write_all(response.as_bytes()).ok();
                        stream.write_all(body).ok();
                    } else {
                        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                        stream.write_all(response.as_bytes()).ok();
                    }
                }
                stream.flush().ok();
            }
        });

        (format!("http://127.0.0.1:{}", port), store)
    }

    #[test]
    fn test_http_courier_deliver_and_receive() {
        let (base_url, _store) = mock_server();
        let cfg = HttpCourierCfg {
            base_url,
            timeout: Duration::from_secs(5),
            backoff: BackoffCfg {
                initial_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(100),
                max_retries: 3,
            },
        };
        let courier = HttpCourier::new(cfg);
        let recipient = test_recipient();
        let proof = test_proof();

        courier.deliver_proof(&recipient, &proof).unwrap();

        let received = courier
            .receive_proof(&recipient, &test_locator())
            .unwrap();
        assert_eq!(received.proof_file.num_proofs(), 1);
    }

    #[test]
    fn test_http_courier_not_found() {
        let (base_url, _store) = mock_server();
        let cfg = HttpCourierCfg {
            base_url,
            timeout: Duration::from_secs(5),
            backoff: BackoffCfg {
                initial_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(100),
                max_retries: 1, // Don't retry 404s.
            },
        };
        let courier = HttpCourier::new(cfg);

        let result = courier.receive_proof(&test_recipient(), &test_locator());
        assert!(matches!(result, Err(CourierError::ProofNotFound)));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xAA, 0xBB, 0x00]), "aabb00");
    }
}
