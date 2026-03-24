// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Exponential backoff handler for courier retry logic.

use std::time::Duration;

/// Configuration for exponential backoff.
#[derive(Clone, Debug)]
pub struct BackoffCfg {
    /// Initial delay between retries.
    pub initial_backoff: Duration,
    /// Maximum delay between retries.
    pub max_backoff: Duration,
    /// Maximum number of retry attempts.
    pub max_retries: u32,
}

impl Default for BackoffCfg {
    fn default() -> Self {
        BackoffCfg {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            max_retries: 2000,
        }
    }
}

/// Executes a closure with exponential backoff retry.
///
/// Calls `op` repeatedly until it returns `Ok`, or `max_retries` is exhausted.
/// The delay between attempts doubles each time, capped at `max_backoff`.
///
/// Returns the successful result, or the last error if retries are exhausted.
pub fn with_backoff<T, E, F>(cfg: &BackoffCfg, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut delay = cfg.initial_backoff;

    for attempt in 0..cfg.max_retries {
        match op() {
            Ok(val) => return Ok(val),
            Err(e) => {
                if attempt + 1 >= cfg.max_retries {
                    return Err(e);
                }
                std::thread::sleep(delay);
                delay = std::cmp::min(delay * 2, cfg.max_backoff);
            }
        }
    }

    // Should not reach here, but satisfy the compiler.
    op()
}

/// Computes the backoff delay for a given attempt number.
///
/// Useful for callers that want to manage their own retry loop.
pub fn delay_for_attempt(cfg: &BackoffCfg, attempt: u32) -> Duration {
    let mut delay = cfg.initial_backoff;
    for _ in 0..attempt {
        delay = std::cmp::min(delay * 2, cfg.max_backoff);
    }
    delay
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn test_immediate_success() {
        let cfg = BackoffCfg {
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_retries: 3,
        };
        let result: Result<u32, &str> = with_backoff(&cfg, || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_success_after_retries() {
        let cfg = BackoffCfg {
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            max_retries: 5,
        };

        let attempts = Cell::new(0u32);
        let result: Result<u32, &str> = with_backoff(&cfg, || {
            let n = attempts.get();
            attempts.set(n + 1);
            if n < 2 {
                Err("not yet")
            } else {
                Ok(42)
            }
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn test_exhausted_retries() {
        let cfg = BackoffCfg {
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            max_retries: 3,
        };

        let result: Result<u32, &str> =
            with_backoff(&cfg, || Err("always fails"));
        assert!(result.is_err());
    }

    #[test]
    fn test_delay_for_attempt() {
        let cfg = BackoffCfg {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            max_retries: 100,
        };

        assert_eq!(delay_for_attempt(&cfg, 0), Duration::from_secs(2));
        assert_eq!(delay_for_attempt(&cfg, 1), Duration::from_secs(4));
        assert_eq!(delay_for_attempt(&cfg, 2), Duration::from_secs(8));
        assert_eq!(delay_for_attempt(&cfg, 3), Duration::from_secs(16));
        assert_eq!(delay_for_attempt(&cfg, 4), Duration::from_secs(32));
        assert_eq!(delay_for_attempt(&cfg, 5), Duration::from_secs(60)); // capped
        assert_eq!(delay_for_attempt(&cfg, 10), Duration::from_secs(60)); // still capped
    }
}
