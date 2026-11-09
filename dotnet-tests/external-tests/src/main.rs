use std::{
    env,
    future::Future,
    panic::AssertUnwindSafe,
    process::ExitCode,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use futures::FutureExt;

use tests::run_client_tests;
use tokio::select;

pub mod client;
pub mod common;
mod tests;

#[tokio::main]
pub async fn main() -> ExitCode {
    env_logger::init();
    // Newer OpenSSL versions ban SHA1 signatures. We need them for our tests,
    // and the .NET SDK uses OpenSSL, so enable it.
    // Safety: set_var isn't thread safe, but we do not call this concurrently.
    unsafe {
        std::env::set_var("OPENSSL_ENABLE_SHA1_SIGNATURES", "1");
    }

    let runner = Runner::new();
    run_client_tests(&runner).await;

    let result = runner.result();

    println!(
        "Test run finished {} successes; {} failures",
        result.succeded, result.failed
    );

    if result.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn colored(r: i32, g: i32, b: i32, text: &str) -> String {
    format!("\x1B[38;2;{r};{g};{b}m{text}\x1B[0m")
}

struct RunnerState {
    succeeded: AtomicU32,
    failed: AtomicU32,
}

pub struct RunnerResult {
    pub succeded: u32,
    pub failed: u32,
}

pub struct Runner {
    filter: Option<String>,
    state: RunnerState,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner {
    pub fn new() -> Self {
        Self {
            filter: env::args().nth(1),
            state: RunnerState {
                succeeded: AtomicU32::new(0),
                failed: AtomicU32::new(0),
            },
        }
    }

    pub fn result(&self) -> RunnerResult {
        RunnerResult {
            succeded: self.state.succeeded.load(Ordering::Relaxed),
            failed: self.state.failed.load(Ordering::Relaxed),
        }
    }

    pub async fn run_test<Fut: Future<Output = ()>>(&self, name: &str, test: Fut) {
        if self.filter.as_ref().is_some_and(|f| !name.contains(f)) {
            return;
        }

        println!("Starting test {name}");
        let r = select! {
            r = AssertUnwindSafe(test).catch_unwind() => {
                r
            }
            _ = tokio::time::sleep(Duration::from_secs(20)) => {
                println!(" {} {name} timed out after 20 seconds", colored(255, 0, 0, "X"));
                self.state.failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        match r {
            Ok(_) => {
                println!(" {} {name}", colored(0, 255, 0, "🗸"));
                self.state.succeeded.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                if e.is::<&'static str>() {
                    println!(
                        " {} {name}: {}",
                        colored(255, 0, 0, "X"),
                        e.downcast_ref::<&'static str>().unwrap()
                    );
                } else if e.is::<String>() {
                    println!(
                        " {} {name}: {}",
                        colored(255, 0, 0, "X"),
                        e.downcast_ref::<String>().unwrap()
                    );
                } else {
                    println!(" {} {name}", colored(255, 0, 0, "X"));
                }
                self.state.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
