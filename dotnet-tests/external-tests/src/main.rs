use std::{env, future::Future, panic::AssertUnwindSafe, time::Duration};

use futures::FutureExt;

use tests::run_client_tests;
use tokio::select;

pub mod client;
pub mod common;
mod tests;

#[tokio::main]
pub async fn main() {
    env_logger::init();

    let runner = Runner::new();
    run_client_tests(&runner).await
}

fn colored(r: i32, g: i32, b: i32, text: &str) -> String {
    format!("\x1B[38;2;{};{};{}m{}\x1B[0m", r, g, b, text)
}

pub struct Runner {
    filter: Option<String>,
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
                return;
            }
        };
        match r {
            Ok(_) => println!(" {} {name}", colored(0, 255, 0, "🗸")),
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
            }
        }
    }
}
