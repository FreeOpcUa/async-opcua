use env_logger::Env;
use opcua_codegen::{run_codegen, CodeGenConfig, CodeGenError};

fn main() -> Result<(), CodeGenError> {
    run_cli()
}

fn run_cli() -> Result<(), CodeGenError> {
    let mut args = std::env::args();
    env_logger::init_from_env(Env::new().filter_or("RUST_LOG", "debug"));

    if args.len() != 2 {
        // Deliberately println instead of using the logger.
        println!(
            r#"Usage:
async-opcua-codegen [config].yml
"#
        );
        return Ok(());
    }

    let config_path = args.nth(1).unwrap();

    let root_path = std::path::Path::new(&config_path)
        .parent()
        .expect("Invalid config file path");

    let config_text =
        std::fs::read_to_string(&config_path).expect("Failed to read config from file");
    let config: CodeGenConfig =
        serde_yaml::from_str(&config_text).expect("Failed to parse config file");

    let mut path_str = root_path
        .to_str()
        .expect("Config file path must be a valid UTF-8 string");
    if path_str.is_empty() {
        path_str = ".";
    }

    run_codegen(&config, path_str)?;

    Ok(())
}
