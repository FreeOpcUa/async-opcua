//! Build script, which actually runs the codegen.
//! The tests in the main library just verifies that the generated
//! code is correct.

use opcua_codegen::{CodeGenConfig, CodeGenSource, CodeGenTarget, TypeCodeGenTarget, run_codegen};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = format!("{}/opcua_generated", out_dir);
    println!("cargo:rustc-env=OPCUA_GENERATED_DIR={}", target_dir);
    run_codegen(
        &CodeGenConfig {
            targets: vec![CodeGenTarget::Types(TypeCodeGenTarget {
                file: "Async.Opcua.Test.NodeSet2.xml".to_owned(),
                output_dir: target_dir,
                enums_single_file: true,
                structs_single_file: true,
                node_ids_from_nodeset: true,
                default_excluded: ["SimpleEnum".to_string()].into_iter().collect(),
                ..Default::default()
            })],
            sources: vec![
                CodeGenSource::Implicit("./schemas".to_owned()),
                CodeGenSource::Implicit("../schemas/1.05".to_owned()),
            ],
            extra_header: String::new(),
            preferred_locale: "en".to_string(),
        },
        "./",
    )
    .unwrap();
}
