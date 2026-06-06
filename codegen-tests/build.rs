//! Build script, which actually runs the codegen.
//! The tests in the main library just verifies that the generated
//! code is correct.

use std::path::Path;

use opcua_codegen::{CodeGenConfig, CodeGenSource, CodeGenTarget, TypeCodeGenTarget, run_codegen};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = format!("{}/opcua_generated", out_dir);
    println!("cargo:rerun-if-changed=schemas/Async.Opcua.Test.NodeSet2.xml");
    println!("cargo:rerun-if-changed=schemas/Async.Opcua.Test.Ext.NodeSet2.xml");
    println!("cargo:rerun-if-changed=schemas/Opc.Ua.Di.NodeSet2.xml");
    println!("cargo:rerun-if-changed=schemas/Opc.Ua.Plc.NodeSet2.xml");
    println!("cargo:rustc-env=OPCUA_GENERATED_DIR={}", target_dir);
    run_codegen(
        &CodeGenConfig {
            targets: vec![
                CodeGenTarget::Types(TypeCodeGenTarget {
                    file: "Async.Opcua.Test.NodeSet2.xml".to_owned(),
                    output_dir: Path::new(&target_dir).join("base"),
                    enums_single_file: true,
                    structs_single_file: true,
                    node_ids_from_nodeset: true,
                    default_excluded: ["SimpleEnum".to_string()].into_iter().collect(),
                    ..Default::default()
                }),
                CodeGenTarget::Types(TypeCodeGenTarget {
                    file: "Async.Opcua.Test.Ext.NodeSet2.xml".to_owned(),
                    output_dir: Path::new(&target_dir).join("ext"),
                    enums_single_file: true,
                    structs_single_file: true,
                    node_ids_from_nodeset: true,
                    dependent_nodesets: vec![opcua_codegen::DependentNodeset {
                        file: "Async.Opcua.Test.NodeSet2.xml".to_owned(),
                        import_path: "crate::generated::base".to_owned(),
                    }],
                    ..Default::default()
                }),
                CodeGenTarget::Types(TypeCodeGenTarget {
                    file: "Opc.Ua.Plc.NodeSet2.xml".to_owned(),
                    output_dir: Path::new(&target_dir).join("plcopen"),
                    enums_single_file: true,
                    structs_single_file: true,
                    node_ids_from_nodeset: true,
                    dependent_nodesets: vec![opcua_codegen::DependentNodeset {
                        file: "Opc.Ua.Di.NodeSet2.xml".to_owned(),
                        import_path: "crate::generated::di".to_owned(),
                    }],
                    ..Default::default()
                }),
                CodeGenTarget::Types(TypeCodeGenTarget {
                    file: "Opc.Ua.Di.NodeSet2.xml".to_owned(),
                    output_dir: Path::new(&target_dir).join("di"),
                    enums_single_file: true,
                    structs_single_file: true,
                    node_ids_from_nodeset: true,
                    ..Default::default()
                }),
            ],
            sources: vec![
                CodeGenSource::Implicit(Path::new("./schemas").to_owned()),
                CodeGenSource::Implicit(Path::new("../schemas/1.05").to_owned()),
            ],
            extra_header: String::new(),
            preferred_locale: "en".to_string(),
        },
        Path::new("./"),
    )
    .unwrap();
}
