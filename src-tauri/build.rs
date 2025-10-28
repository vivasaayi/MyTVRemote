fn main() {
    println!("cargo:rerun-if-changed=src/polo.proto");
    println!("cargo:rerun-if-changed=src/remotemessage.proto");
    prost_build::Config::new()
        .compile_protos(&["src/polo.proto", "src/remotemessage.proto"], &["src"])
        .expect("failed to compile protobuf files");
    tauri_build::build();
}
