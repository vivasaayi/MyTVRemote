fn main() {
    println!("cargo:rerun-if-changed=src/polo.proto");
    prost_build::Config::new()
        .compile_protos(&["src/polo.proto"], &["src"])
        .expect("failed to compile polo.proto");
    tauri_build::build();
}
