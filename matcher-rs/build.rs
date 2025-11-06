use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../matcher/credentialmanager.h");
    println!("cargo:rerun-if-env-changed=TARGET");

    let builder = bindgen::Builder::default()
        .header("../matcher/credentialmanager.h")
        .clang_arg("-I/usr/include")
        .clang_arg("-fvisibility=default")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
