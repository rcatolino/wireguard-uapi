use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=nl.h");
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("nl.h")
        .allowlist_type("nlmsghdr")
        .allowlist_type("nlattr")
        .allowlist_type("genlmsghdr")
        .allowlist_var("CTRL_CMD.*")
        .allowlist_var("CTRL_ATTR.*")
        .allowlist_var("NLM_F_.*")
        .allowlist_var("NLMSG_.*")
        .allowlist_var("GENL_ID_CTRL")
        .allowlist_file(".*wireguard.h")
        // .newtype_enum("wg.*")
        .constified_enum_module("wg.*")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}