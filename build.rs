use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{EnumVariantValue, IntKind, ParseCallbacks};

#[derive(Debug)]
struct CustomParser();

impl ParseCallbacks for CustomParser {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.starts_with("NLA_F") || name.starts_with("NLM") || name.starts_with("GENL_ID") {
            Some(IntKind::U16)
        } else {
            None
        }
    }

    #[allow(clippy::manual_map)]
    fn enum_variant_name(
        &self,
        _: Option<&str>,
        variant_name: &str,
        _: EnumVariantValue,
    ) -> Option<String> {
        if let Some(n) = variant_name.strip_prefix("WGALLOWEDIP_A_") {
            Some(n.to_string())
        } else if let Some(n) = variant_name.strip_prefix("WGPEER_A_") {
            Some(n.to_string())
        } else if let Some(n) = variant_name.strip_prefix("WGPEER_F_") {
            Some(n.to_string())
        } else if let Some(n) = variant_name.strip_prefix("WGDEVICE_A_") {
            Some(n.to_string())
        } else if let Some(n) = variant_name.strip_prefix("WG_CMD_") {
            Some(n.to_string())
        } else {
            None
        }
    }
}

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
        .allowlist_var("NLA_F_.*")
        .allowlist_var("NLMSG_.*")
        .allowlist_var("GENL_ID_CTRL")
        .allowlist_var("RTM_.*")
        .allowlist_type("ifinfomsg")
        .allowlist_file(".*wireguard.h")
        .parse_callbacks(Box::new(CustomParser()))
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
