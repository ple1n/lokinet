fn main() {
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    pkg_config::Config::new()
        .probe("lokinet-embedded")
        .expect("lokinet-embedded not found; build it with `nix build .#lokinet-embedded` or enter `nix develop`");
}
