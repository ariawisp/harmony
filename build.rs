fn main() {
    #[cfg(target_os = "macos")]
    {
        // Ensure the produced cdylib uses @rpath so downstream binaries can resolve it via rpath.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libopenai_harmony.dylib");
    }
}
