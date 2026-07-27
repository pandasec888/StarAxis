#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    vaultx_desktop_lib::run();
}
