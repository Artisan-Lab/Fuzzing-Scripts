use std::path::PathBuf;
use std::process::Command;

const RULF_ARG_DIR: &str = "/opt/rulf/rulf-cmd";

fn rulf_script(crate_name: &str) -> PathBuf {
    PathBuf::from(RULF_ARG_DIR).join(crate_name)
}

pub fn prepare_test_files(crate_name: &str) {
    use super::CRATE_SRC_DIR;
    let src_dir = CRATE_SRC_DIR.get(crate_name).unwrap();
    // run cargo doc
    debug!("cargo doc");
    Command::new("cargo")
        .arg("doc")
        .current_dir(src_dir)
        .status()
        .unwrap();
    // run rulf
    let command = rulf_script(crate_name);
    Command::new(command).current_dir(src_dir).status().unwrap();
    // run cargo clean
    debug!("cargo clean");
    Command::new("cargo")
        .arg("clean")
        .current_dir(src_dir)
        .status()
        .unwrap();
}
