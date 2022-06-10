use super::{ensure_dir, ensure_empty_dir, find_crash};
use super::{CRATE_TEST_DIR, EDITION, TMIN_OUTPUT_DIR};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::exit;
use std::process::{Command, Stdio};
use std::thread;

pub fn multi_thread_tmin(crate_name: &str) {
    let all_crash_files = find_crash(crate_name);
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let tmin_output_path = test_path.join(TMIN_OUTPUT_DIR);
    ensure_empty_dir(&tmin_output_path);
    if all_crash_files.is_empty() {
        warn!("No crash files.");
        exit(-1);
    }
    debug!("total crashes = {}", all_crash_files.len());

    let mut crash_counts = HashMap::new();
    let mut handlers = Vec::new();
    all_crash_files.iter().for_each(|crash| {
        let crash_file_name = crash.to_str().unwrap();
        debug!("crash_file_name = {}", crash_file_name);
        let file_name_split: Vec<&str> = crash_file_name.split('/').collect();
        let file_name_split_len = file_name_split.len();
        if file_name_split_len < 4 {
            error!("Invalid crash file name");
            exit(-1);
        }
        let test_crate_name = file_name_split[file_name_split_len - 4];
        let test_tmin_output_path = tmin_output_path.clone().join(test_crate_name);
        ensure_dir(&test_tmin_output_path);
        let crash_count = if crash_counts.contains_key(test_crate_name) {
            let current_count = *(crash_counts.get(test_crate_name).unwrap()) + 1;
            crash_counts.insert(test_crate_name, current_count);
            current_count
        } else {
            crash_counts.insert(test_crate_name, 1);
            1
        };
        let target_path = test_path
            .clone()
            .join("target")
            .join(EDITION)
            .join(test_crate_name);
        let target_file_name = target_path.to_str().unwrap();
        let tmin_output_file = test_tmin_output_path.join(crash_count.to_string());
        let tmin_output_filename = tmin_output_file.to_str().unwrap();
        let tmin_input_filename = crash.to_str().unwrap();
        let args = vec![
            "afl",
            "tmin",
            "-i",
            tmin_input_filename,
            "-o",
            tmin_output_filename,
            target_file_name,
        ];
        let args: Vec<_> = args.iter().map(ToString::to_string).collect();
        let handler = thread::spawn(move || {
            Command::new("cargo")
                .args(args)
                .stdout(Stdio::null())
                .status()
                .unwrap();
        });
        handlers.push(handler);
    });
    for handler in handlers {
        let _ = handler.join();
    }
}
