#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate config;
extern crate regex;

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Output, Stdio};
use std::str;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

mod prepare;
mod tmin;

// const CRATES_IO_DIR: &'static str = "github.com-1ecc6299db9ec823/";
const USTC_MIRROR_DIR: &str = "mirrors.ustc.edu.cn-61ef6e0cd06fb9b8/";
const USER_HOME: &str = "/home/jjf/";

lazy_static! {
    static ref CRATES: HashSet<&'static str> = {
        let mut m = HashSet::new();
        m.insert("url");
        m.insert("regex-syntax");
        m.insert("semver-parser");
        // m.insert("bat");
        // m.insert("xi-core-lib");
        m.insert("clap");
        m.insert("regex");
        m.insert("serde_json");
        // m.insert("tui");
        m.insert("semver");
        m.insert("http");
        m.insert("flate2");
        // m.insert("smoltcp");
        m.insert("proc-macro2");
        m.insert("time");
        m.insert("base64");
        //fudge like crates
        // m.insert("fudge_like_url");
        // m.insert("fudge_like_regex");
        // m.insert("fudge_like_time");

        //fudge crates
        // m.insert("fudge_url");
        // m.insert("fudge_regex");
        // m.insert("fudge_time");

        m
    };
}

lazy_static! {
    static ref CRATE_SRC_DIR: HashMap<&'static str, String> = {
        let mut m = HashMap::new();
        let src_directory = USER_HOME.to_string() + ".cargo/registry/src/" + USTC_MIRROR_DIR;
        m.insert("url", src_directory.clone() + "url-2.2.0");
        m.insert("regex-syntax", src_directory.clone() + "regex-syntax-0.6.22");
        m.insert("semver-parser", src_directory.clone() + "semver-parser-0.10.2");
        m.insert("bat", "/home/jjf/bat".to_string());
        m.insert("xi-core-lib", "/home/jjf/xi-editor/rust".to_string());
        m.insert("clap", src_directory.clone() + "clap-2.33.3");
        m.insert("regex", src_directory.clone() + "regex-1.4.3");
        m.insert("serde_json", src_directory.clone() + "serde_json-1.0.61");
        m.insert("tui", "/home/jjf/tui-rs".to_string());
        m.insert("semver", src_directory.clone() + "semver-0.11.0");
        m.insert("http", src_directory.clone() + "http-0.2.6");
        m.insert("flate2", src_directory.clone() + "flate2-1.0.19");
        m.insert("smoltcp", "/home/jjf/smoltcp".to_string());
        m.insert("proc-macro2", src_directory.clone() + "proc-macro2-1.0.24");
        m.insert("time", src_directory.clone() + "time-0.2.24");
        m.insert("base64", src_directory + "base64-0.13.0");

        //fudge_like
        m.insert("fudge_like_url", "/home/jjf/Fudge-Like-Targets/url/fudge_like_url".to_string());
        m.insert("fudge_like_regex", "/home/jjf/Fudge-Like-Targets/regex/fudge_like_regex".to_string());
        m.insert("fudge_like_time", "/home/jjf/Fudge-Like-Targets/time/fudge_like_time".to_string());

        //fudge
        m.insert("fudge_url", "/home/jjf/Fudge-Like-Targets/url/fudge_url".to_string());
        m.insert("fudge_regex", "/home/jjf/Fudge-Like-Targets/regex/fudge_regex".to_string());
        m.insert("fudge_time", "/home/jjf/Fudge-Like-Targets/time/fudge_time".to_string());
        m
    };
}

lazy_static! {
    static ref CRATE_TEST_DIR: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("url", "/home/jjf/afl_fast_work/url_afl_work");
        m.insert("regex-syntax", "/home/jjf/afl_fast_work/regex-syntax-afl-work");
        m.insert("semver-parser", "/home/jjf/afl_fast_work/semver-parser-afl-work");
        m.insert("bat", "/home/jjf/afl_fast_work/bat-afl-work");
        m.insert("xi-core-lib", "/home/jjf/afl_fast_work/xi-core-lib-afl-work");
        m.insert("clap", "/home/jjf/afl_fast_work/clap-afl-work");
        m.insert("regex", "/home/jjf/afl_fast_work/regex-afl-work");
        m.insert("serde_json", "/home/jjf/afl_fast_work/serde-json-afl-work");
        m.insert("tui", "/home/jjf/afl_fast_work/tui-afl-work");
        m.insert("semver", "/home/jjf/afl_fast_work/semver-afl-work");
        m.insert("http", "/home/jjf/afl_fast_work/http-afl-work");
        m.insert("flate2", "/home/jjf/afl_fast_work/flate2-afl-work");
        m.insert("smoltcp", "/home/jjf/afl_fast_work/smoltcp-afl-work");
        m.insert("proc-macro2", "/home/jjf/afl_fast_work/proc-macro2-afl-work");
        m.insert("time", "/home/jjf/afl_fast_work/time-afl-work");
        m.insert("base64", "/home/jjf/afl_fast_work/base64-afl-work");
        //fudge like project
        m.insert("fudge_like_url", "/home/jjf/fudge_like_work/url-work");
        m.insert("fudge_like_regex", "/home/jjf/fudge_like_work/regex-work");
        m.insert("fudge_like_time", "/home/jjf/fudge_like_work/time-work");

        //fudge project
        m.insert("fudge_url", "/home/jjf/fudge_work/url-work");
        m.insert("fudge_regex", "/home/jjf/fudge_work/regex-work");
        m.insert("fudge_time", "/home/jjf/fudge_work/time-work");

        m
    };
}

lazy_static! {
    static ref CRATE_VERSION: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("url", "\"= 2.2.0\"");
        m.insert("regex-syntax", "\"= 0.6.22\"");
        m.insert("semver-parser", "\"= 0.10.2\"");
        m.insert("bat", "\"*\"");
        m.insert("xi-core-lib", "\"*\"");
        m.insert("clap", "\"= 2.33.3\"");
        m.insert("regex", "\"= 1.4.3\"");
        m.insert("serde_json", "\"= 1.0.61\"");
        m.insert("tui", "\"*\"");
        m.insert("semver", "\"= 0.11.0\"");
        m.insert("http", "\"= 0.2.6\"");
        m.insert("flate2", "\"= 1.0.19\"");
        m.insert("smoltcp", "\"*\"");
        m.insert("proc-macro2", "\"= 1.0.24\"");
        m.insert("time", "\"= 0.2.24\"");
        m.insert("base64", "\"= 0.13.0\"");

        //fudge_like
        m.insert("fudge_like_url", "\"*\"");
        m.insert("fudge_like_regex", "\"*\"");
        m.insert("fudge_like_time", "\"*\"");

        //fudge
        m.insert("fudge_url", "\"*\"");
        m.insert("fudge_regex", "\"*\"");
        m.insert("fudge_time", "\"*\"");
        m
    };
}

lazy_static! {
    static ref CRATE_PATCH_PATH: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        //m.insert("url", "{path=\"/home/jjf/rust-url/url\"}");
        m.insert("bat", "{path=\"/home/jjf/bat\"}");
        m.insert("xi-core-lib", "{path=\"/home/jjf/xi-editor/rust/core-lib\"}");
        m.insert("tui", "{path=\"/home/jjf/tui-rs\"}");
        m.insert("smoltcp", "{path=\"/home/jjf/smoltcp\"}");

        //fudge-like
        m.insert("fudge_like_url", "{path=\"/home/jjf/Fudge-Like-Targets/url/fudge_like_url\"}");
        m.insert("fudge_like_regex", "{path=\"/home/jjf/Fudge-Like-Targets/regex/fudge_like_regex\"}");
        m.insert("fudge_like_time", "{path=\"/home/jjf/Fudge-Like-Targets/time/fudge_like_time\"}");

        //fudge
        m.insert("fudge_url", "{path=\"/home/jjf/Fudge-Like-Targets/url/fudge_url\"}");
        m.insert("fudge_regex", "{path=\"/home/jjf/Fudge-Like-Targets/regex/fudge_regex\"}");
        m.insert("fudge_time", "{path=\"/home/jjf/Fudge-Like-Targets/time/fudge_time\"}");
        m
    };
}

lazy_static! {
    static ref INVALID_TARGET_NUMBER: HashMap<&'static str, usize> = {
        let mut m = HashMap::new();
        m.insert("proc-macro2", 1);
        m.insert("clap", 4);
        m.insert("syn", 1);
        m
    };
}

const CRASH_DIR: &str = "default/crashes";
const TEST_FILE_DIR: &str = "test_files";
const REPLAY_FILE_DIR: &str = "replay_files";
const AFL_INPUT_DIR: &str = "afl_init";
const AFL_OUTPUT_DIR: &str = "out";
const CARGO_TOML: &str = "Cargo.toml";
const BUILD_SCRIPT: &str = "build";
const AFL_DEPENDENCY: &str = "afl = \"=0.11.1\"";
const TMIN_OUTPUT_DIR: &str = "tmin_output";
const CMIN_OUTPUT_DIR: &str = "cmin_output";
const STATISTIC_OUTPUT_FILE: &str = "statistics";
const EDITION: &str = "debug";
const EXIT_TIME_DIR: &str = "exit_time";
const SHOWMAP_DIR: &str = "showmap";

#[derive(Debug, Clone)]
struct UserOptions {
    crate_name: Option<String>,
    find_literal: Option<usize>,
    check: bool,
    clean: bool,
    build: bool,
    fuzz: bool,
    crash: bool,
    prepare: bool,
    tmin: bool,
    cmin: bool,
    replay: bool,
    statistic: bool,
    showmap: bool,
    init_afl_input: bool,
    all: bool,
}

impl UserOptions {
    fn new() -> Self {
        UserOptions {
            crate_name: None,
            find_literal: None,
            check: false,
            clean: false,
            build: false,
            all: false,
            crash: false,
            fuzz: false,
            prepare: false,
            tmin: false,
            cmin: false,
            statistic: false,
            showmap: false,
            replay: false,
            init_afl_input: false,
        }
    }

    fn new_from_cli(args: Vec<String>) -> Self {
        let mut user_options = UserOptions::new();
        user_options.extract_options(args);
        user_options
    }

    fn extract_options(&mut self, args: Vec<String>) {
        let mut args_iter = args.iter();
        let _ = args_iter.next(); //把程序名字跳过

        let list_option = Regex::new("(-l$|--list)").unwrap();
        let find_literal_option = Regex::new("(-f$|--find-literal)").unwrap();
        let check_option = Regex::new("(-c$|--check)").unwrap();
        let clean_option = Regex::new("-clean").unwrap();
        let build_option = Regex::new("(-b$|--build)").unwrap();
        let fuzz_option = Regex::new("-fuzz").unwrap();
        let all_option = Regex::new("(-a$|--all)").unwrap();
        let help_option = Regex::new("(-h$|--help)").unwrap();
        let crash_option = Regex::new("-crash").unwrap();
        let prepare_option = Regex::new("(-p$|--prepare)").unwrap();
        let tmin_option = Regex::new("(-t$|--tmin)").unwrap();
        let cmin_option = Regex::new("-cmin").unwrap();
        let statistic_option = Regex::new("(-s$|--statistic)").unwrap();
        let showmap_option = Regex::new("-showmap").unwrap();
        let replay_option = Regex::new("(-r$|--replay)").unwrap();
        let init_afl_input_option = Regex::new("(-i$|--init)").unwrap();

        while let Some(s) = args_iter.next() {
            if list_option.is_match(s.as_str()) {
                list_crates();
                exit(0);
            }
            if help_option.is_match(s.as_str()) {
                println!("{}", help_message());
                exit(0);
            }
            if find_literal_option.is_match(s.as_str()) {
                if let Some(input_number) = args_iter.next() {
                    let input_number = input_number.parse::<usize>();
                    if let Ok(input_number) = input_number {
                        self.find_literal = Some(input_number);
                        continue;
                    }
                }
                error!("Invalid -f/find_literal flag.");
                exit(-1);
            }
            if check_option.is_match(s.as_str()) {
                self.check = true;
                continue;
            }
            if clean_option.is_match(s.as_str()) {
                self.clean = true;
                continue;
            }
            if build_option.is_match(s.as_str()) {
                self.build = true;
                continue;
            }
            if fuzz_option.is_match(s.as_str()) {
                self.fuzz = true;
                continue;
            }
            if all_option.is_match(s.as_str()) {
                self.all = true;
                continue;
            }
            if crash_option.is_match(s.as_str()) {
                self.crash = true;
                continue;
            }
            if prepare_option.is_match(s.as_str()) {
                self.prepare = true;
                continue;
            }
            if tmin_option.is_match(s.as_str()) {
                self.tmin = true;
                continue;
            }
            if cmin_option.is_match(s.as_str()) {
                self.cmin = true;
                continue;
            }
            if replay_option.is_match(s.as_str()) {
                self.replay = true;
                continue;
            }
            if statistic_option.is_match(s.as_str()) {
                self.statistic = true;
                continue;
            }
            if showmap_option.is_match(s.as_str()) {
                self.showmap = true;
                continue;
            }
            if init_afl_input_option.is_match(s.as_str()) {
                self.init_afl_input = true;
                continue;
            }
            if self.crate_name.is_none() && CRATES.contains(s.as_str()) {
                self.crate_name = Some(s.clone());
                continue;
            }
            error!("Invalid Options.");
            exit(-1);
        }
        if self.crate_name.is_none() {
            error!("No valid crate is provided.");
            exit(-1);
        }
    }
}

fn list_crates() {
    for crate_name in CRATES.iter() {
        println!("{}", crate_name);
    }
}

fn help_message() -> &'static str {
    "afl_scripts 0.1.0

USAGE: 
    afl_scripts FLAGS CRATE_NAME
        
FLAGS:
    -l,--list           list all supported crates
    -h,--help           print help message
    -f,--find_literal   find literals(example: -f 3 url)
    -c,--check          check precondition
    -clean              clean test directory(may corrupt history data)
    -b,--build          init test directory and build afl test files
    -fuzz               run afl
    -a,--all            clean,build,and fuzz(may corrupt history data)
    -crash              check if any crash was found
    -p,--prepare        prepare test files
    -t,--tmin           use afl tmin to reduce test file size
    -cmin               use afl cmin to reduce test file number
    -r,--replay         replay crash files to check whether it's real crash
    -s,--statistic      output statictic fuzz result info for a crate
    -i,--init           init afl input files for each target
"
    //-showmap            output coverage infomation generated by showmap(showmap is not well designed)
}

fn do_work(user_options: &UserOptions) {
    let crate_name = user_options.crate_name.as_ref().unwrap();
    if user_options.check {
        info!("check {}.", crate_name);
        check_pre_condition(crate_name);
        exit(0);
    }
    if user_options.find_literal.is_some() {
        info!("find literal for {}.", crate_name);
        do_find_literal(crate_name, user_options.find_literal.unwrap().to_string());
        exit(0);
    }
    if user_options.prepare {
        info!("prepare test files for {}.", crate_name);
        prepare::prepare_test_files(crate_name);

        exit(0);
    }
    if user_options.clean {
        info!("clean {}.", crate_name);
        clean(crate_name);
        exit(0);
    }
    if user_options.crash {
        info!("find crash files for {}.", crate_name);
        print_crashes(crate_name);
        exit(0);
    }

    if user_options.build {
        info!("build {}.", crate_name);
        let tests = check_pre_condition(crate_name);
        init_test_dir(crate_name, &tests);
        build_afl_tests(crate_name);
        init_afl_input(crate_name);
        check_build(crate_name, &tests);
        exit(0);
    }
    if user_options.fuzz {
        info!("fuzz {}.", crate_name);
        let tests = check_pre_condition(crate_name);
        check_build(crate_name, &tests);
        fuzz_it(crate_name, &tests);
        exit(0);
    }
    if user_options.tmin {
        info!("run afl-tmin for {}.", crate_name);
        // tmin(crate_name);
        tmin::multi_thread_tmin(crate_name);
        exit(0);
    }
    if user_options.cmin {
        info!("run afl-cmin for {}", crate_name);
        cmin(crate_name);
        exit(0);
    }
    if user_options.replay {
        info!("replay crash files for {}.", crate_name);
        replay_crashes(crate_name);
        exit(0);
    }
    if user_options.statistic {
        info!("statistics for {}.", crate_name);
        output_statistics(crate_name);
        exit(0);
    }
    if user_options.showmap {
        info!("run afl-showmap for {}.", crate_name);
        showmap(crate_name);
        exit(0);
    }
    if user_options.init_afl_input {
        info!("init afl input for {}.", crate_name);
        let tests = check_pre_condition(crate_name);
        check_build(crate_name, &tests);
        init_afl_input(crate_name);
        exit(0);
    }
    if user_options.all {
        let tests = check_pre_condition(crate_name);
        clean(crate_name);
        init_test_dir(crate_name, &tests);
        build_afl_tests(crate_name);
        init_afl_input(crate_name);
        check_build(crate_name, &tests);
        fuzz_it(crate_name, &tests);
        exit(0);
    }
    //default work
    let tests = check_pre_condition(crate_name);
    init_test_dir(crate_name, &tests);
    build_afl_tests(crate_name);
    check_build(crate_name, &tests);
    fuzz_it(crate_name, &tests);
}

fn do_find_literal(crate_name: &str, input_number: String) {
    let input_dir = CRATE_SRC_DIR.get(crate_name).unwrap().to_string();
    let output_dir = CRATE_TEST_DIR.get(crate_name).unwrap().to_string();
    let args = vec![
        "-i",
        input_dir.as_str(),
        "-o",
        output_dir.as_str(),
        "-n",
        input_number.as_str(),
    ];
    Command::new("find_literal")
        .args(args)
        .output()
        .unwrap_or_else(|_| {
            error!("find_literal encounter problems.");
            exit(-1);
        });
}

pub fn print_output(output: Output) {
    let stdout = &output.stdout;
    if !stdout.is_empty() {
        println!("{}", str::from_utf8(stdout.as_slice()).unwrap());
    }
    let stderr = &output.stderr;
    if !stderr.is_empty() {
        eprintln!("{}", str::from_utf8(stderr.as_slice()).unwrap());
    }
}

// 检查一个crate的前置条件是否满足，包括
// test_files, replay_files, afl_init
pub fn check_pre_condition(crate_name: &str) -> Vec<String> {
    check_static();

    let crate_test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let crate_test_path = PathBuf::from(crate_test_dir);

    let afl_init_dir = crate_test_path.join(AFL_INPUT_DIR);
    check_no_empty_directory(&afl_init_dir);
    let test_file_dir = crate_test_path.join(TEST_FILE_DIR);
    let test_file_entries = check_no_empty_directory(&test_file_dir);

    let replay_file_dir = crate_test_path.join(REPLAY_FILE_DIR);
    let replay_file_entries = check_no_empty_directory(&replay_file_dir);

    let mut test_filenames = Vec::new();
    check_rs_file(&test_file_entries, &mut test_filenames);

    let mut replay_filenames = Vec::new();
    check_rs_file(&replay_file_entries, &mut replay_filenames);

    for test_file in &test_filenames {
        let replay_file = test_file.clone().replace("test", "replay");
        if !replay_filenames.contains(&replay_file) {
            error!("replay file dost not exist for test file {}.", test_file);
            exit(-1);
        }
    }
    test_filenames
}

fn check_static() {
    for crate_name in CRATES.iter() {
        if !CRATE_SRC_DIR.contains_key(crate_name) {
            error!("{} not set src dir.", crate_name);
            exit(-1);
        }
        if !CRATE_TEST_DIR.contains_key(crate_name) {
            error!("{} not set test dir.", crate_name);
            exit(-1);
        }
        if !CRATE_VERSION.contains_key(crate_name) {
            error!("{} not set version", crate_name);
            exit(-1);
        }
    }
}

fn check_maybe_empty_directory(dir: &Path) -> Vec<PathBuf> {
    if !dir.is_dir() {
        return Vec::new();
    }
    let file_entry = fs::read_dir(dir).unwrap();
    file_entry
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap()
}

fn check_no_empty_directory(dir: &Path) -> Vec<PathBuf> {
    let file_entries = check_maybe_empty_directory(dir);
    if file_entries.is_empty() {
        error!("No file in {:?}.", dir);
        exit(-1);
    }
    file_entries
}

fn check_rs_file(file_entries: &[PathBuf], filenames: &mut Vec<String>) {
    let regex = Regex::new(r"^(\w|_)+.rs$").unwrap();
    for pathbuf in file_entries {
        let last_file = last_file_name(pathbuf);
        if regex.is_match(last_file) && pathbuf.is_file() {
            filenames.push(last_file.to_string().replace(".rs", ""));
        } else {
            error!("Invalid file {} was found.", last_file);
            exit(-1);
        }
    }
}

fn last_file_name(path: &Path) -> &str {
    let filename = path.to_str().unwrap();
    let filename: Vec<&str> = filename.split('/').collect();
    filename.last().unwrap()
}

fn clean(crate_name: &str) {
    let except_files = vec![AFL_INPUT_DIR, REPLAY_FILE_DIR, TEST_FILE_DIR];
    let crate_test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(crate_test_dir);

    let file_entries = check_maybe_empty_directory(&test_path);
    for file_entry in &file_entries {
        if !except_files.contains(&last_file_name(file_entry)) {
            if file_entry.is_dir() {
                fs::remove_dir_all(file_entry).unwrap_or_else(|_| {
                    error!("Encounter error when removing {:?}.", file_entry);
                    exit(-1);
                });
            }
            if file_entry.is_file() {
                fs::remove_file(file_entry).unwrap_or_else(|_| {
                    error!("Encounter error when removing {:?}.", file_entry);
                    exit(-1);
                });
            }
        }
    }
}

fn init_test_dir(crate_name: &str, tests: &[String]) {
    info!("Init test project");
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    //生成输出目录
    let output_dir = test_path.join(AFL_OUTPUT_DIR);
    fs::create_dir_all(&output_dir).unwrap_or_else(|_| {
        error!("Encounter error when creating {:?}.", output_dir);
        exit(-1);
    });

    //生成cargo.toml内容
    let cargo_toml_path = test_path.join(CARGO_TOML);
    let mut cargo_toml_file = fs::File::create(&cargo_toml_path).unwrap_or_else(|_| {
        error!("Encounter error when creating {:?}.", cargo_toml_path);
        exit(-1);
    });
    let cargo_content = cargo_workspace_file_content(tests);
    cargo_toml_file
        .write_all(cargo_content.as_bytes())
        .unwrap_or_else(|_| {
            error!("write file {:?} failed.", cargo_toml_file);
            exit(-1);
        });

    //对于每个test_file新建项目
    for test in tests {
        let test_cargo_path = test_path.clone().join(test);
        let _ = Command::new("cargo")
            .arg("new")
            .arg(test_cargo_path.as_os_str())
            .output()
            .unwrap();
    }

    //对于每个replay_file新建项目
    let mut replays = Vec::new();
    for test in tests {
        let replay = test.clone().replace("test", "replay");
        let replay_cargo_path = test_path.clone().join(&replay);
        replays.push(replay);
        let _ = Command::new("cargo")
            .arg("new")
            .arg(replay_cargo_path.as_os_str())
            .output()
            .unwrap();
    }

    //生成build script(貌似没必要)
    let build_script_path = test_path.join(BUILD_SCRIPT);
    let mut build_script_file = fs::File::create(&build_script_path).unwrap_or_else(|_| {
        error!("Encounter error when creating {:?}.", build_script_path);
        exit(-1);
    });
    let build_script = build_script_content(&test_path);
    build_script_file
        .write_all(build_script.as_bytes())
        .unwrap_or_else(|_| {
            error!("write file {:?} failed.", build_script_file);
            exit(-1);
        });
    Command::new("chmod")
        .arg("+x")
        .arg(build_script_path.as_os_str())
        .status()
        .unwrap();

    //为每个test crate添加依赖
    for test in tests {
        let test_cargo_toml_path = test_path.clone().join(test).join(CARGO_TOML);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&test_cargo_toml_path)
            .unwrap_or_else(|_| {
                error!("can't open file {:?}.", test_cargo_toml_path);
                exit(-1);
            });
        file.write_all(AFL_DEPENDENCY.as_bytes())
            .unwrap_or_else(|_| {
                error!("write file {:?} failed.", test_cargo_toml_path);
                exit(-1);
            });
        file.write_all("\n".as_bytes()).unwrap();
        let version = if CRATE_PATCH_PATH.contains_key(crate_name) {
            CRATE_PATCH_PATH.get(crate_name).unwrap()
        } else {
            CRATE_VERSION.get(crate_name).unwrap()
        };

        let crate_dependency = format!("{} = {}\n", crate_name, version);
        file.write_all(crate_dependency.as_bytes())
            .unwrap_or_else(|_| {
                error!("write file {:?} failed.", test_cargo_toml_path);
                exit(-1);
            });
    }

    //为每个replay crate添加依赖
    for replay in &replays {
        let replay_cargo_toml_path = test_path.clone().join(replay).join(CARGO_TOML);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&replay_cargo_toml_path)
            .unwrap_or_else(|_| {
                error!("can't open file {:?}.", replay_cargo_toml_path);
                exit(-1);
            });
        let version = if CRATE_PATCH_PATH.contains_key(crate_name) {
            CRATE_PATCH_PATH.get(crate_name).unwrap()
        } else {
            CRATE_VERSION.get(crate_name).unwrap()
        };
        let crate_dependency = format!("{} = {}\n", crate_name, version);
        file.write_all(crate_dependency.as_bytes())
            .unwrap_or_else(|_| {
                error!("write file {:?} failed.", replay_cargo_toml_path);
                exit(-1);
            });
    }

    //复制测试文件
    for test in tests {
        let to_path = test_path.clone().join(test).join("src").join("main.rs");
        let mut test_name = test.clone();
        test_name.push_str(".rs");
        let from_path = test_path.clone().join(TEST_FILE_DIR).join(test_name);
        Command::new("cp")
            .arg(from_path.as_os_str())
            .arg(to_path.as_os_str())
            .output()
            .unwrap();
    }

    //复制replay文件
    for replay in &replays {
        let to_path = test_path.clone().join(replay).join("src").join("main.rs");
        let mut replay_name = replay.clone();
        replay_name.push_str(".rs");
        let from_path = test_path.clone().join(REPLAY_FILE_DIR).join(replay_name);
        Command::new("cp")
            .arg(from_path.as_os_str())
            .arg(to_path.as_os_str())
            .output()
            .unwrap();
    }
}

fn cargo_workspace_file_content(tests: &[String]) -> String {
    let mut content = "[workspace]\nmembers = [\n".to_string();
    for test in tests {
        let one_test = format!("\t\"{}\",\n", test);
        content.push_str(one_test.as_str());
        let one_replay = one_test.replace("test", "replay");
        content.push_str(one_replay.as_str());
    }
    content.push_str("]\n");
    content
}

fn build_script_content(test_path: &Path) -> String {
    format!(
        "cd {:?}
cargo afl build
cd -",
        test_path
    )
    .replace('\"', "")
}

fn build_afl_tests(crate_name: &str) {
    info!("build afl projects.");
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    Command::new("cargo")
        .arg("afl")
        .arg("build")
        .arg("--offline")
        .current_dir(test_path.as_os_str())
        .output()
        .unwrap();
}

fn check_build(crate_name: &str, tests: &[String]) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let target_path = test_path.join("target").join(EDITION);

    let mut flag = true;
    for test in tests {
        let build_afl_file_path = target_path.join(test);
        if !build_afl_file_path.is_file() {
            flag = false;
            error!("{} build failed.", test);
        }
        let replay = test.clone().replace("test", "replay");
        let build_replay_file_path = target_path.join(&replay);
        if !build_replay_file_path.is_file() {
            flag = false;
            error!("{} build failed", replay);
        }
    }
    if flag {
        info!("check build success");
    } else {
        exit(-1);
    }
}

fn fuzz_it(crate_name: &str, tests: &[String]) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let target_path = test_path.join("target").join(EDITION);
    let output_path = test_path.join("out");
    let exit_time_path = test_path.join(EXIT_TIME_DIR);
    ensure_empty_dir(&exit_time_path);

    let mut threads = Vec::new();
    let val = Arc::new(AtomicUsize::new(0));

    for test in tests {
        let afl_target_path = target_path.clone().join(test);
        let afl_output_dir = output_path.clone().join(test);
        if afl_output_dir.is_file() {
            fs::remove_file(&afl_output_dir).unwrap();
        }

        let test_path_copy = test_path.clone();

        let mut afl_dir_name = test.clone();
        afl_dir_name.push_str("_cmin");
        let afl_input_path = PathBuf::from(&test_path)
            .join(AFL_INPUT_DIR)
            .join(afl_dir_name);
        let exit_time_file_path = exit_time_path.join(test);

        let val_copy = val.clone();
        let handle = thread::spawn(move || {
            info!("fuzz {:?}", afl_target_path);
            let start = Instant::now();
            let args = vec![
                "afl",
                "fuzz",
                "-i",
                afl_input_path.to_str().unwrap(),
                "-o",
                afl_output_dir.to_str().unwrap(),
                afl_target_path.to_str().unwrap(),
            ];
            let exit_status = Command::new("cargo")
                .args(&args)
                .current_dir(test_path_copy.as_os_str())
                .env("AFL_EXIT_WHEN_DONE", "1")
                .env("AFL_NO_AFFINITY", "1")
                .stdout(Stdio::null())
                .status()
                .unwrap();
            info!("{:?} {:?}", afl_target_path, exit_status);
            let cost_time = start.elapsed().as_secs();

            val_copy.fetch_add(1, Ordering::SeqCst);

            if exit_time_file_path.is_file() {
                fs::remove_file(&exit_time_file_path).unwrap();
            }
            if exit_time_file_path.is_dir() {
                fs::remove_dir_all(&exit_time_file_path).unwrap();
            }
            if exit_status.success() {
                info!("{:?} succeed.", afl_target_path);
                let mut exit_time_file = fs::File::create(&exit_time_file_path).unwrap();
                let content = format!("{}", cost_time);
                exit_time_file
                    .write_all(content.as_bytes())
                    .unwrap_or_else(|_| {
                        error!("write file {:?} failed.", exit_time_file_path);
                        exit(-1);
                    });
            } else {
                error!("{:?} fails.", afl_target_path)
            }
        });

        threads.push(handle);
    }

    let mut minute_count = 0;
    let statistic_file_path = test_path.join(STATISTIC_OUTPUT_FILE);
    if statistic_file_path.is_file() {
        fs::remove_file(&statistic_file_path).unwrap();
    }
    if statistic_file_path.is_dir() {
        fs::remove_dir_all(&statistic_file_path).unwrap();
    }
    let mut statisticfile = fs::File::create(&statistic_file_path).unwrap();
    let title = "time\tcrashes\ttargets\tdetails\n";
    statisticfile
        .write_all(title.as_bytes())
        .unwrap_or_else(|_| {
            error!("write file {:?} failed.", statistic_file_path);
            exit(-1);
        });

    loop {
        thread::sleep(Duration::from_secs(60));
        minute_count += 1;
        info!("fuzz has run {} minutes.", minute_count);
        output_statistics_to_files(crate_name, minute_count);
        let exit_threads_number = val.as_ref().load(Ordering::SeqCst);
        info!(
            "{} threads has exited, there's still {} threads running",
            exit_threads_number,
            tests.len() - exit_threads_number
        );
        if exit_threads_number == tests.len() {
            break;
        }
    }

    info!(
        "Fuzzing totally runs {} minutes. All fuzzing thread finished",
        minute_count
    );

    //确保所有的线程都已经退出
    for handle in threads {
        handle.join().unwrap();
    }
}

fn find_crash(crate_name: &str) -> Vec<PathBuf> {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let afl_output_path = test_path.join(AFL_OUTPUT_DIR);
    let test_output_paths = check_maybe_empty_directory(&afl_output_path);
    let mut all_crash_files = Vec::new();
    for test_output_path in &test_output_paths {
        let crash_output_path = test_output_path.clone().join(CRASH_DIR);
        let crash_files = check_maybe_empty_directory(&crash_output_path);
        for crash_file in crash_files {
            let filename = crash_file.to_str().unwrap();
            if !filename.contains("README.txt") {
                all_crash_files.push(crash_file);
            }
        }
    }
    all_crash_files
}

fn print_crashes(crate_name: &str) {
    let all_crash_files = find_crash(crate_name);
    if all_crash_files.is_empty() {
        error!("Find no crash files");
        exit(-1);
    } else {
        for crash in &all_crash_files {
            debug!("crash path: {:?}", crash);
        }
    }
    debug!("total crashes: {}", all_crash_files.len());
}

fn ensure_empty_dir(dir: &Path) {
    if dir.is_dir() {
        fs::remove_dir_all(dir).unwrap();
    } else if dir.is_file() {
        fs::remove_file(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
}

fn ensure_dir(dir: &Path) {
    if dir.is_file() {
        fs::remove_file(dir).unwrap();
    }
    if !dir.is_dir() {
        fs::create_dir_all(dir).unwrap();
    }
}

fn cmin(crate_name: &str) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let cmin_output_path = test_path.join(CMIN_OUTPUT_DIR);
    //如果有tmin的output，首先去找tmin的output
    let tmin_output_dir = test_path.join(TMIN_OUTPUT_DIR);
    if tmin_output_dir.is_dir() {
        let tmin_directories = check_maybe_empty_directory(&tmin_output_dir);
        if !tmin_directories.is_empty() {
            ensure_empty_dir(&cmin_output_path);
            for tmin_directory in tmin_directories {
                let tmin_directory_name = tmin_directory.to_str().unwrap();
                let tmin_directory_name_split: Vec<&str> = tmin_directory_name.split('/').collect();
                let test_case_name = tmin_directory_name_split.last().unwrap();
                execute_cmin(
                    tmin_directory_name,
                    test_case_name,
                    &cmin_output_path,
                    &test_path,
                )
            }
            return;
        }
    }

    //如果没能找到tmin的结果，直接去找crash dir
    let afl_output_path = test_path.join(AFL_OUTPUT_DIR);
    let test_output_paths = check_maybe_empty_directory(&afl_output_path);

    let mut nonempty_crash_dir = Vec::new();

    for test_output_path in &test_output_paths {
        let crash_output_path = test_output_path.clone().join(CRASH_DIR);
        let crash_files = check_maybe_empty_directory(&crash_output_path);
        if !crash_files.is_empty() {
            //如果这个crash目录非空，那么就需要对这个目录运行cmin
            nonempty_crash_dir.push(crash_output_path);
        }
    }

    if nonempty_crash_dir.is_empty() {
        warn!("no crash file found.");
        exit(-1);
    }

    ensure_empty_dir(&cmin_output_path);

    for crash_dir in nonempty_crash_dir {
        let crash_dir_name = crash_dir.to_str().unwrap();
        clean_crash_dir(&crash_dir);
        let crash_dir_name_split: Vec<&str> = crash_dir_name.split('/').collect();
        let crash_dir_name_split_len = crash_dir_name_split.len();
        if crash_dir_name_split_len < 2 {
            error!("Invalid crash dir name");
            exit(-1);
        }
        let test_case_name = crash_dir_name_split[crash_dir_name_split_len - 2];
        execute_cmin(
            crash_dir_name,
            test_case_name,
            &cmin_output_path,
            &test_path,
        );
        //print_output(output);
    }
}

fn execute_cmin(
    crash_dir_name: &str,
    test_case_name: &str,
    cmin_output_path: &Path,
    test_path: &Path,
) {
    debug!("{}", test_case_name);
    let test_cmin_output_path = cmin_output_path.to_path_buf().join(test_case_name);
    let cmin_output_pathname = test_cmin_output_path.to_str().unwrap();

    let target_path = test_path
        .to_path_buf()
        .join("target")
        .join(EDITION)
        .join(test_case_name);
    let target_name = target_path.to_str().unwrap();

    //add -C option to only apply to crash inputs
    let args = vec![
        "afl",
        "cmin",
        "-C",
        "-i",
        crash_dir_name,
        "-o",
        cmin_output_pathname,
        target_name,
    ];
    Command::new("cargo").args(args).status().unwrap();
}

//去掉crash dir中的无效文件，比如readme，防止cmin产生不必要的路径
fn clean_crash_dir(crash_dir: &Path) {
    let crash_files = check_maybe_empty_directory(crash_dir);
    for crash_file in crash_files {
        let crash_filename = crash_file.to_str().unwrap();
        if crash_filename.contains("README.txt") {
            fs::remove_file(crash_file).unwrap();
        }
    }
}

//确认哪些才是真的crash，有些crash可能没法replay
fn replay_crashes(crate_name: &str) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let target_path = test_path.join("target").join(EDITION);
    //如果有cmin的结果的话,那么直接去找cmin的结果
    let cmin_path = test_path.join(CMIN_OUTPUT_DIR);
    if cmin_path.is_dir() {
        let cmin_directories = check_maybe_empty_directory(&cmin_path);
        if !cmin_directories.is_empty() {
            for cmin_directory in cmin_directories {
                if !cmin_directory.is_dir() {
                    continue;
                }
                let crash_files = check_maybe_empty_directory(&cmin_directory);
                if crash_files.is_empty() {
                    continue;
                }
                let test_name = last_file_name(&cmin_directory);
                let replay_name = test_name.replace("test", "replay");
                let replay_path = target_path.join(replay_name);
                let replay_file_name = replay_path.to_str().unwrap();
                for crash_file in crash_files {
                    let crash_file_name = crash_file.to_str().unwrap();
                    let output = Command::new(replay_file_name)
                        .arg(crash_file_name)
                        .output()
                        .unwrap();
                    let mut command = replay_file_name.to_string();
                    command.push(' ');
                    command.push_str(crash_file_name);
                    print_output(output);
                    info!("{}", command);
                    //print_output(output);
                }
            }
            return;
        }
    }

    warn!("No cmin output files. Use raw crash files");
    //首先尝试直接对原始的结果进行replay
    let crash_files = find_crash(crate_name);
    for crash_file in crash_files {
        let crash_file_name = crash_file.to_str().unwrap();
        //找到replay_file
        let crash_file_name_split: Vec<&str> = crash_file_name.split('/').collect();
        let crash_file_name_split_len = crash_file_name_split.len();
        if crash_file_name_split_len < 4 {
            error!("Invalid crash file name. {}", crash_file_name);
            exit(-1);
        }
        let test_case_name = crash_file_name_split[crash_file_name_split_len - 4];
        let replay_case_name = test_case_name.replace("test", "replay");
        let replay_file_path = target_path.join(replay_case_name);
        let replay_file_name = replay_file_path.to_str().unwrap();
        if !replay_file_path.is_file() {
            error!("Replay file not exist. {}", replay_file_name);
            exit(-1);
        }
        let output = Command::new(replay_file_name)
            .arg(crash_file_name)
            .output()
            .unwrap();
        let mut command = replay_file_name.to_string();
        command.push(' ');
        command.push_str(crash_file_name);
        info!("{}", command);
        print_output(output);
    }
}

pub fn output_statistics(crate_name: &str) {
    //crate_name
    println!("crate name: {}", crate_name);
    //fuzz driver
    let fuzz_drivers = check_pre_condition(crate_name);
    let fuzz_drivers_number = fuzz_drivers.len();
    println!("fuzz drivers: {}", fuzz_drivers_number);
    //total crashes
    let all_crash_files = find_crash(crate_name);
    let crash_number = all_crash_files.len();
    println!("crashes: {}", crash_number);
    //crashes after cmin
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let cmin_path = test_path.join(CMIN_OUTPUT_DIR);
    if cmin_path.is_dir() {
        let cmin_directories = check_maybe_empty_directory(&cmin_path);
        let find_crash_target_number = cmin_directories.len();
        println!("cmin result(after tmin,cmin):");
        let mut total_cmin_crashes = 0;
        let mut every_target_crashes = String::new();
        if find_crash_target_number > 0 {
            for cmin_directory in &cmin_directories {
                if !cmin_directory.is_dir() {
                    continue;
                }
                let crash_files = check_maybe_empty_directory(cmin_directory);
                let crash_files_number = crash_files.len();
                every_target_crashes.push_str(
                    format!(
                        "\t{} : {}\n",
                        last_file_name(cmin_directory),
                        crash_files_number
                    )
                    .as_str(),
                );
                total_cmin_crashes += crash_files_number;
                if crash_files_number == 0 {
                    continue;
                }
            }
        }
        println!("\tfind crash targets: {}", find_crash_target_number);
        println!("\ttotal crashes after cmin: {}", total_cmin_crashes);
        println!("cmin result detailes: ");
        println!("{}", every_target_crashes);
    } else {
        println!("No cmin output");
    }

    //exit time and average run time
    let exit_path = test_path.join(EXIT_TIME_DIR);
    let exit_targets = check_maybe_empty_directory(&exit_path);
    let finished_targets_number = exit_targets.len();
    println!("targets finished : {} ", finished_targets_number);

    let invalid_targets_number = if INVALID_TARGET_NUMBER.contains_key(crate_name) {
        INVALID_TARGET_NUMBER.get(crate_name).unwrap().to_owned()
    } else {
        0
    };

    println!("invalid targets: {}", invalid_targets_number);
    let not_exit_targets = fuzz_drivers_number - finished_targets_number - invalid_targets_number;
    println!("not exit: {:?}", not_exit_targets);
    let mut run_time = vec![86400; not_exit_targets];

    println!("exit time");

    for exit_target in &exit_targets {
        let content = fs::read_to_string(exit_target).expect("read exit file error");
        let mut exit_time = content.parse::<u64>().unwrap();
        if exit_time > 86400 {
            exit_time = 86400;
        }
        run_time.push(exit_time);
    }

    println!("valid targets: {}", run_time.len());

    let run_time_sum: u64 = run_time.iter().sum();
    println!(
        "average run time: {}",
        (run_time_sum as f64) / ((run_time.len() * 3600) as f64)
    );
}

pub fn output_statistics_to_files(crate_name: &str, fuzz_time: usize) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let statistic_file_path = test_path.join(STATISTIC_OUTPUT_FILE);
    if !statistic_file_path.is_file() {
        fs::File::create(&statistic_file_path).unwrap();
    }

    let all_crash_files = find_crash(crate_name);
    let total_crash_number = all_crash_files.len();

    let mut crash_counts = HashMap::new();
    for crash in &all_crash_files {
        let crash_file_name = crash.to_str().unwrap();
        let file_name_split: Vec<&str> = crash_file_name.split('/').collect();
        let file_name_split_len = file_name_split.len();
        if file_name_split_len < 4 {
            error!("Invalid crash file name");
            exit(-1);
        }
        let test_crate_name = file_name_split[file_name_split_len - 4];
        if crash_counts.contains_key(test_crate_name) {
            let current_count = *(crash_counts.get(test_crate_name).unwrap()) + 1;
            crash_counts.insert(test_crate_name, current_count);
        } else {
            crash_counts.insert(test_crate_name, 1);
        };
    }

    let crash_targets_number = crash_counts.len();
    let mut detail = "[".to_string();
    //detail:即每个target对应的crash的数量
    for (crate_name, crash_number) in &crash_counts {
        detail.push_str(*crate_name);
        detail.push_str(" : ");
        detail.push_str(format!("{}", crash_number).as_str());
        detail.push_str(" ,");
    }
    detail.push(']');

    let content = format!(
        "{}\t{}\t{}\t{}\t\n",
        fuzz_time, total_crash_number, crash_targets_number, detail
    );

    let mut file = OpenOptions::new()
        .append(true)
        .open(&statistic_file_path)
        .unwrap_or_else(|_| {
            error!("can't open file {:?}.", statistic_file_path);
            exit(-1);
        });

    file.write_all(content.as_bytes()).unwrap_or_else(|_| {
        error!("write file {:?} failed.", statistic_file_path);
        exit(-1);
    });
}

fn showmap(crate_name: &str) {
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let showmap_path = test_path.join(SHOWMAP_DIR);
    ensure_empty_dir(&showmap_path);
    let tests = check_pre_condition(crate_name);
    for test in &tests {
        let out_dir = test_path.join(AFL_OUTPUT_DIR).join(test).join("default");
        if !out_dir.is_dir() {
            debug!("{} has no output dir", test);
            continue;
        }
        let target_path = test_path.join("target").join("debug").join(test);
        let showmap_file_path = showmap_path.join(test);
        let output = Command::new("cargo")
            .arg("afl")
            .arg("showmap")
            .arg("-C")
            .arg("-e")
            .arg("-i")
            .arg(out_dir.as_os_str())
            .arg("-o")
            .arg(showmap_file_path.as_os_str())
            .arg("--")
            .arg(target_path.as_os_str())
            .current_dir(test_path.as_os_str())
            .output()
            .unwrap();
        let stdout = &output.stdout;
        let stdout_content = str::from_utf8(stdout).unwrap();
        let stdout_content_lines: Vec<&str> = stdout_content.split('\n').collect();
        let stdout_lines_len = stdout_content_lines.len();
        if stdout_lines_len > 1 {
            let last_line = stdout_content_lines[stdout_lines_len - 2];
            debug!("{}", last_line);
        }
    }
}

fn init_afl_input(crate_name: &str) {
    info!("init afl input for each project");
    let test_dir = CRATE_TEST_DIR.get(crate_name).unwrap();
    let test_path = PathBuf::from(test_dir);
    let afl_init_path = test_path.join(AFL_INPUT_DIR);
    let afl_directory_paths = check_no_empty_directory(&afl_init_path);

    let mut afl_files = Vec::new();

    for afl_path in &afl_directory_paths {
        if afl_path.is_file() {
            afl_files.push(afl_path.clone());
        }
    }

    let tests = check_pre_condition(crate_name);
    for test in &tests {
        let replay = test.replace("test", "replay");
        let this_afl_init_path = afl_init_path.join(test);
        ensure_empty_dir(&this_afl_init_path);
        let replay_target_path = test_path.join("target").join("debug").join(&replay);
        let test_target_path = test_path.join("target").join("debug").join(test);

        let mut has_init_file_flag = false;

        for afl_file in &afl_files {
            let exit_status = Command::new(replay_target_path.as_os_str())
                .arg(afl_file.as_os_str())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            if exit_status.success() {
                has_init_file_flag = true;
                Command::new("cp")
                    .arg(afl_file.as_os_str())
                    .arg(this_afl_init_path.as_os_str())
                    .status()
                    .unwrap();
            }
        }

        //tmin:慢
        //let mut tmin_name = test.clone();
        //tmin_name.push_str("_tmin");
        //let this_tmin_path = afl_init_path.join(&tmin_name);
        //ensure_empty_dir(&this_tmin_path);
        //let all_raw_afl_files = check_maybe_empty_directory(&this_afl_init_path);
        //for raw_afl_file in &all_raw_afl_files {
        //    let filename = last_file_name(raw_afl_file);
        //    let output_file_path = this_tmin_path.join(filename);
        //    let args = vec!["afl", "tmin", "-i", raw_afl_file.to_str().unwrap(), "-o", output_file_path.to_str().unwrap(), "--", test_target_path.to_str().unwrap()];
        //    let _ = Command::new("cargo").args(&args).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        //}

        if !has_init_file_flag {
            debug!("There's no afl input for {:?}", test);
        } else {
            let mut cmin_name = test.clone();
            cmin_name.push_str("_cmin");
            let this_cmin_path = afl_init_path.join(&cmin_name);
            ensure_empty_dir(&this_cmin_path);
            let cmin_args = vec![
                "afl",
                "cmin",
                "-i",
                this_afl_init_path.to_str().unwrap(),
                "-o",
                this_cmin_path.to_str().unwrap(),
                "--",
                test_target_path.to_str().unwrap(),
            ];
            let _ = Command::new("cargo")
                .args(&cmin_args)
                .stdout(Stdio::null())
                .status()
                .unwrap();
        }
    }
}

fn main() {
    let _ = env_logger::builder().parse_env("AFL_LOG").try_init();
    let args: Vec<String> = env::args().collect();
    let user_options = UserOptions::new_from_cli(args);
    trace!("{:?}", user_options);
    do_work(&user_options);
}
