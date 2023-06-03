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

const CRASH_DIR: &str = "default/crashes";
const TEST_FILE_DIR: &str = "test_files";
const REPLAY_FILE_DIR: &str = "replay_files";
const AFL_INPUT_DIR: &str = "afl_init";
const AFL_OUTPUT_DIR: &str = "out";
const CARGO_TOML: &str = "Cargo.toml";
const BUILD_SCRIPT: &str = "build";
const AFL_DEPENDENCY: &str = "afl = \"*\"";
const TMIN_OUTPUT_DIR: &str = "tmin_output";
const CMIN_OUTPUT_DIR: &str = "cmin_output";
const STATISTIC_OUTPUT_FILE: &str = "statistics";
const EXIT_TIME_DIR: &str = "exit_time";
const SHOWMAP_DIR: &str = "showmap";

pub struct Config {
    pub crate_name: String,
    pub crate_dir: PathBuf,
    pub test_dir: PathBuf,
    pub build_dir: PathBuf,
    pub afl_input_dir: PathBuf,
    pub afl_output_dir: PathBuf,
    pub target_dir: PathBuf,
}

impl Config {
    fn new(crate_name: &str, crate_dir: &Path) -> Config {
        let crate_name = crate_name.to_owned();
        let crate_dir = crate_dir.to_owned();
        let test_dir = crate_dir.join("fuzz_target");
        let build_dir = test_dir.join("build");
        let afl_input_dir = test_dir.join(AFL_INPUT_DIR);
        let afl_output_dir = test_dir.join(AFL_OUTPUT_DIR);
        let target_dir = build_dir.join("target").join("debug");

        Config {
            crate_name,
            crate_dir,
            test_dir,
            build_dir,
            afl_input_dir,
            afl_output_dir,
            target_dir,
        }
    }
}

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

        //let list_option = Regex::new("(-l$|--list)").unwrap();
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
            if self.crate_name.is_none() {
                self.crate_name = Some(s.clone());
                continue;
            }
            error!("Invalid Options.");
            exit(-1);
        }
        /* if self.crate_name.is_none() {
            error!("No valid crate is provided.");
            exit(-1);
        } */
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
    let crate_string = user_options.crate_name.clone().unwrap_or_default();
    let crate_name = crate_string.as_str();
    let current_dir = std::env::current_dir().unwrap();
    let config = Config::new(crate_name, &current_dir);

    if user_options.check {
        info!("check {} success.", crate_name);
        check_pre_condition(&config);
        exit(0);
    }
    if user_options.find_literal.is_some() {
        info!("find literal for {}.", crate_name);
        do_find_literal(crate_name, user_options.find_literal.unwrap().to_string());
        exit(0);
    }
    if user_options.prepare {
        info!("prepare test files for {}.", crate_name);
        prepare_test_files(crate_name);
        exit(0);
    }
    if user_options.clean {
        info!("clean {}.", crate_name);
        clean(&config);
        exit(0);
    }
    if user_options.crash {
        info!("find crash files for {}.", crate_name);
        print_crashes(&config);
        exit(0);
    }

    if user_options.build {
        info!("build {}.", crate_name);
        let tests = check_pre_condition(&config);
        info!("init test dir");
        init_test_dir(&config, &tests);
        info!("build afl tests");
        build_afl_tests(&config);
        info!("init afl input");
        init_afl_input(&config);
        info!("check build");
        check_build(&config, &tests);
        exit(0);
    }
    if user_options.fuzz {
        info!("fuzz {}.", crate_name);
        let tests = check_pre_condition(&config);
        check_build(&config, &tests);
        fuzz_it(&config, &tests);
        exit(0);
    }
    if user_options.tmin {
        info!("run afl-tmin for {}.", crate_name);
        tmin(&config);
        exit(0);
    }
    if user_options.cmin {
        info!("run afl-cmin for {}", crate_name);
        cmin(&config);
        exit(0);
    }
    if user_options.replay {
        info!("replay crash files for {}.", crate_name);
        replay_crashes(&config);
        exit(0);
    }
    if user_options.statistic {
        info!("statistics for {}.", crate_name);
        output_statistics(&config);
        exit(0);
    }
    if user_options.showmap {
        info!("run afl-showmap for {}.", crate_name);
        showmap(&config);
        exit(0);
    }
    if user_options.init_afl_input {
        let test_dir = std::env::current_dir().unwrap().join("build");
        info!("init afl input for {}.", crate_name);
        let tests = check_pre_condition(&config);
        check_build(&config, &tests);
        init_afl_input(&config);
        exit(0);
    }
    if user_options.all {
        unreachable!();
        /* let tests = check_pre_condition(crate_name);
        clean(crate_name);
        init_test_dir(crate_name, &tests);
        build_afl_tests(crate_name);
        init_afl_input(crate_name);
        check_build(crate_name, &tests);
        fuzz_it(crate_name, &tests);
        exit(0); */
    }
    //default work
    info!("Nothing to do!");
    /* let tests = check_pre_condition(crate_name);
    init_test_dir(crate_name, &tests);
    build_afl_tests(crate_name);
    check_build(crate_name, &tests);
    fuzz_it(crate_name, &tests); */
}

fn do_find_literal(crate_name: &str, input_number: String) {
    let input_dir = std::env::current_dir().unwrap();
    //let input_dir = CRATE_SRC_DIR.get(crate_name).unwrap().to_string();
    let mut output_dir = std::env::current_dir().unwrap();
    output_dir.push("fuzz_target");
    fs::create_dir_all(&output_dir).unwrap();
    let args = vec![
        "-i",
        input_dir.to_str().unwrap(),
        "-o",
        output_dir.to_str().unwrap(),
        "-n",
        input_number.as_str(),
    ];
    let output = Command::new("find_literal")
        .args(args)
        .output()
        .unwrap_or_else(|_| {
            error!("find_literal encounter problems.");
            exit(-1);
        });
}

fn prepare_test_files(crate_name: &str) {
    //let src_dir = CRATE_SRC_DIR.get(crate_name).unwrap();
    let current_dir = std::env::current_dir().unwrap();
    let output = Command::new("cargo")
        //.current_dir(&current_dir)
        .arg("clean")
        .output()
        .unwrap();
    print_output(output);
    println!("cargo clean");
    let output = Command::new("cargo")
        //.current_dir(&src_path)
        .arg("doc")
        .arg("-v")
        .output()
        .unwrap();
    let stderr = str::from_utf8(output.stderr.as_slice()).unwrap();
    let stderr_lines: Vec<&str> = stderr.split('\n').collect();
    let stderr_lines_number = stderr_lines.len();
    if stderr_lines_number < 3 {
        println!("cargo doc goes wrong");
        exit(-1);
    }
    let rustdoc_line = stderr_lines[stderr_lines_number - 3];
    println!("rustdoc line = {}", rustdoc_line);
    let pattern = Regex::new(r#"`rustdoc.+`"#).unwrap();
    let raw_command = pattern.find(rustdoc_line).unwrap().as_str();
    let command = raw_command.replace("rustdoc ", "").replace('`', "");
    let command_args: Vec<&str> = command.split(' ').collect();
    println!("command_args = {:?}", command_args);
    let output = Command::new("fuzz-target-generator")
        .args(command_args)
        //.current_dir(&src_dir)
        .output()
        .unwrap();
    print_output(output);
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

//检查一个crate的前置条件是否满足，包括
//test_files, replay_files, afl_init
pub fn check_pre_condition(config: &Config) -> Vec<String> {
    let crate_test_dir = &config.test_dir;

    let afl_init_dir = &config.afl_input_dir;
    check_no_empty_directory(&afl_init_dir);
    let test_file_dir = crate_test_dir.join(TEST_FILE_DIR);
    let test_file_entries = check_no_empty_directory(&test_file_dir);

    let replay_file_dir = crate_test_dir.join(REPLAY_FILE_DIR);
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

fn clean(config: &Config) {
    let except_files = vec![AFL_INPUT_DIR, REPLAY_FILE_DIR, TEST_FILE_DIR];
    let test_path = PathBuf::from(&config.test_dir);

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

fn init_test_dir(config: &Config, tests: &[String]) {
    let build_dir = &config.build_dir;

    // remove old build directory
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("remove build directory fail!");
    }
    fs::create_dir(&build_dir).expect("crate build directory fail");

    //生成输出目录
    fs::create_dir_all(&&config.afl_output_dir).unwrap_or_else(|_| {
        error!(
            "Encounter error when creating {:?}.",
            &&config.afl_output_dir
        );
        exit(-1);
    });

    //生成cargo.toml内容
    let cargo_toml_path = build_dir.join(CARGO_TOML);
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

    //对于每个test_file和replay_file新建项目
    let mut replays = Vec::new();
    for test in tests {
        info!("create fuzz and replay projects for {}", test);
        let test_cargo_path = build_dir.join(test);
        let replay = test.replace("test", "replay");
        let replay_cargo_path = build_dir.join(&replay);
        replays.push(replay);
        Command::new("cargo")
            .args(["new", "--vcs", "none"])
            .arg(test_cargo_path.as_os_str())
            .output()
            .unwrap();
        Command::new("cargo")
            .args(["new", "--vcs", "none"])
            .arg(replay_cargo_path.as_os_str())
            .output()
            .unwrap();
    }

    let add_dependency_file = |crate_name: &str, path: PathBuf| {
        let cargo_toml_path = path.join(CARGO_TOML);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&cargo_toml_path)
            .unwrap_or_else(|_| {
                error!("can't open file {:?}.", cargo_toml_path);
                exit(-1);
            });
        file.write_all(AFL_DEPENDENCY.as_bytes())
            .unwrap_or_else(|_| {
                error!("write file {:?} failed.", cargo_toml_path);
                exit(-1);
            });
        file.write_all("\n".as_bytes()).unwrap();
        let crate_dependency = format!("{} = {{path='../../../'}}\n", crate_name);
        file.write_all(crate_dependency.as_bytes())
            .unwrap_or_else(|_| {
                error!("write file {:?} failed.", cargo_toml_path);
                exit(-1);
            });
    };

    //为每个test crate添加依赖
    for test in tests.iter().chain(&replays) {
        add_dependency_file(&&config.crate_name, build_dir.join(test));
    }

    //为每个replay crate添加依赖
    /* for replay in &replays {
        add_dependency_file(&&config.crate_name, build_dir.join(replay));
    } */

    let copy_src = |filename: &str, src_dir: &PathBuf| {
        let to_path = build_dir.join(filename).join("src").join("main.rs");
        let mut filename = filename.to_owned();
        filename.push_str(".rs");
        let from_path = src_dir.join(filename);
        info!("cp {:?} {:?}", from_path, to_path);
        Command::new("cp")
            .arg(from_path.as_os_str())
            .arg(to_path.as_os_str())
            .output()
            .unwrap();
    };
    let test_src_dir = config.test_dir.join(TEST_FILE_DIR);
    //复制测试文件
    for test in tests {
        copy_src(test, &test_src_dir);
    }

    //复制replay文件
    let replay_src_dir = config.test_dir.join(REPLAY_FILE_DIR);
    for replay in &replays {
        copy_src(replay, &replay_src_dir);
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

fn build_afl_tests(config: &Config) {
    Command::new("cargo")
        .arg("afl")
        .arg("build")
        .arg("--offline")
        .current_dir(&config.build_dir)
        .output()
        .unwrap();
}

fn check_build(config: &Config, tests: &[String]) {
    let target_path = &config.target_dir;

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

fn fuzz_it(config: &Config, tests: &[String]) {
    let test_path = PathBuf::from(&config.build_dir);
    let target_path = &config.target_dir;
    let output_path = &config.afl_output_dir;
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
        let afl_input_path = config.afl_input_dir.clone();
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
            info!("args = {:?}", args);
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
        output_statistics_to_files(config, minute_count);
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

fn find_crash(config: &Config) -> Vec<PathBuf> {
    let afl_output_path = &config.afl_output_dir;
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

fn print_crashes(config: &Config) {
    let all_crash_files = find_crash(config);
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

fn tmin(config: &Config) {
    let all_crash_files = find_crash(config);
    let test_path = PathBuf::from(&config.build_dir);
    let tmin_output_path = test_path.join(TMIN_OUTPUT_DIR);
    ensure_empty_dir(&tmin_output_path);
    if all_crash_files.is_empty() {
        warn!("No crash files.");
        exit(-1);
    }
    debug!("total crashes = {}", all_crash_files.len());

    let mut crash_counts = HashMap::new();
    for crash in &all_crash_files {
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
        let target_path = &config.target_dir.join(test_crate_name);
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
        Command::new("cargo")
            .args(args)
            .stdout(Stdio::null())
            .status()
            .unwrap();
    }
}

fn cmin(config: &Config) {
    let test_dir = &config.build_dir;
    let cmin_output_path = test_dir.join(CMIN_OUTPUT_DIR);
    //如果有tmin的output，首先去找tmin的output
    let tmin_output_dir = test_dir.join(TMIN_OUTPUT_DIR);
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
                    &&config.target_dir,
                )
            }
            return;
        }
    }

    //如果没能找到tmin的结果，直接去找crash dir
    let afl_output_path = test_dir.join(AFL_OUTPUT_DIR);
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
            &&config.target_dir,
        );
        //print_output(output);
    }
}

fn execute_cmin(
    crash_dir_name: &str,
    test_case_name: &str,
    cmin_output_path: &Path,
    target_dir: &Path,
) {
    debug!("{}", test_case_name);
    let test_cmin_output_path = cmin_output_path.to_path_buf().join(test_case_name);
    let cmin_output_pathname = test_cmin_output_path.to_str().unwrap();

    let target_path = target_dir.join(test_case_name);
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
fn replay_crashes(config: &Config) {
    let target_path = &config.target_dir;
    //如果有cmin的结果的话,那么直接去找cmin的结果
    let cmin_path = &config.build_dir.join(CMIN_OUTPUT_DIR);
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
    let crash_files = find_crash(config);
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

pub fn output_statistics(config: &Config) {
    let crate_name = &&config.crate_name;
    let test_path = &config.build_dir;
    //crate_name
    println!("crate name: {}", crate_name);
    //fuzz driver
    let fuzz_drivers = check_pre_condition(config);
    let fuzz_drivers_number = fuzz_drivers.len();
    println!("fuzz drivers: {}", fuzz_drivers_number);
    //total crashes
    let all_crash_files = find_crash(config);
    let crash_number = all_crash_files.len();
    println!("crashes: {}", crash_number);
    //crashes after cmin
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

    let invalid_targets_number = 0;

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

pub fn output_statistics_to_files(config: &Config, fuzz_time: usize) {
    let crate_name = &&config.crate_name;
    let test_path = PathBuf::from(&config.test_dir);
    let statistic_file_path = test_path.join(STATISTIC_OUTPUT_FILE);
    if !statistic_file_path.is_file() {
        fs::File::create(&statistic_file_path).unwrap();
    }

    let all_crash_files = find_crash(config);
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

fn showmap(config: &Config) {
    let test_path = PathBuf::from(&config.build_dir);
    let showmap_path = test_path.join(SHOWMAP_DIR);
    ensure_empty_dir(&showmap_path);
    let tests = check_pre_condition(&config);
    for test in &tests {
        let out_dir = test_path.join(AFL_OUTPUT_DIR).join(test).join("default");
        if !out_dir.is_dir() {
            debug!("{} has no output dir", test);
            continue;
        }
        let target_path = &config.target_dir.join(test);
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

fn init_afl_input(config: &Config) {
    let target_dir = config.target_dir.clone();
    let arc_afl_init_path = Arc::new(config.afl_input_dir.clone());
    let afl_directory_paths = check_no_empty_directory(&arc_afl_init_path);

    let mut afl_files = Vec::new();

    for afl_path in &afl_directory_paths {
        if afl_path.is_file() {
            afl_files.push(afl_path.clone());
        }
    }

    let arc_afl_files = Arc::new(afl_files);

    let tests = check_pre_condition(config);
    //let thread_num=std::thread::available_parallelism().unwrap().get();
    //info!("thread num=",{});
    let mut handles = Vec::<_>::new();
    let mut thread_count = 0;
    for test in tests {
        let replay = test.replace("test", "replay");
        let replay_target_path = target_dir.join(&replay);
        let test_target_path = target_dir.join(&test);
        let afl_init_path = arc_afl_init_path.clone();
        let this_afl_init_path = afl_init_path.join(&test);
        let afl_files = arc_afl_files.clone();
        thread_count += 1;
        let handle = thread::spawn(move || {
            ensure_empty_dir(&this_afl_init_path);
            info!("replay_target_path: {:?}", replay_target_path.as_os_str());
            let mut has_init_file_flag = false;
            for afl_file in afl_files.iter() {
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
                info!("thread#{} afl cmin start", thread_count);
                let _ = Command::new("cargo")
                    .args(&cmin_args)
                    .stdout(Stdio::null())
                    .status()
                    .unwrap();
                info!("thread#{} afl cmin end", thread_count);
            }
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

fn main() {
    let _ = env_logger::builder().parse_env("AFL_LOG").try_init();
    let args: Vec<String> = env::args().collect();
    let user_options = UserOptions::new_from_cli(args);
    trace!("{:?}", user_options);
    do_work(&user_options);
}
