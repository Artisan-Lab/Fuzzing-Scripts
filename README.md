# Fuzzing Scripts For Rust libraries with [afl.rs](https://github.com/rust-fuzz/afl.rs)  

These are two scripts for fuzzing Rust libraries to cooperate with our [fuzz target generator](https://github.com/Artisan-Lab/Fuzz-Target-Generator). These two scripts automate the process to fuzz Rust libraries with [afl.rs](https://github.com/rust-fuzz/afl.rs). Because these scripts are initially for personal use, the structures of these scripts are not well designed and there may be some ugly patterns. We may improve this in the future if needed.

We have tried to mention some possible problems that may appear during fuzzing process in this documentation. But we may also miss some conditions. You can submit an issue if you are faced with any problem when fuzzing a Rust library.

## Note:  
afl.rs has released a new version to depend on an AFL++ latest version. We have checked our scripts still can work now(2022-1-5).
## Before using the scripts  

Before using these scripts, you need to make sure you have correctly install [afl.rs](https://github.com/rust-fuzz/afl.rs) and [afl.rs](https://github.com/rust-fuzz/afl.rs) can run properly. You can follow the instructions on [rust-fuzz-book](https://rust-fuzz.github.io/book/afl.html).

## How to build and install these two scripts?

You can follow below instructions to install these two scripts on Unix-like systems.  
```shell
WORKDIR=$HOME #You can change this directory according to your own settings
cd $WORKDIR
git clone https://github.com/Artisan-Lab/Fuzzing-Scripts
cd Fuzzing-Scripts
cargo install --path afl_scripts
cargo install --path find_literal
```

## How to use our scripts to fuzz libraries?

I will take crate `url` as an example.

1. First, replace several directories of `url` in `$WORKDIR/Fuzzing-Scripts/afl_scripts/src/main.rs`.  
    + line 45: the actual source directory of `url` (SOURCE_DIR)
    + line 72: the fuzz target directory of `url`  (TEST_DIR)
    + line 100: the version of crate `url`. If you download `url` source code from github instead of using `cargo`, you can set the version in line 100 as "*" , then set the source code directory of `url` in line 127. The patched directory is also used if you add some patches in the source code.
2. Recompile `afl_scripts`  
    + `cd $WORKDIR/Fuzzing-Scripts`
    + `cargo install --path afl_scripts`
3. Generate fuzz targets for url.
    ```shell
    afl_scripts -p url
    ```
    **Note**: -p option is not always valid (Sadly, most time invalid). I recommend you to follow [our fuzz-target-generator instructions](https://github.com/Artisan-Lab/Fuzz-Target-Generator/blob/develop/README.md) to generate targets.  
4. Generate initial input files for `url` 
    ```shell
    afl_scripts -f 500 url
    ```
5. Compile fuzz targets
    ```shell
    afl_scripts -b url
    ```
    You should see output information "check build success" if targets are compiled successfully.
    **Note**: All targets need to be compiled successfully before you continue fuzzing. For libraries we have tested, we have fixed all problems confronted during compilation. But for other libraries, there may be some language features we missed. So, you may encounter compilation problems. We suggest personally that you may follow steps below personally.
    + remove fuzz targets that cannot be compiled or manually fix compilation errors from `$TEST_DIR/test_files`
    + run `afl_scripts -clean url` to delete previous compilation and fuzzing results (This may corrupt history data)
    + follow the steps from `Generate initial input files` again.
    + What's more, you can submit an issue to our [fuzz target generator](https://github.com/Artisan-Lab/Fuzz-Target-Generator) if you are willing. And we will check and fix the problem.


6. Fuzz all targets. I recommend you that before running thid instruction, open a window with `tmux` or `screen`, for the fuzzing process will last a long time. On my PC, I would like to use `tmux new -s afl-url` 
    ```shell
    afl_scripts -fuzz url
    ```
    For some crates, the fuzzing process will exit automatically. But for url, you need to manually stop the fuzzing process by typing `CTRL C`. The fuzzing time is based on your own preference. In our experiments, we will fuzz each target for 24 hours.
7. Analyse the fuzzing results.
    ```shell
    afl_scripts -t url      #reduce test file size
    afl_scripts -cmin url   #reduce test file number
    afl_scripts -s url      #output statistic info
    afl_scripts -r url      #replay crash files
    ```
