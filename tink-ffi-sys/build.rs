// Copyright 2026 Adam Winstanley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let tink_cc_dir = env::var("TINK_CC_DIR").unwrap_or_else(|_| {
        let bundled = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("tink-cc");
        if !bundled.join("CMakeLists.txt").exists() {
            panic!(
                "tink-cc source not found. If building from a git checkout, run:\n  \
                 git submodule update --init\n\
                 Or set TINK_CC_DIR to a tink-cc source tree."
            );
        }
        bundled.to_string_lossy().into_owned()
    });

    let dst = cmake::Config::new("ffi")
        .define("TINK_BUILD_TESTS", "OFF")
        .define("TINK_CC_DIR", &tink_cc_dir)
        .build_target("tink_ffi")
        .build();

    let build_dir = dst.join("build");

    // Collect every .a file produced by the cmake build (tink-cc builds
    // hundreds of small static archives plus its dependencies: abseil,
    // protobuf, boringssl).  We add each parent directory as a search path
    // and link each archive by its stem name.
    let mut search_dirs = BTreeSet::new();
    let mut lib_names = Vec::new();
    collect_libs(&build_dir, &mut search_dirs, &mut lib_names);

    for dir in &search_dirs {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }

    // Link our shim first, then everything else.
    println!("cargo:rustc-link-lib=static=tink_ffi");
    for name in &lib_names {
        if name != "tink_ffi" {
            println!("cargo:rustc-link-lib=static={name}");
        }
    }

    // Link C++ standard library.
    let target = env::var("TARGET").unwrap();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=stdc++");
    }

    println!("cargo:rerun-if-changed=ffi/");
    println!("cargo:rerun-if-env-changed=TINK_CC_DIR");
}

fn collect_libs(base: &Path, dirs: &mut BTreeSet<PathBuf>, names: &mut Vec<String>) {
    let seen: &mut BTreeSet<String> = &mut BTreeSet::new();
    for path in walkdir(base) {
        if path.extension().is_some_and(|e| e == "a") {
            if let Some(parent) = path.parent() {
                dirs.insert(parent.to_path_buf());
            }
            // Strip "lib" prefix and ".a" suffix to get the linker name.
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let name = stem.strip_prefix("lib").unwrap_or(stem).to_string();
                if seen.insert(name.clone()) {
                    names.push(name);
                }
            }
        }
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip boringssl test data directories that contain fake .a files
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name == "testdata" {
                        continue;
                    }
                }
                results.extend(walkdir(&path));
            } else {
                results.push(path);
            }
        }
    }
    results
}
