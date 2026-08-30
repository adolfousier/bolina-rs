//! mutation-test-rs: surgical mutation testing for bolina-rs
//!
//! Philosophy (from mutation-test.py for Zig):
//! - Mutants are chosen by us, not generated randomly
//! - Each mutant has a SPEC anchor (exact text in source)
//! - Domains group mutants by family
//! - Gating: exit 1 if any mutant survives
//! - Equivalent mutants are documented, not counted

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Deserialize, Clone)]
struct MutantSpec {
    domain: String,
    file: String,
    anchor: String,
    replacement: String,
    description: String,
    #[serde(default)]
    equivalent: bool,
}

#[derive(Debug, Deserialize)]
struct Config {
    mutants: Vec<MutantSpec>,
}

fn find_project_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("src").join("lib.rs").exists() {
            return dir;
        }
        if !dir.pop() {
            panic!("could not find project root (no Cargo.toml + src/lib.rs)");
        }
    }
}

fn apply_mutant(root: &Path, mutant: &MutantSpec) -> Result<(), String> {
    let file_path = root.join(&mutant.file);
    let content = fs::read_to_string(&file_path)
        .map_err(|e| format!("read {}: {}", mutant.file, e))?;

    if !content.contains(&mutant.anchor) {
        return Err(format!(
            "anchor not found in {}: {:?}",
            mutant.file,
            &mutant.anchor[..mutant.anchor.len().min(80)]
        ));
    }

    let mutated = content.replacen(&mutant.anchor, &mutant.replacement, 1);
    if mutated == content {
        return Err(format!("anchor found but replacement identical in {}", mutant.file));
    }

    fs::write(&file_path, &mutated)
        .map_err(|e| format!("write {}: {}", mutant.file, e))?;

    Ok(())
}

fn revert_mutant(root: &Path, mutant: &MutantSpec) -> Result<(), String> {
    let file_path = root.join(&mutant.file);
    let content = fs::read_to_string(&file_path)
        .map_err(|e| format!("read {}: {}", mutant.file, e))?;

    let reverted = content.replacen(&mutant.replacement, &mutant.anchor, 1);
    fs::write(&file_path, &reverted)
        .map_err(|e| format!("write {}: {}", mutant.file, e))?;

    Ok(())
}

fn run_tests(root: &Path) -> (bool, bool) {
    let output = Command::new("cargo")
        .arg("test")
        .arg("--")
        .arg("--test-threads=1")
        .arg("-q")
        .current_dir(root)
        .output();

    match output {
        Ok(o) => {
            let compiled = true;
            let passed = o.status.success();
            (passed, compiled)
        }
        Err(_) => (false, false),
    }
}

fn main() {
    let root = find_project_root();
    let config_path = root.join("tools").join("mutation-test-rs").join("mutants.toml");

    if !config_path.exists() {
        eprintln!("ERROR: {} not found", config_path.display());
        std::process::exit(2);
    }

    let config_str = fs::read_to_string(&config_path).expect("read mutants.toml");
    let config: Config = toml::from_str(&config_str).expect("parse mutants.toml");

    let total = config.mutants.len();
    let domains: Vec<&str> = {
        let mut d: Vec<&str> = config.mutants.iter().map(|m| m.domain.as_str()).collect();
        d.sort();
        d.dedup();
        d
    };

    println!("mutation-test-rs: {} mutants loaded", total);
    println!("domains: {}", domains.join(", "));

    let mut survivors: Vec<MutantSpec> = Vec::new();
    let mut killed = 0usize;
    let mut equivalent = 0usize;
    let mut unviable = 0usize;

    for (i, mutant) in config.mutants.iter().enumerate() {
        if mutant.equivalent {
            equivalent += 1;
            println!("[{}/{}] SKIP (equivalent): {} — {}", i + 1, total, mutant.domain, mutant.description);
            continue;
        }

        print!("[{}/{}] {} — {} ... ", i + 1, total, mutant.domain, mutant.description);

        if let Err(e) = apply_mutant(&root, mutant) {
            println!("ANCHOR ERROR: {}", e);
            continue;
        }

        let (passed, compiled) = run_tests(&root);

        if let Err(e) = revert_mutant(&root, mutant) {
            eprintln!("FATAL: revert failed: {}", e);
            std::process::exit(2);
        }

        if !compiled {
            println!("UNVIABLE");
            unviable += 1;
        } else if !passed {
            println!("KILLED ✓");
            killed += 1;
        } else {
            println!("SURVIVED ✗");
            survivors.push(mutant.clone());
        }
    }

    println!("\n=== SUMMARY ===");
    println!("Total:      {}", total);
    println!("Killed:     {}", killed);
    println!("Survived:   {}", survivors.len());
    println!("Equivalent: {}", equivalent);
    println!("Unviable:   {}", unviable);

    if !survivors.is_empty() {
        println!("\n=== SURVIVORS ===");
        for s in &survivors {
            println!("  {} — {}: {}", s.domain, s.file, s.description);
        }
        std::process::exit(1);
    }

    println!("\nAll mutants killed. ✓");
}
