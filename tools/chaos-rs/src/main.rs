//! chaos-rs: adversarial fuzzing + roundtrip validation
//! 
//! Gera N inputs aleatórios com seed S
//! Para cada input, tenta parse+encode com o codec Rust
//! Se o parse conseguir, compara output com input (roundtrip)
//! Reporta coverage (quantos inputs foram aceites)

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: chaos-rs <seed> <count>");
        std::process::exit(1);
    }

    let seed: u64 = args[1].parse().expect("seed must be u64");
    let count: usize = args[2].parse().expect("count must be usize");

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    
    let mut accepted = 0;
    let mut rejected = 0;
    let mut roundtrip_ok = 0;
    let mut roundtrip_fail = 0;

    for i in 0..count {
        // Generate random input (1-1024 bytes)
        let len = rng.gen_range(1..=1024);
        let mut input = vec![0u8; len];
        rng.fill(&mut input[..]);

        // Try parse+encode with each structure type
        let result = try_parse_encode(&input);

        match result {
            Some(output) => {
                accepted += 1;
                if output == input {
                    roundtrip_ok += 1;
                } else {
                    roundtrip_fail += 1;
                    eprintln!("roundtrip mismatch at input {}", i);
                }
            }
            None => {
                rejected += 1;
            }
        }
    }

    println!("=== CHAOS SUMMARY ===");
    println!("Seed: {}", seed);
    println!("Count: {}", count);
    println!("Accepted: {}", accepted);
    println!("Rejected: {}", rejected);
    println!("Roundtrip OK: {}", roundtrip_ok);
    println!("Roundtrip FAIL: {}", roundtrip_fail);
    println!("Coverage: {:.2}%", 100.0 * accepted as f64 / count as f64);

    if roundtrip_fail > 0 {
        std::process::exit(1);
    }
}

fn try_parse_encode(input: &[u8]) -> Option<Vec<u8>> {
    // Try each structure type
    if let Ok(cert) = bolina::codec::parse_cert(input) {
        return Some(bolina::codec::encode_cert(&cert));
    }
    if let Ok(envelope) = bolina::codec::parse_envelope(input) {
        return Some(bolina::codec::encode_envelope(&envelope));
    }
    if let Ok(span) = bolina::codec::parse_span(input) {
        return Some(bolina::codec::encode_span(&span));
    }
    if let Ok(grant) = bolina::codec::parse_grant(input) {
        return Some(bolina::codec::encode_grant(&grant));
    }
    if let Ok(refusal) = bolina::codec::parse_refusal(input) {
        return Some(bolina::codec::encode_refusal(&refusal));
    }
    None
}
