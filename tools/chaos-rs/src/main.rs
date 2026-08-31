//! Chaos fuzzer with structured corpus (like Zig soak)
use bolina::codec::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Deserialize;
use std::fs;

const CANONICAL_SEEDS: [u64; 5] = [108230699740769, 42, 1337, 999999, 3735928559];
const INPUTS_PER_SEED: usize = 1_000_000;
const MAX_INPUT: usize = 1024;
const MUTATE_RATIO: u8 = 40;

#[derive(Deserialize)]
struct Vectors {
    structures: Structures,
}

#[derive(Deserialize)]
struct Structures {
    envelope_intent: Structure,
    grant: Structure,
    span: Structure,
    effect: Structure,
    refusal: Structure,
    cert: Structure,
}

#[derive(Deserialize)]
struct Structure {
    wire_hex: String,
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap())
        .collect()
}

fn load_seeds() -> Vec<Vec<u8>> {
    let vectors_json = fs::read_to_string("test/vectors.json").expect("vectors.json");
    let vectors: Vectors = serde_json::from_str(&vectors_json).expect("parse vectors");
    
    vec![
        decode_hex(&vectors.structures.envelope_intent.wire_hex),
        decode_hex(&vectors.structures.grant.wire_hex),
        decode_hex(&vectors.structures.span.wire_hex),
        decode_hex(&vectors.structures.effect.wire_hex),
        decode_hex(&vectors.structures.refusal.wire_hex),
        decode_hex(&vectors.structures.cert.wire_hex),
    ]
}

fn mutate<'a>(rng: &mut impl Rng, seed: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
    let len = seed.len().min(buf.len());
    buf[..len].copy_from_slice(&seed[..len]);
    
    let mut k = 1 + rng.gen_range(0..3);
    while k > 0 {
        k -= 1;
        let idx = rng.gen_range(0..len);
        match rng.gen_range(0..5) {
            0 => buf[idx] ^= 1 << rng.gen_range(0..3),
            1 => buf[idx] = rng.gen(),
            2 => return &buf[..rng.gen_range(0..len) + 1],
            3 => buf[idx] = if buf[idx] == 0 { 0xFF } else { 0 },
            _ => {
                if len >= buf.len() { continue; }
                let extra = (1 + rng.gen_range(0..8)).min(buf.len() - len);
                for i in 0..extra {
                    buf[len + i] = rng.gen();
                }
                return &buf[..len + extra];
            }
        }
    }
    &buf[..len]
}

fn next_input<'a>(rng: &mut impl Rng, seeds: &[Vec<u8>], buf: &'a mut [u8]) -> &'a [u8] {
    if rng.gen_range(0..100) < MUTATE_RATIO {
        let seed = &seeds[rng.gen_range(0..seeds.len())];
        mutate(rng, seed, buf)
    } else {
        let len = rng.gen_range(1..=MAX_INPUT);
        for i in 0..len {
            buf[i] = rng.gen();
        }
        &buf[..len]
    }
}

fn try_parse(input: &[u8]) -> bool {
    parse_envelope(input).is_ok()
        || parse_intent(input).is_ok()
        || parse_grant(input).is_ok()
        || parse_span(input).is_ok()
        || parse_cert(input).is_ok()
        || parse_refusal(input).is_ok()
}

fn main() {
    let seeds = load_seeds();
    println!("Loaded {} seeds", seeds.len());
    
    let mut total_inputs = 0;
    let mut total_accepted = 0;
    
    for &seed in &CANONICAL_SEEDS {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut buf = [0u8; MAX_INPUT];
        let mut accepted = 0;
        
        for _ in 0..INPUTS_PER_SEED {
            let input = next_input(&mut rng, &seeds, &mut buf);
            if try_parse(input) {
                accepted += 1;
            }
        }
        
        total_inputs += INPUTS_PER_SEED;
        total_accepted += accepted;
        println!("seed {}: {}/{} accepted ({:.2}%)",
            seed, accepted, INPUTS_PER_SEED,
            100.0 * accepted as f64 / INPUTS_PER_SEED as f64);
    }
    
    println!("\nTotal: {}/{} accepted ({:.2}%)",
        total_accepted, total_inputs,
        100.0 * total_accepted as f64 / total_inputs as f64);
}
