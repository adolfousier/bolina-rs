//! cross-diff: Zig vs Rust byte-a-byte comparison
//! 
//! This tool validates that the Rust implementation produces identical output to the Zig implementation.

use std::fs;
use std::path::Path;

fn main() {
    println!("cross-diff: validating Rust vs Zig byte-a-byte");
    
    // Load test vectors from Zig
    let vectors_path = Path::new("../../test/vectors.json");
    if !vectors_path.exists() {
        eprintln!("ERROR: vectors.json not found at {:?}", vectors_path);
        std::process::exit(1);
    }
    
    let vectors_str = fs::read_to_string(vectors_path).expect("Failed to read vectors.json");
    let vectors: serde_json::Value = serde_json::from_str(&vectors_str).expect("Failed to parse vectors.json");
    
    // Validate each vector
    let mut passed = 0;
    let mut failed = 0;
    
    for (name, vector) in vectors.as_object().expect("vectors.json must be an object") {
        match validate_vector(name, vector) {
            Ok(_) => {
                println!("✓ {}", name);
                passed += 1;
            }
            Err(e) => {
                eprintln!("✗ {}: {}", name, e);
                failed += 1;
            }
        }
    }
    
    println!("\n=== SUMMARY ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    
    if failed > 0 {
        std::process::exit(1);
    }
}

fn validate_vector(name: &str, vector: &serde_json::Value) -> Result<(), String> {
    // Each vector has: input (hex), expected_output (hex)
    let input_hex = vector.get("input")
        .and_then(|v| v.as_str())
        .ok_or("missing 'input' field")?;
    
    let expected_hex = vector.get("expected_output")
        .and_then(|v| v.as_str())
        .ok_or("missing 'expected_output' field")?;
    
    let input_bytes = hex::decode(input_hex).map_err(|e| format!("invalid input hex: {}", e))?;
    let expected_bytes = hex::decode(expected_hex).map_err(|e| format!("invalid expected hex: {}", e))?;
    
    // Parse using Rust codec
    let result = match name {
        n if n.starts_with("envelope_") => {
            let envelope = bolina::codec::parse_envelope(&input_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_envelope(&envelope)
        }
        n if n.starts_with("intent_") => {
            let intent = bolina::codec::parse_intent(&input_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_intent(&intent)
        }
        n if n.starts_with("grant_") => {
            let grant = bolina::codec::parse_grant(&input_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_grant(&grant)
        }
        n if n.starts_with("refusal_") => {
            let refusal = bolina::codec::parse_refusal(&input_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_refusal(&refusal)
        }
        _ => return Err(format!("unknown vector type: {}", name)),
    };
    
    // Compare byte-by-byte
    if result != expected_bytes {
        return Err(format!(
            "mismatch:\n  expected: {}\n  got:      {}",
            hex::encode(&expected_bytes),
            hex::encode(&result)
        ));
    }
    
    Ok(())
}
