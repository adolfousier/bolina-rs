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
    
    // Validate structures
    let structures = vectors.get("structures").expect("missing 'structures' field");
    let mut passed = 0;
    let mut failed = 0;
    
    for (name, structure) in structures.as_object().expect("structures must be an object") {
        match validate_structure(name, structure) {
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

fn validate_structure(name: &str, structure: &serde_json::Value) -> Result<(), String> {
    let wire_hex = structure.get("wire_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing 'wire_hex' field")?;
    
    let wire_bytes = hex::decode(wire_hex).map_err(|e| format!("invalid wire hex: {}", e))?;
    
    // Parse using Rust codec
    let result = match name {
        "cert" => {
            let cert = bolina::codec::parse_cert(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_cert(&cert)
        }
        "envelope_intent" | "effect" => {
            let envelope = bolina::codec::parse_envelope(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_envelope(&envelope)
        }
        "span" => {
            let span = bolina::codec::parse_span(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_span(&span)
        }
        "grant" => {
            let grant = bolina::codec::parse_grant(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_grant(&grant)
        }
        "refusal" => {
            let refusal = bolina::codec::parse_refusal(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_refusal(&refusal)
        }
        "claim" => {
            let claim = bolina::codec::parse_claim(&wire_bytes)
                .map_err(|e| format!("parse failed: {:?}", e))?;
            bolina::codec::encode_claim(&claim)
        }
        _ => return Err(format!("unknown structure: {}", name)),
    };
    
    // Compare byte-by-byte
    if result != wire_bytes {
        return Err(format!(
            "mismatch:\n  expected: {}\n  got:      {}",
            hex::encode(&wire_bytes),
            hex::encode(&result)
        ));
    }
    
    Ok(())
}
