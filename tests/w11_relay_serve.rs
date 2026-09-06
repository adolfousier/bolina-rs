//! Tests for relay_serve classifier (BE-EXEC-04).
//! Named per relay_serve.md spec.

use bolina::relay_serve::*;

// --- BE-EXEC-04: classifier routes handshake types and drops everything else ---
#[test]
fn be_exec_04_classifier_routes_handshake_types() {
    // Handshake types 1, 2, 3 → ToHandshake
    assert_eq!(classify_datagram(&[1]), ServeResult::ToHandshake);
    assert_eq!(classify_datagram(&[2]), ServeResult::ToHandshake);
    assert_eq!(classify_datagram(&[3, 0xAA]), ServeResult::ToHandshake);
}

#[test]
fn be_exec_04_classifier_drops_unknown_and_empty() {
    assert_eq!(classify_datagram(&[]), ServeResult::Dropped);
    assert_eq!(classify_datagram(&[0]), ServeResult::Dropped);
    assert_eq!(classify_datagram(&[4]), ServeResult::Dropped);
    assert_eq!(classify_datagram(&[0xFF]), ServeResult::Dropped);
}

#[test]
fn be_exec_04_classifier_routes_relay_messages() {
    assert_eq!(
        classify_datagram(&[MSG_RELAY_ROUTE, 0, 1]),
        ServeResult::Forwarded
    );
    assert_eq!(
        classify_datagram(&[MSG_RELAY_REGISTRATION]),
        ServeResult::Registered
    );
}

// --- BE-EXEC-04: forward live — registered recipient gets the body ---
#[test]
fn be_exec_04_forward_live_registered_recipient() {
    let mut endpoints = EndpointMap::new();
    endpoints.put(5, &[10, 20, 30], 3);

    let dgram = [MSG_RELAY_ROUTE, 5, 0xAA]; // route to index 5
    let result = classify_route(&dgram, &endpoints, 5);
    assert_eq!(result, ServeResult::Forwarded);
}

// --- BE-EXEC-04: sender gate — no established session, no service ---
#[test]
fn be_exec_04_unregistered_recipient_gets_stored() {
    let endpoints = EndpointMap::new(); // empty — no registrations

    let dgram = [MSG_RELAY_ROUTE, 5, 0xAA];
    let result = classify_route(&dgram, &endpoints, 5);
    assert_eq!(result, ServeResult::Stored);
}

// --- EndpointMap operations ---
#[test]
fn endpoint_map_put_get_remove() {
    let mut map = EndpointMap::new();

    assert!(map.get(0).is_none());
    assert!(map.put(0, &[1, 2, 3], 3));
    let ep = map.get(0).unwrap();
    assert_eq!(&ep.addr[..3], &[1, 2, 3]);
    assert_eq!(ep.addr_len, 3);

    assert!(map.remove(0));
    assert!(map.get(0).is_none());
    assert!(!map.remove(0)); // already removed
}

#[test]
fn endpoint_map_bounds_check() {
    let mut map = EndpointMap::new();
    assert!(!map.put(MAX_ENDPOINTS, &[1], 1)); // out of bounds
    assert!(!map.put(0, &[1], 29)); // addr too long
    assert!(map.get(MAX_ENDPOINTS).is_none());
    assert!(!map.remove(MAX_ENDPOINTS));
}

// --- ServeResult exhaustiveness ---
#[test]
fn serve_result_six_variants_exhaustive() {
    let variants = [
        ServeResult::ToHandshake,
        ServeResult::Forwarded,
        ServeResult::Stored,
        ServeResult::Registered,
        ServeResult::Drained,
        ServeResult::Dropped,
    ];
    // All 6 variants constructible and distinct.
    assert_eq!(variants.len(), 6);
    assert_ne!(variants[0], variants[1]);
    assert_ne!(variants[1], variants[2]);
    assert_ne!(variants[2], variants[3]);
    assert_ne!(variants[3], variants[4]);
    assert_ne!(variants[4], variants[5]);
}
