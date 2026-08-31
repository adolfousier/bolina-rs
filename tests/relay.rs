//! W5 relay tests — port of relay_test.zig (15 tests)

use bolina::transport::relay::*;

// --- RelayRoute parsing ---

#[test]
fn be_mesh_02_parse_relay_route_happy() {
    let mut buf = [0u8; LEN_RELAY_ROUTE];
    let r = RelayRoute { sender_index: 0x12345678, recipient_index: 0xAABBCCDD, timestamp: 1000 };
    r.encode(&mut buf);
    let parsed = RelayRoute::parse(&buf).unwrap();
    assert_eq!(parsed, r);
}

#[test]
fn be_mesh_02_parse_relay_route_wrong_type() {
    let mut buf = [0u8; LEN_RELAY_ROUTE];
    buf[0] = 0xFF;
    assert_eq!(RelayRoute::parse(&buf), Err(RelayError::WrongType));
}

#[test]
fn be_mesh_02_parse_relay_route_non_zero_reserved() {
    let mut buf = [0u8; LEN_RELAY_ROUTE];
    buf[0] = MSG_RELAY_ROUTE;
    buf[1] = 1;
    assert_eq!(RelayRoute::parse(&buf), Err(RelayError::NonZeroReserved));
}

#[test]
fn be_mesh_02_parse_relay_route_trailing_bytes() {
    let mut buf = [0u8; LEN_RELAY_ROUTE + 1];
    buf[0] = MSG_RELAY_ROUTE;
    assert_eq!(RelayRoute::parse(&buf), Err(RelayError::Truncated)); // wrong len
}

#[test]
fn be_mesh_02_parse_relay_route_truncated() {
    let buf = [0u8; LEN_RELAY_ROUTE - 1];
    assert_eq!(RelayRoute::parse(&buf), Err(RelayError::Truncated));
}

// --- RelayRegistration parsing ---

#[test]
fn be_mesh_02_parse_relay_registration_happy() {
    let mut buf = [0u8; LEN_RELAY_REGISTRATION];
    buf[0] = MSG_RELAY_REGISTRATION;
    buf[4..8].copy_from_slice(&1u32.to_be_bytes()); // relay_index
    buf[8..12].copy_from_slice(&2u32.to_be_bytes()); // client_index
    buf[12..20].copy_from_slice(&1000u64.to_be_bytes()); // timestamp
    buf[20..36].fill(0xAA); // overlay_addr
    buf[36..44].copy_from_slice(&3600u64.to_be_bytes()); // expiry
    buf[44..108].fill(0xBB); // sig
    // padding 108..124 ignored
    let reg = RelayRegistration::parse(&buf).unwrap();
    assert_eq!(reg.relay_index, 1);
    assert_eq!(reg.client_index, 2);
    assert_eq!(reg.timestamp, 1000);
    assert_eq!(reg.overlay_addr, [0xAA; LEN_OVERLAY_ADDR]);
    assert_eq!(reg.expiry, 3600);
}

#[test]
fn be_mesh_02_parse_relay_registration_wrong_type() {
    let mut buf = [0u8; LEN_RELAY_REGISTRATION];
    buf[0] = 0xFF;
    assert_eq!(RelayRegistration::parse(&buf), Err(RelayError::WrongType));
}

#[test]
fn be_mesh_02_parse_relay_registration_non_zero_reserved() {
    let mut buf = [0u8; LEN_RELAY_REGISTRATION];
    buf[0] = MSG_RELAY_REGISTRATION;
    buf[2] = 1;
    assert_eq!(RelayRegistration::parse(&buf), Err(RelayError::NonZeroReserved));
}

#[test]
fn be_mesh_02_parse_relay_registration_trailing_bytes() {
    let buf = [0u8; LEN_RELAY_REGISTRATION + 1];
    assert_eq!(RelayRegistration::parse(&buf), Err(RelayError::Truncated));
}

#[test]
fn be_mesh_02_parse_relay_registration_truncated() {
    let buf = [0u8; LEN_RELAY_REGISTRATION - 1];
    assert_eq!(RelayRegistration::parse(&buf), Err(RelayError::Truncated));
}

#[test]
fn be_mesh_02_parse_relay_registration_expiry_too_long() {
    let mut buf = [0u8; LEN_RELAY_REGISTRATION];
    buf[0] = MSG_RELAY_REGISTRATION;
    buf[36..44].copy_from_slice(&(MAX_EXPIRY + 1).to_be_bytes());
    assert_eq!(RelayRegistration::parse(&buf), Err(RelayError::ExpiryTooLong));
}

// --- RelayTable ---

#[test]
fn be_mesh_02_relay_table_insert_and_lookup() {
    let mut t = RelayTable::new();
    let mut addr = [0u8; LEN_OVERLAY_ADDR];
    addr[0] = 0xAA;
    let entry = RelayEntry { overlay_addr: addr, relay_index: 1, client_index: 2, expiry: 1000 };
    assert!(t.insert(entry));
    assert_eq!(t.count(), 1);
    let found = t.lookup(&addr).unwrap();
    assert_eq!(found.relay_index, 1);
    assert_eq!(found.client_index, 2);
}

#[test]
fn be_mesh_02_relay_table_rejects_insert_when_full() {
    let mut t = RelayTable::new();
    for i in 0..MAX_RELAY_TABLE {
        let mut addr = [0u8; LEN_OVERLAY_ADDR];
        addr[0] = (i & 0xFF) as u8;
        addr[1] = ((i >> 8) & 0xFF) as u8;
        let entry = RelayEntry { overlay_addr: addr, relay_index: i as u32, client_index: 0, expiry: 1000 };
        assert!(t.insert(entry), "slot {} should insert", i);
    }
    // MD5 heritage fix: the new addr must be a byte pattern no loop entry sets
    let mut new_addr = [0u8; LEN_OVERLAY_ADDR];
    new_addr[15] = 0xFF; // no loop entry sets byte 15
    let entry = RelayEntry { overlay_addr: new_addr, relay_index: 9999, client_index: 0, expiry: 1000 };
    assert!(!t.insert(entry));
    assert_eq!(t.count(), MAX_RELAY_TABLE);
}

#[test]
fn be_mesh_02_relay_table_prunes_expired() {
    let mut t = RelayTable::new();
    let mut addr1 = [0u8; LEN_OVERLAY_ADDR]; addr1[0] = 1;
    let mut addr2 = [0u8; LEN_OVERLAY_ADDR]; addr2[0] = 2;
    t.insert(RelayEntry { overlay_addr: addr1, relay_index: 0, client_index: 0, expiry: 100 });
    t.insert(RelayEntry { overlay_addr: addr2, relay_index: 0, client_index: 0, expiry: 200 });
    assert_eq!(t.count(), 2);
    t.prune(150); // addr1 expired, addr2 alive
    assert_eq!(t.count(), 1);
    assert!(t.lookup(&addr1).is_none());
    assert!(t.lookup(&addr2).is_some());
}

#[test]
fn md5_re_registration_refreshes_in_place() {
    let mut t = RelayTable::new();
    let addr = [0xAA; LEN_OVERLAY_ADDR];
    let e1 = RelayEntry { overlay_addr: addr, relay_index: 1, client_index: 10, expiry: 100 };
    let e2 = RelayEntry { overlay_addr: addr, relay_index: 2, client_index: 20, expiry: 200 };
    assert!(t.insert(e1));
    assert_eq!(t.count(), 1);
    assert!(t.insert(e2)); // refresh
    assert_eq!(t.count(), 1); // no duplicate
    let found = t.lookup(&addr).unwrap();
    assert_eq!(found.relay_index, 2); // refreshed
    assert_eq!(found.expiry, 200);
}

#[test]
fn be_mesh_02_forward_packet_returns_packet_unchanged() {
    let mut t = RelayTable::new();
    let mut addr = [0u8; LEN_OVERLAY_ADDR]; addr[0] = 1;
    t.insert(RelayEntry { overlay_addr: addr, relay_index: 0, client_index: 42, expiry: 1000 });
    let route = RelayRoute { sender_index: 0, recipient_index: 42, timestamp: 500 };
    let packet = [1, 2, 3, 4];
    let result = forward_packet(&t, &route, &packet, 500).unwrap();
    assert_eq!(result, &packet);
}

#[test]
fn be_mesh_02_forward_packet_stale_route() {
    let t = RelayTable::new();
    let route = RelayRoute { sender_index: 0, recipient_index: 0, timestamp: 1000 };
    let packet = [1, 2, 3];
    // now = 2000, timestamp = 1000, skew = 300 → 1000 + 300 < 2000 → stale
    assert_eq!(forward_packet(&t, &route, &packet, 2000), Err(RelayError::StaleRoute));
}

#[test]
fn be_mesh_02_forward_packet_unknown_recipient() {
    let t = RelayTable::new();
    let route = RelayRoute { sender_index: 0, recipient_index: 999, timestamp: 500 };
    let packet = [1, 2, 3];
    assert_eq!(forward_packet(&t, &route, &packet, 500), Err(RelayError::UnknownRecipient));
}

#[test]
fn exact_max_expiry_must_parse() {
    // Code: expiry > MAX_EXPIRY (86400) is refused; expiry == MAX_EXPIRY is legal.
    // Mutant >= would refuse the boundary registration.
    use bolina::transport::relay::{RelayRegistration, MAX_EXPIRY, LEN_RELAY_REGISTRATION};
    let mut buf = [0u8; LEN_RELAY_REGISTRATION];
    buf[0] = 6; // MSG_RELAY_REGISTRATION
    buf[4..8].copy_from_slice(&1u32.to_be_bytes());
    buf[8..12].copy_from_slice(&2u32.to_be_bytes());
    buf[36..44].copy_from_slice(&MAX_EXPIRY.to_be_bytes());
    let reg = RelayRegistration::parse(&buf);
    assert!(reg.is_ok(), "expiry == MAX_EXPIRY must parse, got {:?}", reg.err());
    assert_eq!(reg.unwrap().expiry, MAX_EXPIRY);
    // MAX_EXPIRY+1 must fail in both variants
    buf[36..44].copy_from_slice(&(MAX_EXPIRY + 1).to_be_bytes());
    assert!(RelayRegistration::parse(&buf).is_err(), "expiry == MAX_EXPIRY+1 must fail");
}
