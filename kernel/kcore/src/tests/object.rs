// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::object`.

use super::*;

#[test]
fn create_retain_release_lifetime() {
    let mut table = ObjectTable::new();
    let id = table.create(ObjectType::Test).unwrap();
    assert_eq!(table.refcount(id), Some(1));
    assert_eq!(table.object_type(id), Some(ObjectType::Test));

    table.retain(id).unwrap();
    assert_eq!(table.refcount(id), Some(2));

    assert_eq!(table.release(id), Ok(false)); // still 1 reference
    assert!(table.is_live(id));
    assert_eq!(table.release(id), Ok(true)); // destroyed at zero
    assert!(!table.is_live(id));
    assert_eq!(table.live_count(), 0);
}

#[test]
fn stale_id_after_reuse_is_rejected() {
    let mut table = ObjectTable::new();
    let first = table.create(ObjectType::Thread).unwrap();
    assert_eq!(table.release(first), Ok(true)); // slot freed, generation bumped
    let second = table.create(ObjectType::Job).unwrap(); // reuses the slot
    assert_ne!(first, second, "reused slot gets a fresh generation");
    // The stale id must not resolve to the new object.
    assert_eq!(table.object_type(first), None);
    assert_eq!(table.retain(first), Err(KError::BadHandle));
    assert_eq!(table.object_type(second), Some(ObjectType::Job));
}

#[test]
fn full_pool_is_fallible() {
    let mut table = ObjectTable::new();
    for _ in 0..MAX_OBJECTS {
        table.create(ObjectType::Test).unwrap();
    }
    assert_eq!(table.create(ObjectType::Test), Err(KError::OutOfMemory));
}
