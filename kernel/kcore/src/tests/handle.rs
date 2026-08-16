// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::handle`.

use super::*;
use crate::object::{ObjectTable, ObjectType};

/// Creates an object and a first handle adopting its creation reference.
fn new_object_handle(
    objects: &mut ObjectTable,
    handles: &mut HandleTable,
    rights: Rights,
) -> (ObjectId, Handle) {
    let id = objects.create(ObjectType::Test).unwrap();
    let handle = handles.insert(id, rights).unwrap();
    (id, handle)
}

#[test]
fn insert_lookup_and_query_rights() {
    let mut objects = ObjectTable::new();
    let mut handles = HandleTable::new();
    let rights = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
    let (id, handle) = new_object_handle(&mut objects, &mut handles, rights);
    assert_eq!(handles.object(handle), Ok(id));
    assert_eq!(handles.rights(handle), Ok(rights));
    assert_eq!(handles.scope(handle), Ok(None)); // unscoped by default
    assert_eq!(objects.refcount(id), Some(1)); // the handle holds the one reference
}

#[test]
fn duplicate_narrows_and_rejects_expansion() {
    let mut objects = ObjectTable::new();
    let mut handles = HandleTable::new();
    let full = Rights::READ | Rights::WRITE | Rights::DUPLICATE;
    let (id, handle) = new_object_handle(&mut objects, &mut handles, full);

    // Narrowing to a subset is allowed and adds a reference.
    let ro = handles
        .duplicate(&mut objects, handle, Rights::READ)
        .unwrap();
    assert_eq!(handles.rights(ro), Ok(Rights::READ));
    assert_eq!(objects.refcount(id), Some(2));

    // Asking for a right the source lacks is an expansion — rejected, with
    // no new reference taken.
    let expand = Rights::READ | Rights::EXECUTE;
    assert_eq!(
        handles.duplicate(&mut objects, ro, expand),
        Err(KError::AccessDenied)
    );
    assert_eq!(objects.refcount(id), Some(2));
}

#[test]
fn replace_rights_only_narrows() {
    let mut objects = ObjectTable::new();
    let mut handles = HandleTable::new();
    let (_, handle) = new_object_handle(&mut objects, &mut handles, Rights::READ | Rights::WRITE);
    handles.replace_rights(handle, Rights::READ).unwrap();
    assert_eq!(handles.rights(handle), Ok(Rights::READ));
    // Cannot re-add WRITE.
    assert_eq!(
        handles.replace_rights(handle, Rights::READ | Rights::WRITE),
        Err(KError::AccessDenied)
    );
}

#[test]
fn object_lives_until_last_handle_closes() {
    let mut objects = ObjectTable::new();
    let mut handles = HandleTable::new();
    let (id, h1) = new_object_handle(&mut objects, &mut handles, Rights::all_core());
    let h2 = handles.duplicate(&mut objects, h1, Rights::READ).unwrap();
    assert_eq!(objects.refcount(id), Some(2));

    assert_eq!(handles.close(&mut objects, h1), Ok(false)); // one reference left
    assert!(objects.is_live(id));
    assert_eq!(handles.close(&mut objects, h2), Ok(true)); // destroyed at last close
    assert!(!objects.is_live(id));
    assert_eq!(handles.count(), 0);
}

#[test]
fn transfer_moves_a_handle_and_conserves_the_reference() {
    let mut objects = ObjectTable::new();
    // A source table (sender) and a destination table (receiver).
    let mut sender = HandleTable::new();
    let mut receiver = HandleTable::new();

    let id = objects.create(ObjectType::Test).unwrap();
    let handle = sender.insert(id, Rights::READ | Rights::TRANSFER).unwrap();
    assert_eq!(objects.refcount(id), Some(1));

    // Take from the sender (reference conserved — refcount unchanged).
    let (object, rights) = sender.take(handle).unwrap();
    assert_eq!(object, id);
    assert_eq!(objects.refcount(id), Some(1));
    assert_eq!(sender.rights(handle), Err(KError::BadHandle)); // gone from sender

    // Install into the receiver (reference adopted — still one reference).
    let installed = receiver.install(object, rights).unwrap();
    assert_eq!(objects.refcount(id), Some(1));
    assert_eq!(receiver.rights(installed), Ok(rights));
    assert!(objects.is_live(id));
}

#[test]
fn transfer_requires_the_transfer_right() {
    let mut objects = ObjectTable::new();
    let mut sender = HandleTable::new();
    let id = objects.create(ObjectType::Test).unwrap();
    // No TRANSFER right.
    let handle = sender.insert(id, Rights::READ | Rights::WRITE).unwrap();
    assert_eq!(sender.take(handle), Err(KError::AccessDenied));
    // The handle is untouched by the failed take.
    assert!(sender.rights(handle).is_ok());
}

/// The transferred half of "rights can be reduced when handles are
/// duplicated or transferred" (docs/kernel/01).
#[test]
fn transfer_narrows_and_rejects_expansion() {
    let mut objects = ObjectTable::new();
    let mut sender = HandleTable::new();
    let mut receiver = HandleTable::new();
    let id = objects.create(ObjectType::Test).unwrap();
    let handle = sender
        .insert(id, Rights::READ | Rights::MAP | Rights::TRANSFER)
        .unwrap();

    // Asking for more than the sender holds is refused, and costs the
    // sender nothing — the handle is still there afterwards.
    assert_eq!(
        sender.take_narrowed(handle, Rights::READ | Rights::WRITE),
        Err(KError::AccessDenied)
    );
    assert!(sender.rights(handle).is_ok());

    // Narrowing succeeds and the receiver gets exactly what was asked for.
    let (object, rights) = sender
        .take_narrowed(handle, Rights::READ | Rights::MAP)
        .unwrap();
    assert_eq!(rights, Rights::READ | Rights::MAP);
    assert_eq!(sender.rights(handle), Err(KError::BadHandle));
    let installed = receiver.install(object, rights).unwrap();
    assert_eq!(
        receiver.rights(installed).unwrap(),
        Rights::READ | Rights::MAP
    );
}

/// The point of narrowing on transfer, and the thing that was impossible
/// before it: a capability the receiver cannot hand on. `TRANSFER` is
/// required to *send*, and rights used to pass through unchanged, so every
/// capability that could be given away necessarily arrived able to be
/// given away again.
#[test]
fn a_grant_can_be_made_non_delegable() {
    let mut objects = ObjectTable::new();
    let mut sender = HandleTable::new();
    let mut receiver = HandleTable::new();
    let id = objects.create(ObjectType::Test).unwrap();
    let handle = sender
        .insert(id, Rights::READ | Rights::MAP | Rights::TRANSFER)
        .unwrap();

    let (object, rights) = sender
        .take_narrowed(handle, Rights::READ | Rights::MAP)
        .unwrap();
    let installed = receiver.install(object, rights).unwrap();

    // The receiver holds a working capability...
    assert!(receiver.rights(installed).unwrap().contains(Rights::MAP));
    // ...and cannot pass it to anyone.
    assert_eq!(receiver.take(installed), Err(KError::AccessDenied));
    // Nor can it launder one through a duplicate: rights only narrow, so
    // the duplicate cannot acquire the TRANSFER the original lacks.
    assert_eq!(
        receiver.duplicate(&mut objects, installed, Rights::READ | Rights::TRANSFER),
        Err(KError::AccessDenied)
    );
}

/// Narrowing does not substitute for the authority to send. A handle
/// without `TRANSFER` cannot be moved however modest the request.
#[test]
fn narrowing_does_not_grant_the_right_to_send() {
    let mut objects = ObjectTable::new();
    let mut sender = HandleTable::new();
    let id = objects.create(ObjectType::Test).unwrap();
    let handle = sender.insert(id, Rights::READ | Rights::MAP).unwrap();
    assert_eq!(
        sender.take_narrowed(handle, Rights::READ),
        Err(KError::AccessDenied)
    );
    assert_eq!(
        sender.take_narrowed(handle, Rights::none()),
        Err(KError::AccessDenied)
    );
    assert!(sender.rights(handle).is_ok());
}

/// An empty rights set is a legal narrowing: useless, but not dangerous,
/// and refusing it would be a special case with nothing behind it.
#[test]
fn narrowing_to_no_rights_is_allowed() {
    let mut objects = ObjectTable::new();
    let mut sender = HandleTable::new();
    let id = objects.create(ObjectType::Test).unwrap();
    let handle = sender.insert(id, Rights::READ | Rights::TRANSFER).unwrap();
    let (_, rights) = sender.take_narrowed(handle, Rights::none()).unwrap();
    assert!(rights.is_empty());
}

#[test]
fn stale_and_absent_handles_are_rejected() {
    let mut objects = ObjectTable::new();
    let mut handles = HandleTable::new();
    let (_, handle) = new_object_handle(&mut objects, &mut handles, Rights::READ);
    handles.close(&mut objects, handle).unwrap();
    // The closed handle is stale.
    assert_eq!(handles.rights(handle), Err(KError::BadHandle));
    assert_eq!(
        handles.duplicate(&mut objects, handle, Rights::READ),
        Err(KError::BadHandle)
    );
}

/// **The read nothing else could do.** Every other accessor starts from a
/// handle the asker already has, so a capability a process was given by
/// mistake is one nobody thinks to look up.
#[test]
fn an_audit_reports_what_a_process_actually_holds() {
    let mut handles = HandleTable::new();
    let a = handles
        .install(ObjectId::from_raw(1), Rights::READ | Rights::MAP)
        .expect("install");
    handles
        .install(ObjectId::from_raw(2), Rights::CONFIGURE)
        .expect("install");

    let mut out = [(ObjectId::from_raw(0), Rights::none()); 8];
    let n = handles.audit(&mut out);
    assert_eq!(n, 2);
    let held: Rights = out[..n].iter().fold(Rights::none(), |acc, (_, r)| acc | *r);
    assert!(
        held.contains(Rights::CONFIGURE),
        "the one nobody asked about"
    );

    // And a handle that went away stops being held.
    handles.drop_handle(a).expect("drop");
    let n = handles.audit(&mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0].0, ObjectId::from_raw(2));
}

/// A buffer that cannot fit the table stops at its own length rather than
/// writing past it, and the count says so.
#[test]
fn an_audit_that_does_not_fit_says_so_by_filling() {
    let mut handles = HandleTable::new();
    for id in 1..=4 {
        handles
            .install(ObjectId::from_raw(id), Rights::READ)
            .expect("install");
    }
    let mut out = [(ObjectId::from_raw(0), Rights::none()); 2];
    assert_eq!(handles.audit(&mut out), out.len());
}
