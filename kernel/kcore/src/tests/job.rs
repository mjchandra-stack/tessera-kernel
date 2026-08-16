// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Tests for `kcore::job`.

use super::*;
use crate::object::{ObjectTable, ObjectType};

// A convenience: create a fresh Job object id from a table.
fn obj(table: &mut ObjectTable) -> ObjectId {
    table.create(ObjectType::Job).expect("object")
}

const FULL: Rights = Rights::from_bits(
    Rights::CREATE_JOB.bits() | Rights::CREATE_PROCESS.bits() | Rights::KILL.bits(),
);

fn member(table: &mut ObjectTable, thread: usize) -> Member {
    Member {
        process: table.create(ObjectType::Process).expect("proc"),
        thread,
    }
}

#[test]
fn root_and_nested_children_form_a_tree() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    let root = jobs
        .create_root(obj(&mut objects), JobLimits::new(4))
        .expect("root");
    let child = jobs
        .create_child(root, obj(&mut objects), JobLimits::new(2), FULL)
        .expect("child");
    assert_eq!(jobs.job(child).expect("child").parent(), Some(root));
    assert_eq!(jobs.job(root).expect("root").parent(), None);
}

#[test]
fn a_child_limit_exceeding_the_parent_is_rejected_but_tighter_is_allowed() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    let root = jobs
        .create_root(obj(&mut objects), JobLimits::new(2))
        .expect("root");
    // Looser than the parent → rejected (tighten-only).
    assert_eq!(
        jobs.create_child(root, obj(&mut objects), JobLimits::new(3), FULL),
        Err(KError::LimitExceeded)
    );
    // Equal or tighter → allowed.
    assert!(
        jobs.create_child(root, obj(&mut objects), JobLimits::new(2), FULL)
            .is_ok()
    );
    assert!(
        jobs.create_child(root, obj(&mut objects), JobLimits::new(1), FULL)
            .is_ok()
    );
}

#[test]
fn the_member_count_ceiling_rejects_the_offending_create() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    let root = jobs
        .create_root(obj(&mut objects), JobLimits::new(2))
        .expect("root");
    jobs.add_process(root, member(&mut objects, 0), FULL)
        .expect("p1");
    jobs.add_process(root, member(&mut objects, 1), FULL)
        .expect("p2");
    // The third exceeds the cap of 2 — a resource error, not a silent drop.
    assert_eq!(
        jobs.add_process(root, member(&mut objects, 2), FULL),
        Err(KError::LimitExceeded)
    );
    assert_eq!(jobs.job(root).expect("root").member_count(), 2);
}

#[test]
fn job_ops_require_the_matching_right() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    let root = jobs
        .create_root(obj(&mut objects), JobLimits::new(4))
        .expect("root");
    // create_child without CREATE_JOB.
    assert_eq!(
        jobs.create_child(root, obj(&mut objects), JobLimits::new(1), Rights::none()),
        Err(KError::AccessDenied)
    );
    // add_process without CREATE_PROCESS.
    assert_eq!(
        jobs.add_process(root, member(&mut objects, 0), Rights::none()),
        Err(KError::AccessDenied)
    );
    // kill_order without KILL.
    let mut order = [None; MAX_JOBS];
    assert_eq!(
        jobs.kill_order(root, Rights::none(), &mut order),
        Err(KError::AccessDenied)
    );
}

#[test]
fn kill_order_is_innermost_first_and_marks_every_job_killed() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    // root ─ childA ─ grandchild
    //      └ childB
    let root = jobs
        .create_root(obj(&mut objects), JobLimits::new(8))
        .expect("root");
    let child_a = jobs
        .create_child(root, obj(&mut objects), JobLimits::new(4), FULL)
        .expect("a");
    let child_b = jobs
        .create_child(root, obj(&mut objects), JobLimits::new(4), FULL)
        .expect("b");
    let grand = jobs
        .create_child(child_a, obj(&mut objects), JobLimits::new(2), FULL)
        .expect("grand");

    let mut order = [None; MAX_JOBS];
    let count = jobs.kill_order(root, FULL, &mut order).expect("order");
    assert_eq!(count, 4);
    // Every descendant must precede its ancestor.
    let pos = |target: JobId| {
        order[..count]
            .iter()
            .position(|&j| j == Some(target))
            .unwrap()
    };
    assert!(pos(grand) < pos(child_a), "grandchild before its parent");
    assert!(pos(child_a) < pos(root), "childA before root");
    assert!(pos(child_b) < pos(root), "childB before root");
    // The root is last (innermost first ⇒ outermost last).
    assert_eq!(order[count - 1], Some(root));
    // All four are marked killed.
    for job in [root, child_a, child_b, grand] {
        assert!(jobs.job(job).expect("job").is_killed());
    }
}

#[test]
fn a_full_job_pool_refuses_root_creation() {
    let mut objects = ObjectTable::new();
    let mut jobs = JobTable::new();
    for _ in 0..MAX_JOBS {
        jobs.create_root(obj(&mut objects), JobLimits::new(1))
            .expect("root");
    }
    assert_eq!(
        jobs.create_root(obj(&mut objects), JobLimits::new(1)),
        Err(KError::OutOfMemory)
    );
}
