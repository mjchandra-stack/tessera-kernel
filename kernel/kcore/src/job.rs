// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jagadeesh Chandra Muddana <mjchandra@gmail.com>

//! Jobs: the containment tree (docs/kernel/05-jobs-containment-and-resource-
//! control.md). *"A `job` is a kernel object that groups processes and child
//! jobs into a tree"* (L20); *"Every process belongs to exactly one job"*
//! (L22); *"Kill a job terminates all members, innermost first"* (L34); limits
//! *"compose down the job tree: a child can only tighten, never exceed, an
//! ancestor's ceiling"* (L83), and an object-count ceiling *"cause[s] the
//! offending create operation to fail with a resource error"* (L93).
//!
//! This module is the pure tree, limits, and rights logic — no scheduler,
//! ports, or object-table dependency, so it is host-tested. The executive
//! (`exec.rs`) drives the *effects* of a kill (terminating member threads and
//! signalling the state port); a `Job` records the member thread indices and a
//! `state_source` for that. v0 caps member-process counts only; the full
//! `resource_domain` (CPU/memory/IO ceilings and the thread/handle/channel/
//! mapping counts), suspend/resume, and the object/handle bridge are deferred
//! (build/README.md, D40).
//!
//! Normative: docs/kernel/05-jobs-containment-and-resource-control.md
//! Budget: none (docs/architecture/03 has no job create/kill row)

use crate::object::ObjectId;
use crate::rights::Rights;
use tessera_karch::KError;

/// Jobs the table holds.
pub const MAX_JOBS: usize = 16;
/// Member processes a single job may hold.
pub const MAX_MEMBERS_PER_JOB: usize = 8;
/// Child jobs a single job may hold.
pub const MAX_CHILDREN_PER_JOB: usize = 8;

/// State-port signals a job raises on its `state_source` (docs/kernel/05: a job
/// exposes a state port signalling "member exit ... and emptiness"). The
/// policy-violation signal is deferred with the enforcement machinery (D40).
pub const SIGNAL_MEMBER_EXIT: u8 = 1;
pub const SIGNAL_EMPTY: u8 = 2;

/// A raw job identifier: an index into the job table. Like `PortId`, a
/// kernel-internal reference; the handle/rights bridge is deferred (D40).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobId(pub usize);

/// The object-count ceilings a job enforces on its members. v0: member-process
/// count only (the offending create fails with a resource error). The full
/// resource-domain ceilings are deferred (D40).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobLimits {
    pub max_processes: u32,
}

impl JobLimits {
    pub const fn new(max_processes: u32) -> Self {
        Self { max_processes }
    }

    /// Whether these limits are no looser than `ancestor`'s — the tighten-only
    /// rule (a child may not exceed an ancestor's ceiling).
    pub fn within(&self, ancestor: &JobLimits) -> bool {
        self.max_processes <= ancestor.max_processes
    }
}

/// A member process and the scheduler index of its (single, v0) thread — what a
/// kill needs to terminate it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Member {
    pub process: ObjectId,
    pub thread: usize,
}

/// One node in the containment tree.
pub struct Job {
    object: ObjectId,
    parent: Option<JobId>,
    children: [Option<JobId>; MAX_CHILDREN_PER_JOB],
    members: [Option<Member>; MAX_MEMBERS_PER_JOB],
    limits: JobLimits,
    /// Abstract event source for this job's state port (member-exit / emptiness).
    state_source: u64,
    killed: bool,
}

impl Job {
    fn new(object: ObjectId, parent: Option<JobId>, limits: JobLimits) -> Self {
        Self {
            object,
            parent,
            children: [None; MAX_CHILDREN_PER_JOB],
            members: [const { None }; MAX_MEMBERS_PER_JOB],
            limits,
            // A per-job source id, distinct across jobs (its object's raw value).
            state_source: object.raw() as u64,
            killed: false,
        }
    }

    pub fn object(&self) -> ObjectId {
        self.object
    }
    pub fn parent(&self) -> Option<JobId> {
        self.parent
    }
    pub fn limits(&self) -> JobLimits {
        self.limits
    }
    pub fn state_source(&self) -> u64 {
        self.state_source
    }
    pub fn is_killed(&self) -> bool {
        self.killed
    }

    /// The number of member processes currently in this job.
    pub fn member_count(&self) -> usize {
        self.members.iter().flatten().count()
    }

    /// A copy of the member slots (for a kill to terminate them without holding
    /// a borrow on the table).
    pub fn members(&self) -> [Option<Member>; MAX_MEMBERS_PER_JOB] {
        self.members
    }
}

/// A fixed pool of jobs forming the containment forest.
pub struct JobTable {
    jobs: [Option<Job>; MAX_JOBS],
}

impl JobTable {
    pub const fn new() -> Self {
        Self {
            jobs: [const { None }; MAX_JOBS],
        }
    }

    /// Creates a root job (no parent). A boot-privileged operation — no right is
    /// required (the root is the ambient authority every other job derives from).
    pub fn create_root(&mut self, object: ObjectId, limits: JobLimits) -> Result<JobId, KError> {
        let index = self.free_slot()?;
        self.jobs[index] = Some(Job::new(object, None, limits));
        Ok(JobId(index))
    }

    /// Creates a child job under `parent`. Requires `CREATE_JOB` on the parent
    /// and enforces the tighten-only rule: the child's limits may not exceed the
    /// parent's ceiling.
    pub fn create_child(
        &mut self,
        parent: JobId,
        object: ObjectId,
        limits: JobLimits,
        caller_rights: Rights,
    ) -> Result<JobId, KError> {
        if !caller_rights.contains(Rights::CREATE_JOB) {
            return Err(KError::AccessDenied);
        }
        let parent_job = self.job(parent).ok_or(KError::BadHandle)?;
        if parent_job.killed {
            return Err(KError::BadHandle);
        }
        if !limits.within(&parent_job.limits) {
            return Err(KError::LimitExceeded);
        }
        let index = self.free_slot()?;
        self.jobs[index] = Some(Job::new(object, Some(parent), limits));
        let child = JobId(index);
        // Link the child into the parent's child set.
        let parent_job = self.job_mut(parent).ok_or(KError::BadHandle)?;
        let slot = parent_job
            .children
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        parent_job.children[slot] = Some(child);
        Ok(child)
    }

    /// Adds a member process (with its thread's scheduler index) to `job`.
    /// Requires `CREATE_PROCESS`; the member-count ceiling rejects the create
    /// with `LimitExceeded` rather than degrading the system.
    pub fn add_process(
        &mut self,
        job: JobId,
        member: Member,
        caller_rights: Rights,
    ) -> Result<(), KError> {
        if !caller_rights.contains(Rights::CREATE_PROCESS) {
            return Err(KError::AccessDenied);
        }
        let job = self.job_mut(job).ok_or(KError::BadHandle)?;
        if job.killed {
            return Err(KError::BadHandle);
        }
        if job.member_count() as u32 >= job.limits.max_processes {
            return Err(KError::LimitExceeded);
        }
        let slot = job
            .members
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)?;
        job.members[slot] = Some(member);
        Ok(())
    }

    /// Fills `order` with the `root` subtree's jobs **innermost-first** (every
    /// descendant before its ancestor), returns the count, and marks each job
    /// `killed`. Requires `KILL`. The caller (executive) then terminates each
    /// job's member threads and signals its state port in this order.
    pub fn kill_order(
        &mut self,
        root: JobId,
        caller_rights: Rights,
        order: &mut [Option<JobId>],
    ) -> Result<usize, KError> {
        if !caller_rights.contains(Rights::KILL) {
            return Err(KError::AccessDenied);
        }
        if self.job(root).is_none() {
            return Err(KError::BadHandle);
        }
        // DFS visiting parents before children (a pre-order), into a scratch
        // list; the subtree has at most MAX_JOBS nodes.
        let mut pre: [Option<JobId>; MAX_JOBS] = [None; MAX_JOBS];
        let mut pre_len = 0usize;
        let mut stack: [Option<JobId>; MAX_JOBS] = [None; MAX_JOBS];
        let mut sp = 0usize;
        stack[sp] = Some(root);
        sp += 1;
        while sp > 0 {
            sp -= 1;
            let Some(job_id) = stack[sp] else { continue };
            if pre_len >= pre.len() {
                return Err(KError::OutOfMemory);
            }
            pre[pre_len] = Some(job_id);
            pre_len += 1;
            if let Some(job) = self.job(job_id) {
                for child in job.children.iter().flatten() {
                    if sp >= stack.len() {
                        return Err(KError::OutOfMemory);
                    }
                    stack[sp] = Some(*child);
                    sp += 1;
                }
            }
        }
        if order.len() < pre_len {
            return Err(KError::OutOfMemory);
        }
        // Reverse the parents-before-children list → innermost-first: every
        // ancestor now follows all its descendants.
        for i in 0..pre_len {
            order[i] = pre[pre_len - 1 - i];
        }
        for slot in order.iter().take(pre_len) {
            if let Some(job_id) = slot
                && let Some(job) = self.job_mut(*job_id)
            {
                job.killed = true;
            }
        }
        Ok(pre_len)
    }

    pub fn job(&self, id: JobId) -> Option<&Job> {
        self.jobs.get(id.0).and_then(Option::as_ref)
    }

    pub fn job_mut(&mut self, id: JobId) -> Option<&mut Job> {
        self.jobs.get_mut(id.0).and_then(Option::as_mut)
    }

    fn free_slot(&self) -> Result<usize, KError> {
        self.jobs
            .iter()
            .position(Option::is_none)
            .ok_or(KError::OutOfMemory)
    }
}

impl Default for JobTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/job.rs"]
mod tests;
