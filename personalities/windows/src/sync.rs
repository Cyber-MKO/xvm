//! Waitable kernel objects and the waits on them.
//!
//! Each process has one hub: a mutex and a condition variable. Every
//! change to an object's signaled state happens under the hub's mutex
//! and wakes all waiters; each waiter rechecks its own objects. That
//! makes waiting on several objects at once (`WaitForMultipleObjects`)
//! as simple as waiting on one. Waits never hold the process lock.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

/// An event object.
#[derive(Debug)]
pub struct EventObject {
    /// Manual-reset events stay signaled until reset; auto-reset events
    /// release one waiter and reset.
    pub manual_reset: bool,
    signaled: AtomicBool,
}

impl EventObject {
    pub fn new(manual_reset: bool, signaled: bool) -> Self {
        EventObject {
            manual_reset,
            signaled: AtomicBool::new(signaled),
        }
    }

    pub fn is_signaled(&self) -> bool {
        self.signaled.load(Ordering::SeqCst)
    }
}

/// A thread object: signaled once the thread has ended.
#[derive(Debug)]
pub struct ThreadObject {
    /// The ID `GetCurrentThreadId` reports for it.
    pub id: u32,
    finished: AtomicBool,
    exit_code: AtomicU32,
    /// `SetThreadPriority`'s value, kept but not applied to the host.
    pub priority: AtomicI32,
}

impl ThreadObject {
    pub fn new(id: u32) -> Self {
        ThreadObject {
            id,
            finished: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
            priority: AtomicI32::new(0),
        }
    }

    /// The exit code, or None while the thread runs.
    pub fn exit_code(&self) -> Option<u32> {
        self.finished
            .load(Ordering::SeqCst)
            .then(|| self.exit_code.load(Ordering::SeqCst))
    }
}

/// A semaphore: signaled while its count is above zero.
#[derive(Debug)]
pub struct SemaphoreObject {
    pub maximum: i32,
    count: AtomicI32,
}

impl SemaphoreObject {
    pub fn new(initial: i32, maximum: i32) -> Self {
        SemaphoreObject {
            maximum,
            count: AtomicI32::new(initial),
        }
    }

    pub fn count(&self) -> i32 {
        self.count.load(Ordering::SeqCst)
    }
}

/// A mutex: signaled when free, and for the thread that owns it, which
/// may take it again (each wait counts; each release uncounts).
#[derive(Debug, Default)]
pub struct MutexObject {
    /// Owning thread ID, 0 when free.
    owner: AtomicU32,
    count: AtomicU32,
    /// Its owner ended without releasing it; the next wait reports that.
    abandoned: AtomicBool,
}

impl MutexObject {
    pub fn owner(&self) -> u32 {
        self.owner.load(Ordering::SeqCst)
    }
}

/// Something a thread can wait for.
#[derive(Debug, Clone)]
pub enum Waitable {
    Event(Arc<EventObject>),
    Thread(Arc<ThreadObject>),
    Semaphore(Arc<SemaphoreObject>),
    Mutex(Arc<MutexObject>),
}

impl Waitable {
    /// Whether a wait by thread `me` would succeed now.
    fn is_signaled(&self, me: u32) -> bool {
        match self {
            Waitable::Event(e) => e.is_signaled(),
            Waitable::Thread(t) => t.finished.load(Ordering::SeqCst),
            Waitable::Semaphore(s) => s.count() > 0,
            Waitable::Mutex(m) => m.owner() == 0 || m.owner() == me,
        }
    }

    /// What a successful wait by `me` does to the object. Returns true
    /// for an abandoned mutex.
    fn consume(&self, me: u32) -> bool {
        match self {
            Waitable::Event(e) if !e.manual_reset => e.signaled.store(false, Ordering::SeqCst),
            Waitable::Semaphore(s) => {
                s.count.fetch_sub(1, Ordering::SeqCst);
            }
            Waitable::Mutex(m) => {
                m.owner.store(me, Ordering::SeqCst);
                m.count.fetch_add(1, Ordering::SeqCst);
                return m.abandoned.swap(false, Ordering::SeqCst);
            }
            Waitable::Event(_) | Waitable::Thread(_) => {}
        }
        false
    }
}

/// How a wait ended well: which object, and whether it was an abandoned
/// mutex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Woken {
    pub index: usize,
    pub abandoned: bool,
}

#[derive(Debug, Default)]
pub struct SyncHub {
    /// Every mutex created, so an ending thread's mutexes can be
    /// abandoned.
    lock: Mutex<Vec<Weak<MutexObject>>>,
    changed: Condvar,
}

impl SyncHub {
    pub fn set_event(&self, event: &EventObject) {
        let _guard = self.lock.lock().unwrap();
        event.signaled.store(true, Ordering::SeqCst);
        self.changed.notify_all();
    }

    /// Record the thread's exit code and signal its object, once. Mutexes
    /// it still owns become free and abandoned.
    pub fn finish_thread(&self, thread: &ThreadObject, exit_code: u32) {
        let mut mutexes = self.lock.lock().unwrap();
        if !thread.finished.load(Ordering::SeqCst) {
            thread.exit_code.store(exit_code, Ordering::SeqCst);
            thread.finished.store(true, Ordering::SeqCst);
        }
        mutexes.retain(|m| m.strong_count() > 0);
        for m in mutexes.iter().filter_map(Weak::upgrade) {
            if m.owner() == thread.id {
                m.owner.store(0, Ordering::SeqCst);
                m.count.store(0, Ordering::SeqCst);
                m.abandoned.store(true, Ordering::SeqCst);
            }
        }
        self.changed.notify_all();
    }

    /// A new mutex, owned by `owner` once if that is not 0.
    pub fn new_mutex(&self, owner: u32) -> Arc<MutexObject> {
        let m = Arc::new(MutexObject::default());
        if owner != 0 {
            m.owner.store(owner, Ordering::SeqCst);
            m.count.store(1, Ordering::SeqCst);
        }
        self.lock.lock().unwrap().push(Arc::downgrade(&m));
        m
    }

    /// Release one hold of `mutex` by `me`. False if `me` does not own it.
    pub fn release_mutex(&self, mutex: &MutexObject, me: u32) -> bool {
        let _guard = self.lock.lock().unwrap();
        if me == 0 || mutex.owner() != me {
            return false;
        }
        if mutex.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            mutex.owner.store(0, Ordering::SeqCst);
            self.changed.notify_all();
        }
        true
    }

    /// Add `n` to the count and return the previous count, or None if
    /// that would pass the maximum (the count is then unchanged).
    pub fn release_semaphore(&self, semaphore: &SemaphoreObject, n: i32) -> Option<i32> {
        let _guard = self.lock.lock().unwrap();
        let previous = semaphore.count();
        if n <= 0 || previous.checked_add(n)? > semaphore.maximum {
            return None;
        }
        semaphore.count.store(previous + n, Ordering::SeqCst);
        self.changed.notify_all();
        Some(previous)
    }

    pub fn reset_event(&self, event: &EventObject) {
        let _guard = self.lock.lock().unwrap();
        event.signaled.store(false, Ordering::SeqCst);
    }

    /// `wait_as` for a waiter that owns no mutex.
    pub fn wait(
        &self,
        objects: &[Waitable],
        all: bool,
        timeout: Option<Duration>,
    ) -> Option<usize> {
        self.wait_as(0, objects, all, timeout).map(|w| w.index)
    }

    /// Wait as thread `me` until one of `objects` (or, with `all`, every
    /// one) is signaled, then consume it as a successful wait does.
    /// Returns the object (with `all`, the first abandoned mutex, else
    /// 0), or None on timeout. `None` for `timeout` waits forever.
    pub fn wait_as(
        &self,
        me: u32,
        objects: &[Waitable],
        all: bool,
        timeout: Option<Duration>,
    ) -> Option<Woken> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut guard = self.lock.lock().unwrap();
        loop {
            if all {
                if objects.iter().all(|o| o.is_signaled(me)) {
                    let abandoned: Vec<bool> = objects.iter().map(|o| o.consume(me)).collect();
                    let first = abandoned.iter().position(|&a| a);
                    return Some(Woken {
                        index: first.unwrap_or(0),
                        abandoned: first.is_some(),
                    });
                }
            } else if let Some(i) = objects.iter().position(|o| o.is_signaled(me)) {
                let abandoned = objects[i].consume(me);
                return Some(Woken {
                    index: i,
                    abandoned,
                });
            }
            guard = match deadline {
                None => self.changed.wait(guard).unwrap(),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return None;
                    }
                    self.changed.wait_timeout(guard, deadline - now).unwrap().0
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(manual: bool, signaled: bool) -> Arc<EventObject> {
        Arc::new(EventObject::new(manual, signaled))
    }

    #[test]
    fn auto_reset_releases_one_waiter_manual_reset_stays_set() {
        let hub = SyncHub::default();
        let auto = event(false, true);
        let w = [Waitable::Event(auto.clone())];
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(0));
        assert_eq!(
            hub.wait(&w, false, Some(Duration::ZERO)),
            None,
            "reset by the wait"
        );

        let manual = event(true, true);
        let w = [Waitable::Event(manual.clone())];
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(0));
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(0));
        hub.reset_event(&manual);
        assert_eq!(hub.wait(&w, false, Some(Duration::from_millis(10))), None);
    }

    #[test]
    fn a_waiter_wakes_when_another_thread_sets_the_event() {
        let hub = Arc::new(SyncHub::default());
        let e = event(false, false);
        let waiter = {
            let (hub, e) = (hub.clone(), e.clone());
            std::thread::spawn(move || hub.wait(&[Waitable::Event(e)], false, None))
        };
        std::thread::sleep(Duration::from_millis(20));
        hub.set_event(&e);
        assert_eq!(waiter.join().unwrap(), Some(0));
        assert!(!e.is_signaled(), "the waiter consumed it");
    }

    #[test]
    fn threads_signal_once_with_their_exit_code() {
        let hub = SyncHub::default();
        let t = Arc::new(ThreadObject::new(8));
        let w = [Waitable::Thread(t.clone())];
        assert_eq!(t.exit_code(), None);
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), None);
        hub.finish_thread(&t, 3);
        hub.finish_thread(&t, 4);
        assert_eq!(t.exit_code(), Some(3));
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(0));
        assert_eq!(
            hub.wait(&w, false, Some(Duration::ZERO)),
            Some(0),
            "stays signaled"
        );
    }

    #[test]
    fn semaphores_count_down_on_waits_and_up_on_release() {
        let hub = SyncHub::default();
        let s = Arc::new(SemaphoreObject::new(1, 2));
        let w = [Waitable::Semaphore(s.clone())];
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(0));
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), None);
        assert_eq!(hub.release_semaphore(&s, 2), Some(0));
        assert_eq!(hub.release_semaphore(&s, 1), None, "past the maximum");
        assert_eq!(s.count(), 2);
        assert_eq!(hub.release_semaphore(&s, 0), None);
    }

    #[test]
    fn any_and_all_over_several_objects() {
        let hub = SyncHub::default();
        let (a, b) = (event(true, false), event(true, true));
        let w = [Waitable::Event(a.clone()), Waitable::Event(b.clone())];
        assert_eq!(hub.wait(&w, false, Some(Duration::ZERO)), Some(1));
        assert_eq!(hub.wait(&w, true, Some(Duration::ZERO)), None);
        hub.set_event(&a);
        assert_eq!(hub.wait(&w, true, Some(Duration::ZERO)), Some(0));
    }
}
