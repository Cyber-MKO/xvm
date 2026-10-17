//! Waitable kernel objects and the waits on them.
//!
//! Each process has one hub: a mutex and a condition variable. Every
//! change to an object's signaled state happens under the hub's mutex
//! and wakes all waiters; each waiter rechecks its own objects. That
//! makes waiting on several objects at once (`WaitForMultipleObjects`)
//! as simple as waiting on one. Waits never hold the process lock.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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

/// Something a thread can wait for.
#[derive(Debug, Clone)]
pub enum Waitable {
    Event(Arc<EventObject>),
    Thread(Arc<ThreadObject>),
    Semaphore(Arc<SemaphoreObject>),
}

impl Waitable {
    fn is_signaled(&self) -> bool {
        match self {
            Waitable::Event(e) => e.is_signaled(),
            Waitable::Thread(t) => t.finished.load(Ordering::SeqCst),
            Waitable::Semaphore(s) => s.count() > 0,
        }
    }

    /// What a successful wait does to the object.
    fn consume(&self) {
        match self {
            Waitable::Event(e) if !e.manual_reset => e.signaled.store(false, Ordering::SeqCst),
            Waitable::Semaphore(s) => {
                s.count.fetch_sub(1, Ordering::SeqCst);
            }
            Waitable::Event(_) | Waitable::Thread(_) => {}
        }
    }
}

#[derive(Debug, Default)]
pub struct SyncHub {
    lock: Mutex<()>,
    changed: Condvar,
}

impl SyncHub {
    pub fn set_event(&self, event: &EventObject) {
        let _guard = self.lock.lock().unwrap();
        event.signaled.store(true, Ordering::SeqCst);
        self.changed.notify_all();
    }

    /// Record the thread's exit code and signal its object, once.
    pub fn finish_thread(&self, thread: &ThreadObject, exit_code: u32) {
        let _guard = self.lock.lock().unwrap();
        if !thread.finished.load(Ordering::SeqCst) {
            thread.exit_code.store(exit_code, Ordering::SeqCst);
            thread.finished.store(true, Ordering::SeqCst);
        }
        self.changed.notify_all();
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

    /// Wait until one of `objects` (or, with `all`, every one) is
    /// signaled, then consume it as a successful wait does. Returns the
    /// index of the object (0 with `all`), or None on timeout. `None` for
    /// `timeout` waits forever.
    pub fn wait(
        &self,
        objects: &[Waitable],
        all: bool,
        timeout: Option<Duration>,
    ) -> Option<usize> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut guard = self.lock.lock().unwrap();
        loop {
            if all {
                if objects.iter().all(Waitable::is_signaled) {
                    objects.iter().for_each(Waitable::consume);
                    return Some(0);
                }
            } else if let Some(i) = objects.iter().position(Waitable::is_signaled) {
                objects[i].consume();
                return Some(i);
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
