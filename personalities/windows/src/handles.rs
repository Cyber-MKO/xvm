//! Kernel object handles of one process.
//!
//! Handle values are multiples of 4, as on Windows, and are never 0 or
//! the pseudo-handles -1 and -2.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::sync::{EventObject, MutexObject, SemaphoreObject, ThreadObject, Waitable};

/// An open file or directory.
#[derive(Debug, Clone)]
pub struct FileObject {
    /// Shared so I/O can run without the process lock.
    pub file: Arc<std::fs::File>,
    /// The host path, used to check share modes between handles.
    pub host_path: PathBuf,
    pub windows_path: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    /// FILE_SHARE_READ (1), FILE_SHARE_WRITE (2), FILE_SHARE_DELETE (4).
    pub share: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone)]
pub enum Object {
    File(FileObject),
    Event(Arc<EventObject>),
    Thread(Arc<ThreadObject>),
    Semaphore(Arc<SemaphoreObject>),
    Mutex(Arc<MutexObject>),
}

impl Object {
    /// What a wait on this handle waits for, if it can be waited on.
    pub fn waitable(&self) -> Option<Waitable> {
        match self {
            Object::Event(e) => Some(Waitable::Event(e.clone())),
            Object::Thread(t) => Some(Waitable::Thread(t.clone())),
            Object::Semaphore(s) => Some(Waitable::Semaphore(s.clone())),
            Object::Mutex(m) => Some(Waitable::Mutex(m.clone())),
            Object::File(_) => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct HandleTable {
    objects: BTreeMap<u32, Object>,
    next: u32,
}

const FIRST_HANDLE: u32 = 0x40;

impl HandleTable {
    pub fn insert(&mut self, object: Object) -> u32 {
        if self.next == 0 {
            self.next = FIRST_HANDLE;
        }
        while self.objects.contains_key(&self.next) {
            self.next += 4;
        }
        let handle = self.next;
        self.next += 4;
        self.objects.insert(handle, object);
        handle
    }

    pub fn get(&self, handle: u32) -> Option<&Object> {
        self.objects.get(&handle)
    }

    pub fn remove(&mut self, handle: u32) -> Option<Object> {
        self.objects.remove(&handle)
    }

    pub fn files(&self) -> impl Iterator<Item = &FileObject> {
        self.objects.values().filter_map(|o| match o {
            Object::File(f) => Some(f),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Object {
        Object::File(FileObject {
            file: Arc::new(std::fs::File::open("/dev/null").unwrap()),
            host_path: "/dev/null".into(),
            windows_path: r"C:\nul".into(),
            can_read: true,
            can_write: false,
            can_delete: false,
            share: 7,
            is_directory: false,
        })
    }

    #[test]
    fn handles_are_multiples_of_four_and_not_reused_while_open() {
        let mut table = HandleTable::default();
        let a = table.insert(file());
        let b = table.insert(file());
        assert!(a % 4 == 0 && b % 4 == 0 && a != b && a != 0);
        assert!(table.remove(a).is_some());
        assert!(table.get(a).is_none());
        assert!(table.get(b).is_some());
        assert_eq!(table.files().count(), 1);
    }
}
