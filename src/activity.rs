use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, PartialEq)]
pub enum Status {
    Running,
    Done(String),
}

#[derive(Clone)]
pub struct Activity {
    pub id: u64,
    pub kind: &'static str,
    pub description: String,
    pub status: Status,
    pub time: String,        // HH:MM:SS at start
    pub started: Instant,
}

impl Activity {
    pub fn elapsed_str(&self) -> String {
        let ms = self.started.elapsed().as_millis();
        if ms < 1000 {
            format!("{}ms", ms)
        } else {
            format!("{:.1}s", ms as f64 / 1000.0)
        }
    }
}

struct Inner {
    entries: VecDeque<Activity>,
    next_id: u64,
}

#[derive(Clone)]
pub struct ActivityLog {
    inner: Arc<Mutex<Inner>>,
}

impl ActivityLog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: VecDeque::new(),
                next_id: 0,
            })),
        }
    }

    pub fn start(&self, kind: &'static str, description: String) -> u64 {
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
        let now = chrono::Local::now();
        g.entries.push_back(Activity {
            id,
            kind,
            description,
            status: Status::Running,
            time: now.format("%H:%M:%S").to_string(),
            started: Instant::now(),
        });
        // keep a bounded history
        while g.entries.len() > 20 {
            g.entries.pop_front();
        }
        id
    }

    pub fn finish(&self, id: u64, result: String) {
        let mut g = self.inner.lock().unwrap();
        if let Some(a) = g.entries.iter_mut().find(|a| a.id == id) {
            a.status = Status::Done(result);
        }
    }

    // Returns up to `n` most-recent entries, oldest first.
    pub fn recent(&self, n: usize) -> Vec<Activity> {
        let g = self.inner.lock().unwrap();
        let skip = g.entries.len().saturating_sub(n);
        g.entries.iter().skip(skip).cloned().collect()
    }
}
