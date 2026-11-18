//! Bounded, delayed post-import quota refresh with retained worker ownership.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures_util::FutureExt;
use tokio::{sync::watch, task::JoinHandle, time::Instant};

use crate::{
    account_refresh::{self, RefreshOutcome},
    state::AppState,
};

const MAX_PENDING: usize = 256;
const BUSY_RETRIES: u8 = 50;
const BUSY_DELAY: Duration = Duration::from_millis(100);

pub struct BackgroundRefreshConfig {
    pub import_delay: Duration,
    pub oauth_delay: Duration,
    pub capacity: usize,
    pub shutdown_wait: Duration,
}

impl Default for BackgroundRefreshConfig {
    fn default() -> Self {
        Self {
            import_delay: Duration::from_millis(500),
            oauth_delay: Duration::from_secs(1),
            capacity: 2,
            shutdown_wait: Duration::from_secs(5),
        }
    }
}

pub struct BackgroundShutdownReport {
    pub drained: bool,
    pub abandoned: Vec<i64>,
    pub cancelled: usize,
}

struct Job {
    ready: Instant,
    retries: u8,
}

#[derive(Default)]
struct Control {
    stopped: bool,
    pending: BTreeMap<i64, Job>,
    executing: BTreeSet<i64>,
    cancelled: usize,
}

struct Shared {
    state: Arc<AppState>,
    control: Mutex<Control>,
    changed: watch::Sender<()>,
}

pub struct BackgroundRefresh {
    shared: Arc<Shared>,
    config: BackgroundRefreshConfig,
    // Tasks own Shared, never this handle owner.
    workers: Mutex<Vec<JoinHandle<()>>>,
    active: bool,
}

impl BackgroundRefresh {
    pub fn new(state: Arc<AppState>) -> Self {
        Self::with_config(state, BackgroundRefreshConfig::default())
    }

    pub fn with_config(state: Arc<AppState>, mut config: BackgroundRefreshConfig) -> Self {
        config.capacity = config.capacity.clamp(1, 16);
        let (changed, _) = watch::channel(());
        let shared = Arc::new(Shared {
            state,
            control: Mutex::new(Control::default()),
            changed,
        });
        let runtime = tokio::runtime::Handle::try_current().ok();
        let mut workers = Vec::new();
        if let Some(runtime) = &runtime {
            for _ in 0..config.capacity {
                workers.push(runtime.spawn(work(shared.clone(), shared.changed.subscribe())));
            }
        }
        Self {
            shared,
            config,
            workers: Mutex::new(workers),
            active: runtime.is_some(),
        }
    }

    pub fn refresh_after_import(&self, account_id: i64) -> bool {
        self.enqueue(account_id, self.config.import_delay)
    }

    pub fn refresh_after_oauth(&self, account_id: i64) -> bool {
        self.enqueue(account_id, self.config.oauth_delay)
    }

    fn enqueue(&self, id: i64, delay: Duration) -> bool {
        if !self.active {
            return false;
        }
        let mut control = self.shared.control.lock().unwrap();
        if control.stopped
            || control.pending.contains_key(&id)
            || control.pending.len() >= MAX_PENDING
        {
            return false;
        }
        control.pending.insert(
            id,
            Job {
                ready: Instant::now() + delay,
                retries: 0,
            },
        );
        self.shared.changed.send_replace(());
        true
    }

    pub fn pending(&self) -> Vec<i64> {
        self.shared
            .control
            .lock()
            .unwrap()
            .pending
            .keys()
            .copied()
            .collect()
    }

    pub fn executing(&self) -> Vec<i64> {
        self.shared
            .control
            .lock()
            .unwrap()
            .executing
            .iter()
            .copied()
            .collect()
    }

    pub fn is_stopped(&self) -> bool {
        self.shared.control.lock().unwrap().stopped
    }

    pub fn stop(&self) {
        let mut control = self.shared.control.lock().unwrap();
        control.stopped = true;
        control.cancelled += control.pending.len();
        control.pending.clear();
        self.shared.changed.send_replace(());
    }

    pub async fn wait_idle(&self) {
        loop {
            let idle = {
                let control = self.shared.control.lock().unwrap();
                control.pending.is_empty() && control.executing.is_empty()
            };
            let joined = {
                let mut workers = self.workers.lock().unwrap();
                workers.retain_mut(|handle| !join_finished(handle));
                workers.is_empty()
            };
            if idle && (!self.is_stopped() || joined) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn shutdown(&self) -> BackgroundShutdownReport {
        self.stop();
        let drained = tokio::time::timeout(self.config.shutdown_wait, self.wait_idle())
            .await
            .is_ok();
        let control = self.shared.control.lock().unwrap();
        BackgroundShutdownReport {
            drained,
            abandoned: if drained {
                Vec::new()
            } else {
                control.executing.iter().copied().collect()
            },
            cancelled: control.cancelled,
        }
    }
}

impl Drop for BackgroundRefresh {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn work(shared: Arc<Shared>, mut changed: watch::Receiver<()>) {
    loop {
        let (job, next) = {
            let mut control = shared.control.lock().unwrap();
            if control.stopped {
                return;
            }
            let next = control
                .pending
                .iter()
                .filter(|(id, _)| !control.executing.contains(*id))
                .min_by_key(|(id, job)| (job.ready, **id))
                .map(|(&id, job)| (id, job.ready));
            match next {
                Some((id, ready)) if ready <= Instant::now() => {
                    let job = control.pending.remove(&id).unwrap();
                    control.executing.insert(id);
                    (Some((id, job)), None)
                }
                other => (None, other.map(|(_, ready)| ready)),
            }
        };
        let Some((id, job)) = job else {
            tokio::select! {
                _ = changed.changed() => (),
                _ = async {
                    match next {
                        Some(ready) => tokio::time::sleep_until(ready).await,
                        None => std::future::pending::<()>().await,
                    }
                } => (),
            }
            continue;
        };
        let refresh = account_refresh::refresh_background(&shared.state, id);
        tokio::pin!(refresh);
        let mut first_poll = true;
        // Serialize the first HTTP poll with stop, without holding a guard across an await.
        let result = AssertUnwindSafe(std::future::poll_fn(|cx| {
            if first_poll {
                let control = shared.control.lock().unwrap();
                if control.stopped {
                    return Poll::Ready(Ok(RefreshOutcome::Skipped));
                }
                first_poll = false;
                refresh.as_mut().poll(cx)
            } else {
                refresh.as_mut().poll(cx)
            }
        }))
        .catch_unwind()
        .await;
        let mut control = shared.control.lock().unwrap();
        control.executing.remove(&id);
        match result {
            Ok(Ok(RefreshOutcome::Inflight(_))) if !control.stopped => {
                if !control.pending.contains_key(&id) {
                    if job.retries < BUSY_RETRIES && control.pending.len() < MAX_PENDING {
                        control.pending.insert(
                            id,
                            Job {
                                ready: Instant::now() + BUSY_DELAY,
                                retries: job.retries + 1,
                            },
                        );
                    } else {
                        eprintln!(
                            "background quota refresh reschedule refused for busy account {id}"
                        );
                    }
                }
            }
            Ok(Err(error)) => eprintln!(
                "background quota refresh failed for account {id}: {} ({})",
                error.message, error.status
            ),
            Err(_) => eprintln!("background quota refresh panicked for account {id}"),
            _ => (),
        }
        shared.changed.send_replace(());
    }
}

fn join_finished(handle: &mut JoinHandle<()>) -> bool {
    if !handle.is_finished() {
        return false;
    }
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    match std::pin::Pin::new(handle).poll(&mut cx) {
        Poll::Ready(result) => {
            if let Err(error) = result {
                eprintln!("background quota worker join failed: {error}");
            }
            true
        }
        Poll::Pending => false,
    }
}
