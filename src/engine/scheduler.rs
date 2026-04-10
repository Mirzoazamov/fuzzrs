use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, Notify};
use tokio::time::{Duration, Instant};

/// Represents an abstract task to be processed.
/// In the future, this will contain HTTP request context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: usize,
    pub path: String,
    pub url: String,
}

/// Simulated response for testing the scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskResult {
    Ok,
    RateLimited,
    Error,
}

/// The shared state coordinating concurrency and backpressure.
pub struct SchedulerState {
    max_concurrency: AtomicUsize,
    current_concurrency: AtomicUsize,
    pause_until: RwLock<Option<Instant>>,
    notify_capacity: Notify,
    notify_shutdown: Notify,
}

impl SchedulerState {
    pub fn new(initial_concurrency: usize) -> Self {
        Self {
            max_concurrency: AtomicUsize::new(initial_concurrency),
            current_concurrency: AtomicUsize::new(0),
            pause_until: RwLock::new(None),
            notify_capacity: Notify::new(),
            notify_shutdown: Notify::new(),
        }
    }

    /// Wait until we have concurrency capacity AND we are not globally paused.
    pub async fn wait_for_capacity_and_ready(&self) {
        loop {
            // First check if we need to sleep due to rate limiting
            let pause = { *self.pause_until.read().unwrap() };
            if let Some(until) = pause {
                let now = Instant::now();
                if now < until {
                    tokio::time::sleep(until - now).await;
                    continue; // Re-evaluate after sleeping
                }
            }

            // Check if we have concurrency capacity
            let max = self.max_concurrency.load(Ordering::SeqCst);
            let current = self.current_concurrency.load(Ordering::SeqCst);

            if current < max {
                // Optimistically increment. Since there's only ONE consumer (dispatcher),
                // this is race-free for capacity upgrades.
                self.current_concurrency.fetch_add(1, Ordering::SeqCst);
                return;
            }

            // Wait for a worker to finish and notify us
            self.notify_capacity.notified().await;
        }
    }

    /// Worker calls this when it finishes a task.
    pub fn release_capacity(&self) {
        self.current_concurrency.fetch_sub(1, Ordering::SeqCst);
        // Notify dispatcher that capacity might be available
        self.notify_capacity.notify_one();
        // Notify potential shutdown waiter
        self.notify_shutdown.notify_waiters();
    }

    /// Triggers the backpressure logic: 5s pause and 20% concurrency reduction.
    pub fn trigger_rate_limit(&self) {
        let mut pause = self.pause_until.write().unwrap();
        let now = Instant::now();

        // Debounce: don't reduce again if we are already pausing
        if let Some(until) = *pause {
            if until > now {
                return;
            }
        }

        // Pause for 5 seconds
        *pause = Some(now + Duration::from_secs(5));

        // Reduce concurrency by 20%
        let current_max = self.max_concurrency.load(Ordering::SeqCst);
        let mut new_max = (current_max * 8) / 10;
        if new_max == 0 {
            new_max = 1; // Never stall completely
        }
        self.max_concurrency.store(new_max, Ordering::SeqCst);
    }
    
    pub fn max_concurrency(&self) -> usize {
        self.max_concurrency.load(Ordering::Relaxed)
    }
}

pub struct Scheduler {
    tx: Option<mpsc::Sender<Task>>,
    state: Arc<SchedulerState>,
    dispatcher_task: Option<tokio::task::JoinHandle<()>>,
}

impl Scheduler {
    /// Creates a new Scheduler. 
    /// `channel_capacity` bounds the mpsc queue (backpressure).
    /// `worker_concurrency` determines max active in-flight tasks.
    /// `processor` is the async closure handling the task.
    pub fn new<F, Fut>(
        channel_capacity: usize,
        worker_concurrency: usize,
        processor: F,
    ) -> Self
    where
        F: Fn(Task, Arc<SchedulerState>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = TaskResult> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel::<Task>(channel_capacity);
        let state = Arc::new(SchedulerState::new(worker_concurrency));

        let dispatcher_state = Arc::clone(&state);
        let processor = Arc::new(processor);

        // Dispatcher loop
        let handle = tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                // Wait for permit (blocks if concurrency limit reached or paused)
                dispatcher_state.wait_for_capacity_and_ready().await;

                let state_clone = Arc::clone(&dispatcher_state);
                let proc_clone = Arc::clone(&processor);

                tokio::spawn(async move {
                    // Check pause right before executing actual work (adheres to "sleep all workers")
                    let pause = { *state_clone.pause_until.read().unwrap() };
                    if let Some(until) = pause {
                        let now = Instant::now();
                        if now < until {
                            tokio::time::sleep(until - now).await;
                        }
                    }

                    // Process the task
                    let result = proc_clone(task, Arc::clone(&state_clone)).await;

                    if result == TaskResult::RateLimited {
                        state_clone.trigger_rate_limit();
                    }

                    // Release capacity
                    state_clone.release_capacity();
                });
            }
        });

        Self {
            tx: Some(tx),
            state,
            dispatcher_task: Some(handle),
        }
    }

    /// Submit a task to the scheduler queue.
    /// Blocks (async) if the channel is full, enforcing backpressure.
    pub async fn submit(&self, task: Task) -> Result<(), mpsc::error::SendError<Task>> {
        if let Some(tx) = &self.tx {
            tx.send(task).await?;
        }
        Ok(())
    }

    /// Triggers graceful shutdown and awaits completion of all tasks.
    pub async fn shutdown(mut self) {
        // Drop the sender to close the channel
        self.tx.take();

        // Wait for dispatcher loop to end
        if let Some(handle) = self.dispatcher_task.take() {
            let _ = handle.await;
        }

        // Wait until all inflight workers release their capacity
        while self.state.current_concurrency.load(Ordering::SeqCst) > 0 {
            self.state.notify_shutdown.notified().await;
        }
    }
    
    pub fn state(&self) -> Arc<SchedulerState> {
        Arc::clone(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_basic_work_distribution() {
        let processed_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&processed_count);

        let scheduler = Scheduler::new(100, 10, move |_task, _state| {
            let c = Arc::clone(&count_clone);
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                TaskResult::Ok
            }
        });

        for i in 0..100 {
            scheduler.submit(Task { id: i, path: "".to_string(), url: "".to_string() }).await.unwrap();
        }

        scheduler.shutdown().await;
        assert_eq!(processed_count.load(Ordering::SeqCst), 100);
    }

    #[tokio::test]
    async fn test_backpressure_bounded_channel() {
        let channel_capacity = 10;
        let scheduler = Scheduler::new(channel_capacity, 2, |_task, _state| {
            async move {
                // Sleep to force channel to fill up
                tokio::time::sleep(Duration::from_millis(50)).await;
                TaskResult::Ok
            }
        });

        let start = Instant::now();
        
        // We submit 15 tasks. Capacity is 10, processing is 2. 
        // 2 will be processing, 10 in queue.
        // the 13th, 14th, 15th will block the producer.
        for i in 0..15 {
            scheduler.submit(Task { id: i, path: "".to_string(), url: "".to_string() }).await.unwrap();
        }
        
        let elapsed = start.elapsed();
        // Since it takes 50ms per task, blocking the producer ensures
        // the producer awaits. If it didn't await, elapsed would be ~0ms.
        assert!(elapsed.as_millis() >= 50);

        scheduler.shutdown().await;
    }

    #[tokio::test]
    async fn test_adaptive_rate_limiting() {
        // To verify the pause, track execution times
        let execution_times = Arc::new(Mutex::new(Vec::new()));
        let exec_clone = Arc::clone(&execution_times);

        let initial_concurrency = 10;
        let scheduler = Scheduler::new(100, initial_concurrency, move |task, _state| {
            let e = Arc::clone(&exec_clone);
            async move {
                e.lock().await.push(Instant::now());
                if task.id == 0 {
                    // Trigger rate limit on the first task
                    TaskResult::RateLimited
                } else {
                    TaskResult::Ok
                }
            }
        });

        let state = scheduler.state();
        let submit_start = Instant::now();

        // Submit 10 tasks
        for i in 0..10 {
            scheduler.submit(Task { id: i, path: "".to_string(), url: "".to_string() }).await.unwrap();
        }

        scheduler.shutdown().await;
        
        // We expected a ~5s pause after the first task triggers 429
        let elapsed = submit_start.elapsed();
        assert!(elapsed.as_secs() >= 5, "Workers should have paused for 5 seconds");
        
        // Concurrency should be reduced by 20% (10 -> 8)
        assert_eq!(state.max_concurrency(), 8);
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let processed_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&processed_count);

        let scheduler = Scheduler::new(50, 10, move |_task, _state| {
            let c = Arc::clone(&count_clone);
            async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                c.fetch_add(1, Ordering::SeqCst);
                TaskResult::Ok
            }
        });

        for i in 0..50 {
            scheduler.submit(Task { id: i, path: "".to_string(), url: "".to_string() }).await.unwrap();
        }

        // initiate shutdown immediately
        scheduler.shutdown().await;
        
        // All tasks must have finished, nothing lost
        assert_eq!(processed_count.load(Ordering::SeqCst), 50);
    }
}
