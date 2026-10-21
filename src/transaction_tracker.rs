use std::collections::{hash_map, HashMap};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// How often completed transactions older than the retention period are dropped. Scanning the whole table on every
/// call makes each call cost O(transactions seen in the retention period), so a busy client slows down quadratically.
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);

/// `TransactionTracker` tracks the state of transactions to detect retransmissions.
pub struct TransactionTracker {
    retention_period: Duration,
    transactions: Mutex<Transactions>,
}

struct Transactions {
    states: HashMap<(u32, String), TransactionState>,
    last_housekeeping: SystemTime,
}

impl TransactionTracker {
    pub fn new(retention_period: Duration) -> Self {
        Self {
            retention_period,
            transactions: Mutex::new(Transactions {
                states: HashMap::new(),
                last_housekeeping: SystemTime::now(),
            }),
        }
    }

    /// Checks if the transaction is a retransmission.
    /// If it's a new transaction, it is marked as `InProgress`.
    ///
    /// Returns `true` if the transaction is a retransmission, `false` otherwise.
    pub fn is_retransmission(&self, xid: u32, client_addr: &str) -> bool {
        let key = (xid, client_addr.to_string());
        let mut transactions = self.transactions.lock().expect("unable to unlock transactions mutex");
        let now = SystemTime::now();
        // A clock that went backwards also triggers housekeeping.
        if now
            .duration_since(transactions.last_housekeeping)
            .map_or(true, |age| age >= HOUSEKEEPING_INTERVAL)
        {
            housekeeping(&mut transactions.states, now, self.retention_period);
            transactions.last_housekeeping = now;
        }
        if let hash_map::Entry::Vacant(e) = transactions.states.entry(key) {
            e.insert(TransactionState::InProgress);
            false
        } else {
            true
        }
    }

    /// Marks the transaction as processed.
    pub fn mark_processed(&self, xid: u32, client_addr: &str) {
        let key = (xid, client_addr.to_string());
        let completion_time = SystemTime::now();
        let mut transactions = self.transactions.lock().expect("unable to unlock transactions mutex");
        if let Some(tx) = transactions.states.get_mut(&key) {
            *tx = TransactionState::Completed(completion_time);
        }
    }
}

fn housekeeping(transactions: &mut HashMap<(u32, String), TransactionState>, now: SystemTime, max_age: Duration) {
    let mut cutoff = now - max_age;
    transactions.retain(|_, v| match v {
        TransactionState::InProgress => true,
        TransactionState::Completed(completion_time) => completion_time >= &mut cutoff,
    });
}

pub enum TransactionState {
    InProgress,
    Completed(SystemTime),
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    const CLIENT: &str = "127.0.0.1:1000";

    fn force_housekeeping(tracker: &TransactionTracker) {
        tracker.transactions.lock().unwrap().last_housekeeping = UNIX_EPOCH;
    }

    #[test]
    fn repeated_xid_from_same_client_is_a_retransmission() {
        let tracker = TransactionTracker::new(Duration::from_secs(60));
        assert!(!tracker.is_retransmission(1, CLIENT));
        assert!(tracker.is_retransmission(1, CLIENT));
        tracker.mark_processed(1, CLIENT);
        assert!(tracker.is_retransmission(1, CLIENT));
        assert!(!tracker.is_retransmission(1, "127.0.0.1:2000"));
    }

    #[test]
    fn housekeeping_drops_only_expired_completed_transactions() {
        let tracker = TransactionTracker::new(Duration::ZERO);
        assert!(!tracker.is_retransmission(1, CLIENT));
        tracker.mark_processed(1, CLIENT);
        assert!(!tracker.is_retransmission(2, CLIENT));

        std::thread::sleep(Duration::from_millis(2));
        force_housekeeping(&tracker);
        assert!(!tracker.is_retransmission(3, CLIENT));
        assert!(!tracker.is_retransmission(1, CLIENT), "expired completed transaction is forgotten");
        assert!(tracker.is_retransmission(2, CLIENT), "in-progress transaction is kept");
    }

    #[test]
    fn housekeeping_waits_for_the_interval() {
        let tracker = TransactionTracker::new(Duration::ZERO);
        assert!(!tracker.is_retransmission(1, CLIENT));
        tracker.mark_processed(1, CLIENT);
        assert!(tracker.is_retransmission(1, CLIENT), "kept until the next housekeeping");
    }
}
