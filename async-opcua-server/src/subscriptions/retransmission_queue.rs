use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use opcua_types::NotificationMessage;

use super::{
    subscription::{reclaim_data_change_notification_vecs, DataChangeNotificationVecPool},
    NonAckedPublish,
};

#[derive(Default)]
pub(crate) struct RetransmissionQueue {
    entries: BTreeMap<u64, NonAckedPublish>,
    index: HashMap<(u32, u32), u64>,
    by_subscription: HashMap<u32, BTreeSet<u64>>,
    next_id: u64,
}

impl RetransmissionQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn enqueue(
        &mut self,
        pool: &mut DataChangeNotificationVecPool,
        max_len: usize,
        subscription_id: u32,
        message: Arc<NotificationMessage>,
    ) {
        if message.notification_data.is_none() {
            return;
        }

        if self.len() >= max_len {
            if let Some((id, entry)) = self.entries.pop_first() {
                self.remove_indexes(id, &entry);
                Self::reclaim_non_acked_publish(pool, entry);
            }
        }

        self.push_existing(NonAckedPublish {
            message,
            subscription_id,
        });
    }

    pub(crate) fn push_existing(&mut self, entry: NonAckedPublish) {
        let id = self.next_id;
        self.next_id += 1;

        let subscription_id = entry.subscription_id;
        let sequence_number = entry.message.sequence_number;
        debug_assert!(
            !self.index.contains_key(&(subscription_id, sequence_number)),
            "duplicate retransmission queue entry"
        );

        self.entries.insert(id, entry);
        self.index.insert((subscription_id, sequence_number), id);
        self.by_subscription
            .entry(subscription_id)
            .or_default()
            .insert(id);
    }

    pub(crate) fn ack(
        &mut self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Option<NonAckedPublish> {
        let id = self.index.remove(&(subscription_id, sequence_number))?;
        let entry = self.entries.remove(&id)?;
        self.remove_subscription_id(subscription_id, id);
        Some(entry)
    }

    pub(crate) fn remove_subscription(&mut self, subscription_id: u32) -> Vec<NonAckedPublish> {
        let Some(ids) = self.by_subscription.remove(&subscription_id) else {
            return Vec::new();
        };

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(entry) = self.entries.remove(&id) else {
                continue;
            };
            self.index
                .remove(&(entry.subscription_id, entry.message.sequence_number));
            removed.push(entry);
        }
        removed
    }

    pub(crate) fn clone_subscription(&self, subscription_id: u32) -> Vec<NonAckedPublish> {
        let Some(ids) = self.by_subscription.get(&subscription_id) else {
            return Vec::new();
        };

        ids.iter()
            .filter_map(|id| self.entries.get(id).cloned())
            .collect()
    }

    pub(crate) fn available_sequence_numbers(&self, subscription_id: u32) -> Option<Vec<u32>> {
        if self.is_empty() {
            return None;
        }

        let ids = self.by_subscription.get(&subscription_id)?;
        let sequence_numbers: Vec<u32> = ids
            .iter()
            .filter_map(|id| self.entries.get(id))
            .map(|entry| entry.message.sequence_number)
            .collect();
        if sequence_numbers.is_empty() {
            None
        } else {
            Some(sequence_numbers)
        }
    }

    pub(crate) fn get_message(
        &self,
        subscription_id: u32,
        sequence_number: u32,
    ) -> Option<Arc<NotificationMessage>> {
        let id = self.index.get(&(subscription_id, sequence_number))?;
        self.entries.get(id).map(|entry| Arc::clone(&entry.message))
    }

    fn remove_indexes(&mut self, id: u64, entry: &NonAckedPublish) {
        self.index
            .remove(&(entry.subscription_id, entry.message.sequence_number));
        self.remove_subscription_id(entry.subscription_id, id);
    }

    fn remove_subscription_id(&mut self, subscription_id: u32, id: u64) {
        let Some(ids) = self.by_subscription.get_mut(&subscription_id) else {
            return;
        };
        ids.remove(&id);
        if ids.is_empty() {
            self.by_subscription.remove(&subscription_id);
        }
    }

    fn reclaim_non_acked_publish(
        pool: &mut DataChangeNotificationVecPool,
        notification: NonAckedPublish,
    ) {
        let Some(message) = Arc::into_inner(notification.message) else {
            return;
        };
        reclaim_data_change_notification_vecs(message, pool);
    }
}

#[cfg(test)]
mod tests {
    // Feature 027 (T004/T005): behavior + scaling for the bounded-time retransmission queue.
    use std::sync::Arc;
    use std::time::Instant;

    use opcua_types::{
        DataValue, DateTime, MonitoredItemNotification, NotificationMessage, StatusCode,
    };

    use super::super::subscription::DataChangeNotificationVecPool;
    use super::RetransmissionQueue;

    // status_change carries notification_data, so enqueue accepts it (unlike keep-alive).
    fn msg(seq: u32) -> Arc<NotificationMessage> {
        Arc::new(NotificationMessage::status_change(
            seq,
            DateTime::now(),
            StatusCode::Good,
        ))
    }

    fn data_change_msg(seq: u32) -> Arc<NotificationMessage> {
        Arc::new(NotificationMessage::data_change(
            seq,
            DateTime::now(),
            vec![MonitoredItemNotification {
                client_handle: seq,
                value: DataValue::new_now(seq as i32),
            }],
            Vec::new(),
        ))
    }

    fn push(q: &mut RetransmissionQueue, sub: u32, seq: u32) {
        let mut pool = DataChangeNotificationVecPool::default();
        q.enqueue(&mut pool, usize::MAX, sub, msg(seq));
    }

    #[test]
    fn eviction_drops_globally_oldest_not_lowest_key() {
        let mut q = RetransmissionQueue::new();
        let mut pool = DataChangeNotificationVecPool::default();
        // Interleave two subscriptions; capacity 2.
        q.enqueue(&mut pool, 2, 1, msg(1)); // global #0  (sub1, seq1) — oldest
        q.enqueue(&mut pool, 2, 2, msg(1)); // global #1  (sub2, seq1)
        q.enqueue(&mut pool, 2, 1, msg(2)); // global #2  (sub1, seq2) -> evicts the oldest

        assert_eq!(q.len(), 2);
        assert!(
            q.get_message(1, 1).is_none(),
            "globally oldest (sub1,seq1) must be evicted"
        );
        assert!(q.get_message(2, 1).is_some());
        assert!(q.get_message(1, 2).is_some());
    }

    #[test]
    fn ack_removes_present_and_reports_absent() {
        let mut q = RetransmissionQueue::new();
        push(&mut q, 1, 10);
        push(&mut q, 1, 11);

        assert!(q.ack(1, 10).is_some(), "present key removed");
        assert!(q.get_message(1, 10).is_none());
        assert!(q.ack(1, 10).is_none(), "second ack of same key is absent");
        assert!(q.ack(1, 999).is_none(), "unknown seq is absent");
        assert_eq!(q.len(), 1, "only the acked entry was removed");
    }

    #[test]
    fn available_sequence_numbers_are_in_insertion_order() {
        let mut q = RetransmissionQueue::new();
        assert_eq!(q.available_sequence_numbers(1), None, "empty queue -> None");
        push(&mut q, 1, 5);
        push(&mut q, 2, 100);
        push(&mut q, 1, 6);
        push(&mut q, 1, 7);
        assert_eq!(q.available_sequence_numbers(1), Some(vec![5, 6, 7]));
        assert_eq!(q.available_sequence_numbers(2), Some(vec![100]));
        assert_eq!(q.available_sequence_numbers(3), None, "absent sub -> None");
    }

    #[test]
    fn remove_subscription_returns_insertion_order_and_leaves_others() {
        let mut q = RetransmissionQueue::new();
        push(&mut q, 1, 1);
        push(&mut q, 2, 50);
        push(&mut q, 1, 2);
        push(&mut q, 1, 3);

        let removed = q.remove_subscription(1);
        let seqs: Vec<u32> = removed.iter().map(|e| e.message.sequence_number).collect();
        assert_eq!(seqs, vec![1, 2, 3], "removed in insertion order");
        assert!(q.get_message(1, 1).is_none());
        assert_eq!(
            q.available_sequence_numbers(2),
            Some(vec![50]),
            "other sub untouched"
        );
        assert!(
            q.remove_subscription(999).is_empty(),
            "unknown sub -> empty"
        );
    }

    #[test]
    fn get_message_hit_and_miss() {
        let mut q = RetransmissionQueue::new();
        push(&mut q, 7, 42);
        assert!(q.get_message(7, 42).is_some());
        assert!(q.get_message(7, 43).is_none());
        assert!(q.get_message(8, 42).is_none());
    }

    #[test]
    fn data_change_buffers_are_reclaimed_on_eviction_ack_and_remove() {
        let mut q = RetransmissionQueue::new();
        let mut pool = DataChangeNotificationVecPool::default();

        q.enqueue(&mut pool, 1, 1, data_change_msg(1));
        q.enqueue(&mut pool, 1, 1, data_change_msg(2));
        assert_eq!(
            pool.reclaimed_data_change_vec_count(),
            1,
            "capacity eviction reclaims the evicted data-change Vec"
        );

        let acked = q.ack(1, 2).expect("acked entry must be returned");
        RetransmissionQueue::reclaim_non_acked_publish(&mut pool, acked);
        assert_eq!(
            pool.reclaimed_data_change_vec_count(),
            2,
            "ack caller can reclaim the removed data-change Vec"
        );

        q.enqueue(&mut pool, 4, 2, data_change_msg(10));
        q.enqueue(&mut pool, 4, 2, data_change_msg(11));
        let removed = q.remove_subscription(2);
        assert_eq!(removed.len(), 2);
        for entry in removed {
            RetransmissionQueue::reclaim_non_acked_publish(&mut pool, entry);
        }
        assert_eq!(
            pool.reclaimed_data_change_vec_count(),
            4,
            "remove_subscription caller can reclaim every removed data-change Vec"
        );
    }

    // SC-001: ack-flood and teardown over a large queue complete in sub-quadratic time. A quadratic
    // implementation would miss this generous absolute bound by orders of magnitude.
    #[test]
    fn large_scale_ack_flood_and_teardown_are_bounded() {
        const N: u32 = 50_000;
        const SUBS: u32 = 4;
        let mut q = RetransmissionQueue::new();
        let mut pool = DataChangeNotificationVecPool::default();
        for seq in 0..N {
            let sub = seq % SUBS + 1;
            q.enqueue(&mut pool, N as usize + 1, sub, msg(seq));
        }
        assert_eq!(q.len(), N as usize);

        let start = Instant::now();
        // Ack-flood: acknowledge a large interleaved batch across subscriptions.
        for seq in 0..N / 2 {
            let sub = seq % SUBS + 1;
            assert!(q.ack(sub, seq).is_some());
        }
        // Teardown: bulk-remove each remaining subscription bucket.
        let mut removed_count = 0;
        for sub in 1..=SUBS {
            removed_count += q.remove_subscription(sub).len();
        }
        assert_eq!(removed_count as u32, N - N / 2);
        let elapsed = start.elapsed();

        assert!(q.is_empty());
        assert!(
            elapsed.as_secs() < 5,
            "ack-flood + teardown over {N} entries took {elapsed:?} (quadratic regression?)"
        );
    }
}
