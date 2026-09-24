//! Bounded replay of successful UDP Allocate/Refresh responses.
//! Ingress limits still apply. Unauthenticated/error traffic cannot fill this
//! cache. Entries are exact-wire matches, scoped to the processor and source.
use bytes::Bytes;
use parking_lot::{Mutex, MutexGuard};
use std::collections::{hash_map::RandomState, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const SHARDS: usize = 64;
const CAPACITY: usize = 128; // 8192 entries total, <= 4096 request + 1024 response bytes each.
const TTL: Duration = Duration::from_secs(40);
type Key = (SocketAddr, [u8; 12]);
struct Entry {
    request: Bytes,
    response: Bytes,
    until: Instant,
}
pub(crate) enum Lookup {
    Miss,
    Conflict,
    Reply(Bytes),
}
#[derive(Default)]
pub(crate) struct Cache {
    entries: HashMap<Key, Entry>,
    order: VecDeque<Key>,
}
impl Cache {
    fn key(src: SocketAddr, raw: &[u8]) -> Key {
        (src, raw[8..20].try_into().expect("decoded STUN header"))
    }
    pub(crate) fn expire(&mut self, now: Instant) {
        while let Some(key) = self.order.front() {
            if self.entries.get(key).is_some_and(|v| v.until > now) {
                break;
            }
            let key = self.order.pop_front().unwrap();
            self.entries.remove(&key);
        }
    }
    pub(crate) fn lookup(&self, src: SocketAddr, raw: &[u8]) -> Lookup {
        match self.entries.get(&Self::key(src, raw)) {
            None => Lookup::Miss,
            Some(e) if e.request.as_ref() == raw => Lookup::Reply(e.response.clone()),
            Some(_) => Lookup::Conflict,
        }
    }
    pub(crate) fn insert(
        &mut self,
        src: SocketAddr,
        request: Bytes,
        response: Bytes,
        now: Instant,
    ) {
        if request.len() > 4096 || response.len() > 1024 {
            return;
        }
        let key = Self::key(src, &request);
        // Duplicate hits never refresh TTL or add queue entries.
        if self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() == CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.order.push_back(key);
        self.entries.insert(
            key,
            Entry {
                request: Bytes::copy_from_slice(&request),
                response: Bytes::copy_from_slice(&response),
                until: now + TTL,
            },
        );
    }
}
pub(crate) struct UdpTransactions {
    hash: RandomState,
    shards: Vec<Mutex<Cache>>,
}
impl UdpTransactions {
    pub(crate) fn new() -> Self {
        Self {
            hash: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(Cache::default())).collect(),
        }
    }
    pub(crate) fn lock(&self, src: SocketAddr) -> MutexGuard<'_, Cache> {
        self.shards[self.hash.hash_one(src) as usize % SHARDS].lock()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_cache_scope_conflict_expiry_and_bound() {
        let mut c = Cache::default();
        let src = "127.0.0.1:1234".parse().unwrap();
        let other = "127.0.0.1:1235".parse().unwrap();
        let now = Instant::now();
        let raw = Bytes::from(vec![0; 20]);
        c.insert(src, raw.clone(), Bytes::from_static(b"reply"), now);
        assert!(matches!(c.lookup(src, &raw), Lookup::Reply(_)));
        assert!(matches!(c.lookup(other, &raw), Lookup::Miss));
        let mut changed = raw.to_vec();
        changed[0] = 1;
        assert!(matches!(c.lookup(src, &changed), Lookup::Conflict));
        c.expire(now + TTL);
        assert!(matches!(c.lookup(src, &raw), Lookup::Miss));
        for i in 0..CAPACITY + 1 {
            let mut r = vec![0; 20];
            r[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            c.insert(src, Bytes::from(r), Bytes::from_static(b"r"), now);
        }
        assert_eq!(c.entries.len(), CAPACITY);
        assert_eq!(c.order.len(), CAPACITY);
        assert!(matches!(c.lookup(src, &raw), Lookup::Miss));
    }
}
