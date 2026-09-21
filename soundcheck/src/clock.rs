//! Hybrid logical clock: [`Hlc`] and [`HlcClock`], persisted through storage so
//! a restart never moves it backwards.
//!
//! Every function that depends on physical time takes it as a parameter, so
//! tests control it. The engine passes [`physical_now_ms`].

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The most a remote clock value may run ahead of local physical time before
/// it is rejected (CON-5, section 7 check 5).
pub const MAX_DRIFT_MS: u64 = 5 * 60 * 1000;

/// A hybrid logical clock value.
///
/// Field order matters: the derived `Ord` compares `wall_ms` first and then
/// `counter`, which is the ordering the conflict rules depend on.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Hlc {
    /// Wall-clock milliseconds since the Unix epoch, as seen by this clock.
    pub wall_ms: u64,
    /// Disambiguates events that share `wall_ms`.
    pub counter: u32,
}

impl Hlc {
    /// Construct a value directly. Mostly for tests and fixtures.
    pub const fn new(wall_ms: u64, counter: u32) -> Self {
        Hlc { wall_ms, counter }
    }

    /// Fixed 12-byte encoding: `wall_ms` LE, then `counter` LE. Used wherever
    /// an `Hlc` is hashed or signed.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..8].copy_from_slice(&self.wall_ms.to_le_bytes());
        out[8..].copy_from_slice(&self.counter.to_le_bytes());
        out
    }
}

/// Errors from [`HlcClock::observe`].
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    /// The remote value is more than [`MAX_DRIFT_MS`] ahead of physical time.
    #[error(
        "remote clock {remote_wall_ms} ms is too far ahead of local time {physical_now_ms} ms"
    )]
    TooFarAhead {
        /// The rejected remote wall time.
        remote_wall_ms: u64,
        /// Local physical time at the check.
        physical_now_ms: u64,
    },
}

/// The clock state of one node. Callers persist [`HlcClock::last`] through
/// storage and restore it with [`HlcClock::new`] so a restart never moves the
/// clock backwards.
#[derive(Debug, Clone)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    /// Start from a persisted value (or `Hlc::default()` for a fresh node).
    pub fn new(last: Hlc) -> Self {
        HlcClock { last }
    }

    /// The most recent value handed out or observed.
    pub fn last(&self) -> Hlc {
        self.last
    }

    /// A value for a local event or send. Strictly greater than every value
    /// this clock has handed out or observed before, even if `physical_now_ms`
    /// stalls or steps backwards.
    pub fn now(&mut self, physical_now_ms: u64) -> Hlc {
        let wall = physical_now_ms.max(self.last.wall_ms);
        let next = if wall == self.last.wall_ms {
            bump(self.last)
        } else {
            Hlc::new(wall, 0)
        };
        self.last = next;
        next
    }

    /// Fold a remote value into the clock. Rejects values more than
    /// [`MAX_DRIFT_MS`] ahead of `physical_now_ms`. After a successful
    /// observation, the next [`HlcClock::now`] is greater than `remote`.
    pub fn observe(&mut self, remote: Hlc, physical_now_ms: u64) -> Result<Hlc, ClockError> {
        if remote.wall_ms > physical_now_ms.saturating_add(MAX_DRIFT_MS) {
            return Err(ClockError::TooFarAhead {
                remote_wall_ms: remote.wall_ms,
                physical_now_ms,
            });
        }
        let wall = physical_now_ms.max(self.last.wall_ms).max(remote.wall_ms);
        let mut counter: Option<u32> = None;
        if self.last.wall_ms == wall {
            counter = Some(self.last.counter);
        }
        if remote.wall_ms == wall {
            counter = Some(counter.map_or(remote.counter, |c| c.max(remote.counter)));
        }
        let next = match counter {
            Some(c) => bump(Hlc::new(wall, c)),
            None => Hlc::new(wall, 0),
        };
        self.last = next;
        Ok(next)
    }
}

/// The next value after `v` at the same wall time, rolling into the next
/// millisecond if the counter is exhausted so ordering stays strict.
fn bump(v: Hlc) -> Hlc {
    match v.counter.checked_add(1) {
        Some(c) => Hlc::new(v.wall_ms, c),
        None => Hlc::new(v.wall_ms.saturating_add(1), 0),
    }
}

/// Seconds since the Unix epoch from the system clock, for token validity
/// checks. Returns 0 if the system clock is before the epoch.
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch from the system clock. Returns 0 if the
/// system clock is before the epoch.
pub fn physical_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_strictly_increasing_with_stalled_clock() {
        let mut c = HlcClock::new(Hlc::default());
        let mut prev = c.now(1_000);
        for _ in 0..100 {
            let v = c.now(1_000);
            assert!(v > prev, "{v:?} must exceed {prev:?}");
            prev = v;
        }
        assert_eq!(prev, Hlc::new(1_000, 100));
    }

    #[test]
    fn now_is_strictly_increasing_when_physical_clock_steps_back() {
        let mut c = HlcClock::new(Hlc::default());
        let a = c.now(5_000);
        let b = c.now(4_000);
        let d = c.now(1);
        assert!(b > a);
        assert!(d > b);
        assert_eq!(b.wall_ms, 5_000);
        assert_eq!(d, Hlc::new(5_000, 2));
    }

    #[test]
    fn now_moves_to_physical_time_and_resets_counter() {
        let mut c = HlcClock::new(Hlc::new(1_000, 7));
        assert_eq!(c.now(2_000), Hlc::new(2_000, 0));
    }

    #[test]
    fn observe_rejects_more_than_five_minutes_ahead() {
        let mut c = HlcClock::new(Hlc::default());
        let now = 1_000_000;
        let ok = Hlc::new(now + MAX_DRIFT_MS, 0);
        assert!(c.observe(ok, now).is_ok());
        let bad = Hlc::new(now + MAX_DRIFT_MS + 1, 0);
        assert_eq!(
            c.observe(bad, now),
            Err(ClockError::TooFarAhead {
                remote_wall_ms: now + MAX_DRIFT_MS + 1,
                physical_now_ms: now
            })
        );
        // A rejected observation leaves the clock untouched.
        assert_eq!(c.last(), Hlc::new(now + MAX_DRIFT_MS, 1));
    }

    #[test]
    fn after_observe_next_now_is_greater_than_remote() {
        let cases = [
            // (last, remote, physical)
            (Hlc::new(10, 0), Hlc::new(50, 3), 20),
            (Hlc::new(50, 9), Hlc::new(50, 3), 20),
            (Hlc::new(50, 1), Hlc::new(50, 3), 20),
            (Hlc::new(10, 0), Hlc::new(20, 4), 20),
            (Hlc::new(10, 0), Hlc::new(5, 4), 20),
            (Hlc::new(30, 2), Hlc::new(5, 4), 20),
        ];
        for (last, remote, physical) in cases {
            let mut c = HlcClock::new(last);
            let observed = c.observe(remote, physical).unwrap();
            assert!(observed > remote, "{observed:?} > {remote:?}");
            assert!(observed > last, "{observed:?} > {last:?}");
            let next = c.now(physical);
            assert!(next > remote, "{next:?} > {remote:?} (last {last:?})");
            assert!(next > observed);
        }
    }

    #[test]
    fn observe_counter_rules() {
        // Only physical time supplies the wall: counter resets to 0.
        let mut c = HlcClock::new(Hlc::new(10, 5));
        assert_eq!(c.observe(Hlc::new(20, 7), 100).unwrap(), Hlc::new(100, 0));
        // Remote alone supplies the wall: its counter + 1.
        let mut c = HlcClock::new(Hlc::new(10, 5));
        assert_eq!(c.observe(Hlc::new(200, 7), 100).unwrap(), Hlc::new(200, 8));
        // Last and remote share the wall: max counter + 1.
        let mut c = HlcClock::new(Hlc::new(200, 9));
        assert_eq!(c.observe(Hlc::new(200, 7), 100).unwrap(), Hlc::new(200, 10));
        let mut c = HlcClock::new(Hlc::new(200, 2));
        assert_eq!(c.observe(Hlc::new(200, 7), 100).unwrap(), Hlc::new(200, 8));
    }

    #[test]
    fn ordering_compares_wall_before_counter() {
        assert!(Hlc::new(2, 0) > Hlc::new(1, u32::MAX));
        assert!(Hlc::new(1, 1) > Hlc::new(1, 0));
        assert_eq!(
            Hlc::new(1, 1).cmp(&Hlc::new(1, 1)),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn counter_exhaustion_rolls_into_next_millisecond() {
        let mut c = HlcClock::new(Hlc::new(7, u32::MAX));
        assert_eq!(c.now(7), Hlc::new(8, 0));
    }

    #[test]
    fn to_bytes_is_fixed_little_endian() {
        let b = Hlc::new(0x0102, 0x0304).to_bytes();
        assert_eq!(b, [2, 1, 0, 0, 0, 0, 0, 0, 4, 3, 0, 0]);
    }
}
