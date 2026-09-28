//! Molded streaming with generation marks.
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const WRITING: u64 = 1 << 63;
const DATA: u64 = 0;
const DONE: u64 = 1;

#[repr(C, align(128))]
struct MarkedSlot<const WORDS: usize> {
    mark: AtomicU64,
    kind: AtomicU64,
    words: [AtomicU64; WORDS],
}

#[repr(C, align(128))]
struct ProducerMark(AtomicU64);

struct Lane<const WORDS: usize> {
    slots: Box<[MarkedSlot<WORDS>]>,
    producer_mark: ProducerMark,
    mask: u64,
}

pub struct MoldProducer<const WORDS: usize> {
    lane: Arc<Lane<WORDS>>,
    next_mark: u64,
    done: bool,
}

pub struct MoldWorker<const WORDS: usize> {
    lane: Arc<Lane<WORDS>>,
    expected_mark: u64,
    done: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MoldEntry<const WORDS: usize> {
    Data([u64; WORDS]),
    Gap(u64),
    Done,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TypedMoldEntry<Record> {
    Data(Record),
    Gap(u64),
    Done,
}

/// A fixed record layout known by both the producer and consumer.
pub trait MoldRecord<const WORDS: usize>: Sized {
    fn encode(self) -> [u64; WORDS];
    fn decode(words: [u64; WORDS]) -> Self;
}

/// A scalar that occupies one word in a Mold record.
pub trait MoldWord: Sized {
    fn into_mold_word(self) -> u64;
    fn from_mold_word(word: u64) -> Self;
}

macro_rules! mold_words {
    ($($type:ty),+ $(,)?) => {$ (
        impl MoldWord for $type {
            #[inline]
            fn into_mold_word(self) -> u64 { self as u64 }

            #[inline]
            fn from_mold_word(word: u64) -> Self { word as Self }
        }
    )+ };
}

mold_words!(u8, u16, u32, u64, i8, i16, i32, i64);

/// Define the word-level ABI for a fixed-size record.
///
/// Field order is the ABI shared with the BPF producer.
#[macro_export]
macro_rules! mold_record {
    ($record:ty, $words:literal { $($field:ident : $field_type:ty),+ $(,)? }) => {
        impl $crate::mold::MoldRecord<$words> for $record {
            #[inline]
            fn encode(self) -> [u64; $words] {
                [$(
                    <$field_type as $crate::mold::MoldWord>::into_mold_word(self.$field)
                ),+]
            }

            #[inline]
            fn decode(words: [u64; $words]) -> Self {
                let mut words = words.into_iter();
                Self {
                    $($field: <$field_type as $crate::mold::MoldWord>::from_mold_word(
                        words.next().expect("Mold schema word count must match its fields"),
                    )),+
                }
            }
        }
    };
}

/// Allocate the complete lane before recording starts.
pub fn marked_mold<const WORDS: usize>(
    capacity: usize,
) -> std::io::Result<(MoldProducer<WORDS>, MoldWorker<WORDS>)> {
    if WORDS == 0 || capacity == 0 || !capacity.is_power_of_two() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mold requires records and a non-zero power-of-two capacity",
        ));
    }
    let slots = (0..capacity)
        .map(|_| MarkedSlot {
            mark: AtomicU64::new(0),
            kind: AtomicU64::new(DATA),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let lane = Arc::new(Lane {
        slots,
        producer_mark: ProducerMark(AtomicU64::new(0)),
        mask: capacity as u64 - 1,
    });
    Ok((
        MoldProducer {
            lane: Arc::clone(&lane),
            next_mark: 1,
            done: false,
        },
        MoldWorker {
            lane,
            expected_mark: 1,
            done: false,
        },
    ))
}

impl<const WORDS: usize> MoldProducer<WORDS> {
    pub fn produce(&mut self, words: [u64; WORDS]) -> bool {
        if self.done {
            return false;
        }
        self.publish(DATA, words);
        true
    }

    #[inline]
    pub fn produce_record<Record: MoldRecord<WORDS>>(&mut self, record: Record) -> bool {
        self.produce(record.encode())
    }

    pub fn finish(&mut self) {
        if !self.done {
            self.publish(DONE, [0; WORDS]);
            self.done = true;
        }
    }

    fn publish(&mut self, kind: u64, words: [u64; WORDS]) {
        assert!(self.next_mark < WRITING, "generation mark exhausted");
        let slot = &self.lane.slots[((self.next_mark - 1) & self.lane.mask) as usize];
        // Snapshot invariant:
        //
        // `mark` validates this slot; `producer_mark` only describes progress
        // and the retention frontier. A worker accepts an object only when its
        // mark equals the expected generation before and after reading it.
        //
        // The committed Release store below exposes a completed payload to the
        // first mark Acquire. During overwrite, observing any new payload
        // Release through an Acquire makes this earlier WRITING store happen-
        // before the final mark load. Atomic coherence then prevents that load
        // from observing the older committed mark, rejecting a mixed snapshot.
        slot.mark.store(WRITING | self.next_mark, Ordering::Relaxed);
        for (destination, word) in slot.words.iter().zip(words) {
            destination.store(word, Ordering::Release);
        }
        slot.kind.store(kind, Ordering::Release);
        slot.mark.store(self.next_mark, Ordering::Release);
        self.lane
            .producer_mark
            .0
            .store(self.next_mark, Ordering::Release);
        self.next_mark += 1;
    }
}

impl<const WORDS: usize> MoldWorker<WORDS> {
    pub fn try_next(&mut self) -> Option<MoldEntry<WORDS>> {
        if self.done {
            return None;
        }
        let producer_mark = self.lane.producer_mark.0.load(Ordering::Acquire);
        if self.expected_mark > producer_mark {
            return None;
        }

        let capacity = self.lane.slots.len() as u64;
        let oldest_mark = producer_mark.saturating_sub(capacity - 1).max(1);
        if self.expected_mark < oldest_mark {
            let missed = oldest_mark - self.expected_mark;
            self.expected_mark = oldest_mark;
            return Some(MoldEntry::Gap(missed));
        }

        let slot = &self.lane.slots[((self.expected_mark - 1) & self.lane.mask) as usize];
        let first_mark = slot.mark.load(Ordering::Acquire);
        if first_mark != self.expected_mark {
            return None;
        }
        let words = std::array::from_fn(|index| slot.words[index].load(Ordering::Acquire));
        let kind = slot.kind.load(Ordering::Acquire);
        if slot.mark.load(Ordering::Acquire) != first_mark {
            return None;
        }

        self.expected_mark += 1;
        match kind {
            DATA => Some(MoldEntry::Data(words)),
            DONE => {
                self.done = true;
                Some(MoldEntry::Done)
            }
            _ => unreachable!("invalid mold entry kind"),
        }
    }

    #[inline]
    pub fn try_next_record<Record: MoldRecord<WORDS>>(&mut self) -> Option<TypedMoldEntry<Record>> {
        self.try_next().map(|entry| match entry {
            MoldEntry::Data(words) => TypedMoldEntry::Data(Record::decode(words)),
            MoldEntry::Gap(missed) => TypedMoldEntry::Gap(missed),
            MoldEntry::Done => TypedMoldEntry::Done,
        })
    }

    pub fn is_done(&self) -> bool {
        self.done
    }
}

pub const CONTEXT_SWITCH_WORDS: usize = 6;
pub type ContextSwitchProducer = MoldProducer<CONTEXT_SWITCH_WORDS>;
pub type ContextSwitchWorker = MoldWorker<CONTEXT_SWITCH_WORDS>;

pub fn encode_context_switch(
    record: crate::record::ContextSwitchRecord,
) -> [u64; CONTEXT_SWITCH_WORDS] {
    <crate::record::ContextSwitchRecord as MoldRecord<CONTEXT_SWITCH_WORDS>>::encode(record)
}

pub fn decode_context_switch(
    words: [u64; CONTEXT_SWITCH_WORDS],
) -> crate::record::ContextSwitchRecord {
    <crate::record::ContextSwitchRecord as MoldRecord<CONTEXT_SWITCH_WORDS>>::decode(words)
}

#[cfg(test)]
mod tests {
    use super::{MoldEntry, TypedMoldEntry, marked_mold};

    #[test]
    fn worker_follows_marks_and_done() {
        let (mut producer, mut worker) = marked_mold::<1>(4).unwrap();
        producer.produce([1]);
        producer.produce([2]);
        producer.finish();
        assert_eq!(worker.try_next(), Some(MoldEntry::Data([1])));
        assert_eq!(worker.try_next(), Some(MoldEntry::Data([2])));
        assert_eq!(worker.try_next(), Some(MoldEntry::Done));
    }

    #[test]
    fn worker_seeks_forward_by_the_exact_gap() {
        let (mut producer, mut worker) = marked_mold::<1>(4).unwrap();
        for value in 1..=6 {
            producer.produce([value]);
        }
        producer.finish();
        assert_eq!(worker.try_next(), Some(MoldEntry::Gap(3)));
        for value in 4..=6 {
            assert_eq!(worker.try_next(), Some(MoldEntry::Data([value])));
        }
        assert_eq!(worker.try_next(), Some(MoldEntry::Done));
    }

    #[test]
    fn concurrent_marks_never_accept_a_torn_object() {
        const OBJECTS: u64 = 500_000;
        let (mut producer, mut worker) = marked_mold::<6>(64).unwrap();
        let producer = std::thread::spawn(move || {
            for mark in 1..=OBJECTS {
                producer.produce([mark; 6]);
            }
            producer.finish();
        });
        let (mut delivered, mut missed) = (0, 0);
        loop {
            match worker.try_next() {
                Some(MoldEntry::Data(words)) => {
                    assert!(words.iter().all(|word| *word == words[0]));
                    delivered += 1;
                }
                Some(MoldEntry::Gap(gap)) => missed += gap,
                Some(MoldEntry::Done) => break,
                None => std::hint::spin_loop(),
            }
        }
        producer.join().unwrap();
        assert_eq!(delivered + missed, OBJECTS);
    }

    #[test]
    fn validates_shape_and_context_switch_layout() {
        assert!(marked_mold::<0>(4).is_err());
        assert!(marked_mold::<1>(3).is_err());
        assert_eq!(std::mem::align_of::<super::MarkedSlot<6>>(), 128);
        assert_eq!(std::mem::size_of::<super::MarkedSlot<6>>(), 128);
    }

    #[test]
    fn typed_schema_round_trips_without_allocation() {
        let record = crate::record::ContextSwitchRecord {
            timestamp_ns: 1,
            runtime_ns: 2,
            previous_pid: 3,
            next_pid: 4,
            cpu: 5,
            previous_state: -6,
        };
        let (mut producer, mut worker) = marked_mold::<6>(4).unwrap();
        assert!(producer.produce_record(record));
        producer.finish();
        assert_eq!(worker.try_next_record(), Some(TypedMoldEntry::Data(record)));
        assert_eq!(
            worker.try_next_record::<crate::record::ContextSwitchRecord>(),
            Some(TypedMoldEntry::Done)
        );
    }
}
