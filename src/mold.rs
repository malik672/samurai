//! Molded streaming with generation marks.
use crate::bpf::map::MappedArray;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const CONSUMER_MARK_INTERVAL: u64 = 128;

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

#[repr(C)]
struct MappedSlot<const WORDS: usize> {
    mark: AtomicU64,
    kind: u64,
    words: [u64; WORDS],
}

#[repr(C)]
struct MappedFrontier {
    producer_mark: AtomicU64,
    _producer_padding: [u64; 7],
    consumer_mark: AtomicU64,
    _consumer_padding: [u64; 7],
}

/// Validated mmap view of the fixed Mold maps created by a BPF program.
pub struct MappedMold<'map, const WORDS: usize> {
    slots: &'map MappedArray<'map>,
    frontiers: &'map MappedArray<'map>,
    lanes: usize,
    capacity: usize,
}

/// One userspace cursor over one CPU-owned BPF lane.
pub struct MappedMoldWorker<'mold, 'map, const WORDS: usize> {
    mold: &'mold MappedMold<'map, WORDS>,
    lane: usize,
    expected_mark: u64,
    consumed_since_publish: u64,
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

/// A field occupying one or more consecutive words in a Mold schema.
pub trait MoldField: Sized {
    const WORDS: usize;
    fn encode_field(self, output: &mut [u64], offset: &mut usize);
    fn decode_field(input: &[u64], offset: &mut usize) -> Self;
}

impl<Word: MoldWord> MoldField for Word {
    const WORDS: usize = 1;

    #[inline]
    fn encode_field(self, output: &mut [u64], offset: &mut usize) {
        output[*offset] = self.into_mold_word();
        *offset += 1;
    }

    #[inline]
    fn decode_field(input: &[u64], offset: &mut usize) -> Self {
        let value = Self::from_mold_word(input[*offset]);
        *offset += 1;
        value
    }
}

impl<const BYTES: usize> MoldField for [u8; BYTES] {
    const WORDS: usize = BYTES.div_ceil(8);

    #[inline]
    fn encode_field(self, output: &mut [u64], offset: &mut usize) {
        for (index, chunk) in self.chunks(8).enumerate() {
            let mut bytes = [0; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            output[*offset + index] = u64::from_ne_bytes(bytes);
        }
        *offset += Self::WORDS;
    }

    #[inline]
    fn decode_field(input: &[u64], offset: &mut usize) -> Self {
        let mut output = [0; BYTES];
        for (index, chunk) in output.chunks_mut(8).enumerate() {
            let bytes = input[*offset + index].to_ne_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        *offset += Self::WORDS;
        output
    }
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
        const _: () = assert!(
            $words == 0 $(+ <$field_type as $crate::mold::MoldField>::WORDS)+
        );

        impl $crate::mold::MoldRecord<$words> for $record {
            #[inline]
            fn encode(self) -> [u64; $words] {
                let mut output = [0; $words];
                let mut offset = 0;
                $(<$field_type as $crate::mold::MoldField>::encode_field(
                    self.$field,
                    &mut output,
                    &mut offset,
                );)+
                output
            }

            #[inline]
            fn decode(words: [u64; $words]) -> Self {
                let mut offset = 0;
                Self {
                    $($field: <$field_type as $crate::mold::MoldField>::decode_field(
                        &words,
                        &mut offset,
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

impl<'map, const WORDS: usize> MappedMold<'map, WORDS> {
    pub fn new(
        slots: &'map MappedArray<'map>,
        frontiers: &'map MappedArray<'map>,
    ) -> io::Result<Self> {
        if WORDS == 0
            || slots.value_size() != size_of::<MappedSlot<WORDS>>()
            || frontiers.value_size() != size_of::<MappedFrontier>()
            || frontiers.entries() == 0
            || !slots.entries().is_multiple_of(frontiers.entries())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mapped Mold ABI",
            ));
        }
        let capacity = slots.entries() / frontiers.entries();
        if capacity == 0 || !capacity.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mold lane capacity must be a non-zero power of two",
            ));
        }
        Ok(Self {
            slots,
            frontiers,
            lanes: frontiers.entries(),
            capacity,
        })
    }

    pub fn lanes(&self) -> usize {
        self.lanes
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn worker(&self, lane: usize) -> io::Result<MappedMoldWorker<'_, 'map, WORDS>> {
        if lane >= self.lanes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Mold lane index out of range",
            ));
        }
        Ok(MappedMoldWorker {
            mold: self,
            lane,
            expected_mark: 1,
            consumed_since_publish: 0,
        })
    }
}

impl<const WORDS: usize> MappedMoldWorker<'_, '_, WORDS> {
    pub fn try_next(&mut self) -> io::Result<Option<MoldEntry<WORDS>>> {
        let producer_mark = self.frontier()?.producer_mark.load(Ordering::Acquire);
        if self.expected_mark > producer_mark {
            return Ok(None);
        }
        let oldest_mark = producer_mark
            .saturating_sub(self.mold.capacity as u64 - 1)
            .max(1);
        if self.expected_mark < oldest_mark {
            let missed = oldest_mark - self.expected_mark;
            self.expected_mark = oldest_mark;
            self.publish_progress()?;
            return Ok(Some(MoldEntry::Gap(missed)));
        }

        let index = self.lane * self.mold.capacity
            + ((self.expected_mark - 1) & (self.mold.capacity as u64 - 1)) as usize;
        let slot = self
            .mold
            .slots
            .value_ptr(index)?
            .cast::<MappedSlot<WORDS>>();
        let slot = unsafe { slot.as_ref() };
        let first_mark = slot.mark.load(Ordering::Acquire);
        if first_mark != self.expected_mark {
            return Ok(None);
        }
        let words = unsafe { std::ptr::read_volatile(&raw const slot.words) };
        let kind = unsafe { std::ptr::read_volatile(&raw const slot.kind) };
        std::sync::atomic::fence(Ordering::Acquire);
        if slot.mark.load(Ordering::Acquire) != first_mark {
            return Ok(None);
        }

        self.expected_mark += 1;
        self.consumed_since_publish += 1;
        if self.consumed_since_publish == CONSUMER_MARK_INTERVAL {
            self.publish_progress()?;
        }
        match kind {
            DATA => Ok(Some(MoldEntry::Data(words))),
            DONE => Ok(Some(MoldEntry::Done)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mapped Mold entry kind",
            )),
        }
    }

    pub fn try_next_record<Record: MoldRecord<WORDS>>(
        &mut self,
    ) -> io::Result<Option<TypedMoldEntry<Record>>> {
        Ok(self.try_next()?.map(|entry| match entry {
            MoldEntry::Data(words) => TypedMoldEntry::Data(Record::decode(words)),
            MoldEntry::Gap(missed) => TypedMoldEntry::Gap(missed),
            MoldEntry::Done => TypedMoldEntry::Done,
        }))
    }

    pub fn is_caught_up(&self) -> io::Result<bool> {
        Ok(self.expected_mark > self.frontier()?.producer_mark.load(Ordering::Acquire))
    }

    pub fn publish_consumer_mark(&mut self) -> io::Result<()> {
        self.publish_progress()
    }

    fn frontier(&self) -> io::Result<&MappedFrontier> {
        let frontier = self
            .mold
            .frontiers
            .value_ptr(self.lane)?
            .cast::<MappedFrontier>();
        Ok(unsafe { frontier.as_ref() })
    }

    fn publish_progress(&mut self) -> io::Result<()> {
        let consumer_mark = self.expected_mark - 1;
        self.consumed_since_publish = 0;
        self.frontier()?
            .consumer_mark
            .store(consumer_mark, Ordering::Release);
        Ok(())
    }
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

    #[test]
    fn openat_schema_preserves_signed_arguments() {
        use super::MoldRecord;
        let record = crate::record::OpenAtRecord {
            timestamp_ns: 10,
            pid: 20,
            cpu: 3,
            directory_fd: -100,
            flags: i32::MIN,
            mode: 0o640,
            path_len: 8,
            path: {
                let mut path = [0; 64];
                path[..8].copy_from_slice(b"/tmp/log");
                path
            },
        };
        let words = <crate::record::OpenAtRecord as MoldRecord<15>>::encode(record);
        assert_eq!(
            <crate::record::OpenAtRecord as MoldRecord<15>>::decode(words),
            record
        );
        assert_eq!(record.path_bytes(), b"/tmp/log");
    }
}
