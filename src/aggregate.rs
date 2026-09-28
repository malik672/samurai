//! Scheduler profiling reduced into CPU-local BPF map values.

use crate::{
    bpf::{
        map::{LruPerCpuHashMap, PerCpuArrayMap},
        program::TracePoint,
    },
    profile::{SchedulerProfile, TaskStats},
    utils::tracepoint::TracepointResolver,
};
use std::{io, thread, time::Duration};

const TASK_STATS_SIZE: usize = 7 * size_of::<u64>();

pub struct AggregateSchedulerRecorder<'map> {
    program: &'map TracePoint,
    tasks: &'map LruPerCpuHashMap,
    records: &'map PerCpuArrayMap,
}

pub struct AggregateRecording {
    profile: SchedulerProfile,
    kernel_records: u64,
}

impl AggregateRecording {
    pub fn profile(&self) -> &SchedulerProfile {
        &self.profile
    }

    pub fn into_profile(self) -> SchedulerProfile {
        self.profile
    }

    pub fn kernel_records(&self) -> u64 {
        self.kernel_records
    }

    pub fn retained_records(&self) -> u64 {
        self.profile.records()
    }

    pub fn evicted_records(&self) -> u64 {
        self.kernel_records.saturating_sub(self.retained_records())
    }
}

impl<'map> AggregateSchedulerRecorder<'map> {
    pub fn new(
        program: &'map TracePoint,
        tasks: &'map LruPerCpuHashMap,
        records: &'map PerCpuArrayMap,
    ) -> io::Result<Self> {
        if tasks.key_size() != size_of::<u32>() || tasks.value_size() != TASK_STATS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected aggregate task-map ABI",
            ));
        }
        if records.cpu_count() != tasks.cpu_count() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "aggregate maps disagree about CPU count",
            ));
        }
        Ok(Self {
            program,
            tasks,
            records,
        })
    }

    pub fn record(
        self,
        resolver: &TracepointResolver,
        duration: Duration,
    ) -> io::Result<AggregateRecording> {
        if duration.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording duration must be positive",
            ));
        }
        let attachment = self.program.attach(resolver, "sched", "sched_switch")?;
        thread::sleep(duration);
        drop(attachment);

        let cpu_entries = read_task_partitions(self.tasks)?;
        let task_capacity = self.tasks.max_entries();
        let cpu_count = self.tasks.cpu_count();
        let locals = thread::scope(|scope| -> io::Result<Vec<SchedulerProfile>> {
            let workers: Vec<_> = cpu_entries
                .into_iter()
                .enumerate()
                .map(|(cpu, entries)| {
                    scope.spawn(move || -> io::Result<SchedulerProfile> {
                        let mut profile =
                            SchedulerProfile::with_capacity(task_capacity, cpu_count)?;
                        for (pid, stats) in entries {
                            profile.merge_reduced(pid, cpu, stats)?;
                        }
                        Ok(profile)
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .map_err(|_panic| io::Error::other("aggregate worker panicked"))?
                })
                .collect()
        })?;

        let mut profile = SchedulerProfile::with_capacity(task_capacity, cpu_count)?;
        for local in locals {
            profile.merge(local)?;
        }
        let mut records = vec![0; self.records.cpu_count()];
        self.records.read_u64(0, &mut records)?;
        Ok(AggregateRecording {
            profile,
            kernel_records: records.iter().sum(),
        })
    }
}

fn read_task_partitions(map: &LruPerCpuHashMap) -> io::Result<Vec<Vec<(u32, TaskStats)>>> {
    let mut partitions = (0..map.cpu_count()).map(|_| Vec::new()).collect::<Vec<_>>();
    let mut current: Option<Vec<u8>> = None;
    let mut next = vec![0; map.key_size()];
    let mut values = vec![0; map.values_len()];
    while map.next_key(current.as_deref(), &mut next)? {
        map.read(&next, &mut values)?;
        let pid = u32::from_ne_bytes(next.as_slice().try_into().unwrap());
        for (cpu, partition) in partitions.iter_mut().enumerate() {
            let stats = decode_task_stats(map.cpu_value(&values, cpu)?)?;
            if stats != TaskStats::default() {
                partition.push((pid, stats));
            }
        }
        current = Some(next.clone());
    }
    Ok(partitions)
}

fn decode_task_stats(bytes: &[u8]) -> io::Result<TaskStats> {
    if bytes.len() != TASK_STATS_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid aggregate task-stat size",
        ));
    }
    let mut fields = [0u64; 7];
    for (field, bytes) in fields.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *field = u64::from_ne_bytes(*bytes);
    }
    Ok(TaskStats {
        runtime_ns: fields[0],
        measured_timeslices: fields[1],
        max_timeslice_ns: fields[2],
        switches_in: fields[3],
        switches_out: fields[4],
        voluntary_switches: fields[5],
        involuntary_switches: fields[6],
    })
}
