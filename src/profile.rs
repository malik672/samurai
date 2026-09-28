use crate::record::ContextSwitchRecord;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskStats {
    pub runtime_ns: u64,
    pub measured_timeslices: u64,
    pub max_timeslice_ns: u64,
    pub switches_in: u64,
    pub switches_out: u64,
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
}

impl TaskStats {
    pub fn average_timeslice_ns(&self) -> u64 {
        self.runtime_ns
            .checked_div(self.measured_timeslices)
            .unwrap_or(0)
    }

    fn merge(&mut self, other: Self) {
        self.runtime_ns += other.runtime_ns;
        self.measured_timeslices += other.measured_timeslices;
        self.max_timeslice_ns = self.max_timeslice_ns.max(other.max_timeslice_ns);
        self.switches_in += other.switches_in;
        self.switches_out += other.switches_out;
        self.voluntary_switches += other.voluntary_switches;
        self.involuntary_switches += other.involuntary_switches;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuStats {
    pub records: u64,
    pub runtime_ns: u64,
}

pub struct SchedulerProfile {
    tasks: FxHashMap<u32, TaskStats>,
    task_limit: usize,
    cpus: Vec<CpuStats>,
    records: u64,
}

impl SchedulerProfile {
    pub fn with_capacity(task_limit: usize, cpu_count: usize) -> io::Result<Self> {
        if task_limit == 0 || cpu_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "task capacity and CPU count must be positive",
            ));
        }
        let tasks = FxHashMap::with_capacity_and_hasher(task_limit, FxBuildHasher);
        Ok(Self {
            tasks,
            task_limit,
            cpus: vec![CpuStats::default(); cpu_count],
            records: 0,
        })
    }

    pub fn observe(&mut self, event: ContextSwitchRecord) -> io::Result<()> {
        let cpu = self.cpus.get_mut(event.cpu as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "record has invalid CPU ID")
        })?;
        cpu.records += 1;
        cpu.runtime_ns += event.runtime_ns;
        self.records += 1;

        self.ensure_task(event.previous_pid)?;
        let previous = self.tasks.get_mut(&event.previous_pid).unwrap();
        previous.switches_out += 1;
        if event.previous_state == 0 {
            previous.involuntary_switches += 1;
        } else {
            previous.voluntary_switches += 1;
        }
        if event.runtime_ns != 0 {
            previous.runtime_ns += event.runtime_ns;
            previous.measured_timeslices += 1;
            previous.max_timeslice_ns = previous.max_timeslice_ns.max(event.runtime_ns);
        }

        self.ensure_task(event.next_pid)?;
        self.tasks.get_mut(&event.next_pid).unwrap().switches_in += 1;
        Ok(())
    }

    pub fn merge(&mut self, other: Self) -> io::Result<()> {
        if self.cpus.len() != other.cpus.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "profiles have different CPU counts",
            ));
        }
        for (pid, stats) in other.tasks {
            self.ensure_task(pid)?;
            self.tasks.get_mut(&pid).unwrap().merge(stats);
        }
        for (total, local) in self.cpus.iter_mut().zip(other.cpus) {
            total.records += local.records;
            total.runtime_ns += local.runtime_ns;
        }
        self.records += other.records;
        Ok(())
    }

    pub fn merge_reduced(&mut self, pid: u32, cpu: usize, stats: TaskStats) -> io::Result<()> {
        let cpu_stats = self.cpus.get_mut(cpu).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CPU index is outside the profile",
            )
        })?;
        cpu_stats.records += stats.switches_out;
        cpu_stats.runtime_ns += stats.runtime_ns;
        self.records += stats.switches_out;
        self.ensure_task(pid)?;
        self.tasks.get_mut(&pid).unwrap().merge(stats);
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn tasks(&self) -> impl Iterator<Item = (u32, &TaskStats)> {
        self.tasks.iter().map(|(pid, stats)| (*pid, stats))
    }

    pub fn cpus(&self) -> &[CpuStats] {
        &self.cpus
    }

    fn ensure_task(&mut self, pid: u32) -> io::Result<()> {
        if self.tasks.contains_key(&pid) {
            return Ok(());
        }
        if self.tasks.len() == self.task_limit {
            return Err(io::Error::other("scheduler profile task capacity exceeded"));
        }
        self.tasks.insert(pid, TaskStats::default());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_commutative_task_statistics() {
        let mut profile = SchedulerProfile::with_capacity(4, 2).unwrap();
        profile
            .observe(ContextSwitchRecord {
                timestamp_ns: 100,
                runtime_ns: 40,
                previous_pid: 10,
                next_pid: 20,
                cpu: 1,
                previous_state: 0,
            })
            .unwrap();
        let task = profile.tasks().find(|(pid, _)| *pid == 10).unwrap().1;
        assert_eq!(task.runtime_ns, 40);
        assert_eq!(task.involuntary_switches, 1);
        assert_eq!(task.average_timeslice_ns(), 40);
        assert_eq!(profile.cpus()[1].runtime_ns, 40);
    }
}
