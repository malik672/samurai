//! Compiled tracepoint objects, parsed and relocated with aya-obj.
//!
//! Loading sequence adapted from Aya, MIT licensed; see LICENSES/aya-MIT.txt.
//! Source: aya/src/bpf.rs at 15593549d93cd39decf008f6d859fd054ba40bcf.
//!
//! Initial scope: native little-endian ELF and legacy array, per-CPU array,
//! and ring-buffer maps; no BTF, CO-RE, global data, or pinning.
use std::{fs, io, os::fd::AsRawFd, path::Path};

use aya_obj::{EbpfSectionKind, Object, ProgramSection, maps::PinningType};
use rustc_hash::FxHashMap;

use super::{
    map::{ArrayMap, LruPerCpuHashMap, PerCpuArrayMap, RingBufferMap},
    program::TracePoint,
    syscall::{
        BPF_F_MMAPABLE, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF,
    },
};

pub struct ObjectLoader {
    object: Object,
}

pub struct LoadedObject {
    programs: FxHashMap<String, TracePoint>,
    array_maps: FxHashMap<String, ArrayMap>,
    per_cpu_array_maps: FxHashMap<String, PerCpuArrayMap>,
    lru_per_cpu_hash_maps: FxHashMap<String, LruPerCpuHashMap>,
    ring_buffer_maps: FxHashMap<String, RingBufferMap>,
}

impl ObjectLoader {
    /// Parse and validate without creating any kernel objects.
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let object = Object::parse(bytes).map_err(invalid_data)?;
        // The currently supported object target is native little-endian.
        if !cfg!(target_endian = "little") || bytes.get(5) != Some(&1) {
            return Err(unsupported(
                "only native little-endian BPF objects are supported",
            ));
        }
        if object.btf.is_some() || object.btf_ext.is_some() {
            return Err(unsupported(
                "BTF/CO-RE objects are not supported yet; compile without -g",
            ));
        }
        if object.programs.is_empty() {
            return Err(invalid_data("object has no programs"));
        }
        for (name, program) in &object.programs {
            if !matches!(program.section, ProgramSection::TracePoint) {
                return Err(unsupported(format!(
                    "program {name}: only tracepoint programs are supported"
                )));
            }
            if !object.functions.contains_key(&program.function_key()) {
                return Err(invalid_data(format!(
                    "program {name}: missing entry function"
                )));
            }
        }
        for (name, map) in &object.maps {
            let valid_shape = match map.map_type() {
                BPF_MAP_TYPE_ARRAY | BPF_MAP_TYPE_PERCPU_ARRAY => {
                    map.key_size() == 4 && map.value_size() != 0
                }
                BPF_MAP_TYPE_LRU_PERCPU_HASH => map.key_size() != 0 && map.value_size() != 0,
                BPF_MAP_TYPE_RINGBUF => {
                    map.key_size() == 0
                        && map.value_size() == 0
                        && map.max_entries().is_power_of_two()
                }
                _ => false,
            };
            if !matches!(map.section_kind(), EbpfSectionKind::Maps)
                || !valid_shape
                || map.max_entries() == 0
                || (map.map_flags() != 0
                    && !(map.map_type() == BPF_MAP_TYPE_ARRAY && map.map_flags() == BPF_F_MMAPABLE))
                || map.pinning() != PinningType::None
                || !map.data().is_empty()
            {
                return Err(unsupported(format!(
                    "map {name}: unsupported legacy map definition"
                )));
            }
        }
        Ok(Self { object })
    }

    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::parse(&fs::read(path)?)
    }

    pub fn program_names(&self) -> impl Iterator<Item = &str> {
        self.object.programs.keys().map(String::as_str)
    }

    pub fn map_names(&self) -> impl Iterator<Item = &str> {
        self.object.maps.keys().map(String::as_str)
    }

    /// Create maps, relocate and load all programs, then drop parsed data.
    pub fn load(mut self) -> io::Result<LoadedObject> {
        // Like Aya, transfer map definitions into the runtime map objects.
        let mut array_maps = FxHashMap::default();
        let mut per_cpu_array_maps = FxHashMap::default();
        let mut lru_per_cpu_hash_maps = FxHashMap::default();
        let mut ring_buffer_maps = FxHashMap::default();
        for (name, map_obj) in self.object.maps.drain() {
            match map_obj.map_type() {
                BPF_MAP_TYPE_ARRAY => {
                    let map = ArrayMap::create(map_obj)
                        .map_err(|err| context(format!("create map {name}"), err))?;
                    array_maps.insert(name, map);
                }
                BPF_MAP_TYPE_PERCPU_ARRAY => {
                    let map = PerCpuArrayMap::create(map_obj)
                        .map_err(|err| context(format!("create map {name}"), err))?;
                    per_cpu_array_maps.insert(name, map);
                }
                BPF_MAP_TYPE_LRU_PERCPU_HASH => {
                    let map = LruPerCpuHashMap::create(map_obj)
                        .map_err(|err| context(format!("create map {name}"), err))?;
                    lru_per_cpu_hash_maps.insert(name, map);
                }
                BPF_MAP_TYPE_RINGBUF => {
                    let map = RingBufferMap::create(map_obj)
                        .map_err(|err| context(format!("create map {name}"), err))?;
                    ring_buffer_maps.insert(name, map);
                }
                _ => unreachable!("map types were validated during parsing"),
            }
        }
        let sections = self
            .object
            .functions
            .keys()
            .map(|(section, _)| *section)
            .collect();
        self.object
            .relocate_maps(
                array_maps
                    .iter()
                    .map(|(name, map)| (name.as_str(), map.fd().as_raw_fd(), map.obj()))
                    .chain(
                        lru_per_cpu_hash_maps
                            .iter()
                            .map(|(name, map)| (name.as_str(), map.fd().as_raw_fd(), map.obj())),
                    )
                    .chain(
                        per_cpu_array_maps
                            .iter()
                            .map(|(name, map)| (name.as_str(), map.fd().as_raw_fd(), map.obj())),
                    )
                    .chain(
                        ring_buffer_maps
                            .iter()
                            .map(|(name, map)| (name.as_str(), map.fd().as_raw_fd(), map.obj())),
                    ),
                &sections,
            )
            .map_err(invalid_data)?;
        self.object
            .relocate_calls(&sections)
            .map_err(invalid_data)?;

        let programs = load_programs(self.object, TracePoint::load)?;
        Ok(LoadedObject {
            programs,
            array_maps,
            per_cpu_array_maps,
            lru_per_cpu_hash_maps,
            ring_buffer_maps,
        })
    }
}

// The object owns instructions until every synchronous load finishes.
fn load_programs<T>(
    mut object: Object,
    mut load: impl FnMut(&aya_obj::Program, &aya_obj::Function) -> io::Result<T>,
) -> io::Result<FxHashMap<String, T>> {
    object
        .programs
        .drain()
        .map(|(name, program)| {
            let function = object
                .functions
                .get(&program.function_key())
                .ok_or_else(|| invalid_data(format!("program {name}: missing entry function")))?;
            let loaded = load(&program, function)
                .map_err(|err| context(format!("load program {name}"), err))?;
            Ok((name, loaded))
        })
        .collect()
}

impl LoadedObject {
    pub fn map(&self, name: &str) -> Option<&ArrayMap> {
        self.array_maps.get(name)
    }

    pub fn ring_buffer(&self, name: &str) -> Option<&RingBufferMap> {
        self.ring_buffer_maps.get(name)
    }

    pub fn per_cpu_map(&self, name: &str) -> Option<&PerCpuArrayMap> {
        self.per_cpu_array_maps.get(name)
    }

    pub fn lru_per_cpu_hash(&self, name: &str) -> Option<&LruPerCpuHashMap> {
        self.lru_per_cpu_hash_maps.get(name)
    }

    pub fn program(&self, name: &str) -> Option<&TracePoint> {
        self.programs.get(name)
    }
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn context(operation: String, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
    };

    fn compile(name: &str, source: &str, debug: bool) -> Vec<u8> {
        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "object-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join(format!("{name}.c"));
        let output = dir.join(format!("{name}.o"));
        fs::write(&input, source).unwrap();
        let mut command = Command::new("clang");
        command.args(["-target", "bpfel", "-O2", "-c"]);
        if debug {
            command.arg("-g");
        }
        let result = command
            .arg(input)
            .arg("-o")
            .arg(&output)
            .output()
            .expect("object tests require clang with a BPF backend");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let bytes = fs::read(output).unwrap();
        fs::remove_dir_all(dir).unwrap();
        bytes
    }

    fn fixture() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            compile(
                "counter",
                include_str!("../../examples/bpf/counter.c"),
                false,
            )
        })
    }

    #[test]
    fn parses_and_relocates_compiled_counter() {
        let mut loader = ObjectLoader::parse(fixture()).unwrap();
        assert_eq!(
            loader.program_names().collect::<Vec<_>>(),
            ["count_switches"]
        );
        assert_eq!(loader.map_names().collect::<Vec<_>>(), ["switches"]);
        let definitions = loader.object.maps.clone();
        let map = &definitions["switches"];
        assert_eq!(map.map_type(), BPF_MAP_TYPE_PERCPU_ARRAY);
        assert_eq!(
            (map.key_size(), map.value_size(), map.max_entries()),
            (4, 8, 1)
        );
        let key = loader.object.programs["count_switches"].function_key();
        let before = loader.object.functions[&key].instructions.len();
        let sections = loader.object.functions.keys().map(|(s, _)| *s).collect();
        // Relocation only writes FD numbers; no kernel object is needed here.
        loader
            .object
            .relocate_maps(std::iter::once(("switches", 1_000_007, map)), &sections)
            .unwrap();
        loader.object.relocate_calls(&sections).unwrap();
        let instructions = &loader.object.functions[&key].instructions;
        assert!(instructions.len() > before, "BPF subprogram must be linked");
        assert!(
            instructions
                .iter()
                .any(|i| i.code == 0x18 && i.src_reg() == 1 && i.imm == 1_000_007)
        );
    }

    #[test]
    fn parses_ring_buffer_map_fixture() {
        let bytes = compile("record", include_str!("../../examples/bpf/record.c"), false);
        let loader = ObjectLoader::parse(&bytes).unwrap();
        let ring = &loader.object.maps["events"];
        assert_eq!(ring.map_type(), BPF_MAP_TYPE_RINGBUF);
        assert_eq!(ring.key_size(), 0);
        assert_eq!(ring.value_size(), 0);
        assert_eq!(ring.max_entries(), 1 << 20);
    }

    #[test]
    fn aliased_programs_borrow_same_instructions_during_loading() {
        let source = r#"
__attribute__((section("tracepoint/sched/sched_switch"), used))
int first(void *ctx) { return 0; }
extern int second(void *ctx) __attribute__((alias("first")));
__attribute__((section("license"), used)) char license_value[] = "GPL";
"#;
        let bytes = compile("aliases", source, false);
        let mut loader = ObjectLoader::parse(&bytes).unwrap();
        let key = loader.object.programs["first"].function_key();
        assert_eq!(key, loader.object.programs["second"].function_key());
        let sections = loader.object.functions.keys().map(|(s, _)| *s).collect();
        loader.object.relocate_calls(&sections).unwrap();
        let original = loader.object.functions[&key].instructions.as_ptr();
        let mut calls = 0;
        let programs = load_programs(loader.object, |_, function| {
            assert_eq!(function.instructions.as_ptr(), original);
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(programs.len(), 2);
    }

    #[test]
    fn failed_load_drops_previously_loaded_programs() {
        use std::{cell::Cell, rc::Rc};
        struct Loaded(Rc<Cell<usize>>);
        impl Drop for Loaded {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let mut object = ObjectLoader::parse(fixture()).unwrap().object;
        object
            .programs
            .insert("alias".into(), object.programs["count_switches"].clone());
        let dropped = Rc::new(Cell::new(0));
        let mut calls = 0;
        let result = load_programs(object, |_, _| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(Loaded(Rc::clone(&dropped)))
        });
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied));
        assert_eq!(calls, 2);
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    #[ignore = "manual optimized ownership benchmark; see benches/ownership.py"]
    fn benchmark_function_ownership() {
        use std::{
            hint::black_box,
            os::fd::OwnedFd,
            time::{Duration, Instant},
        };
        // Historical comparison, not the current production loader.
        use std::{collections::hash_map::Entry, sync::Arc};
        #[allow(dead_code)]
        struct ArcProgram {
            obj: aya_obj::Program,
            function: Arc<aya_obj::Function>,
            fd: Option<OwnedFd>,
        }
        fn prepare_programs(object: &mut Object) -> io::Result<FxHashMap<String, ArcProgram>> {
            let mut functions = FxHashMap::default();
            object
                .programs
                .drain()
                .map(|(name, program)| {
                    let key = program.function_key();
                    let function = match functions.entry(key) {
                        Entry::Occupied(entry) => Arc::clone(entry.get()),
                        Entry::Vacant(entry) => {
                            let function = object.functions.remove(&key).ok_or_else(|| {
                                invalid_data(format!("program {name}: missing entry function"))
                            })?;
                            Arc::clone(entry.insert(Arc::new(function)))
                        }
                    };
                    Ok((
                        name,
                        ArcProgram {
                            obj: program,
                            function,
                            fd: None,
                        },
                    ))
                })
                .collect()
        }

        // Match the previous wrapper's fields and owned Function representation.
        #[allow(dead_code)]
        struct PreviousProgram {
            obj: aya_obj::Program,
            function: aya_obj::Function,
            fd: Option<OwnedFd>,
        }
        let mode = std::env::var("SAMURAI_OWNERSHIP_MODE").unwrap();
        assert!(matches!(mode.as_str(), "clone" | "arc" | "borrow"));
        fn mock_load(obj: &aya_obj::Program, function: &aya_obj::Function) -> io::Result<u64> {
            black_box(obj.license.as_bytes());
            black_box(function.instructions.as_slice());
            Ok(black_box(1))
        }
        let mut base = ObjectLoader::parse(fixture()).unwrap().object;
        let maps = base.maps.clone();
        let sections = base.functions.keys().map(|(s, _)| *s).collect();
        base.relocate_maps(maps.iter().map(|(n, m)| (n.as_str(), 100, m)), &sections)
            .unwrap();
        base.relocate_calls(&sections).unwrap();
        let program = base.programs["count_switches"].clone();
        let function = base.functions[&program.function_key()].clone();
        for (label, programs, aliases, large) in [
            ("counter", 1, false, false),
            ("32_unique_small", 32, false, false),
            ("32_aliases_small", 32, true, false),
            ("32_unique_large", 32, false, true),
            ("32_aliases_large", 32, true, true),
        ] {
            let mut template = base.clone();
            template.programs.clear();
            template.functions.clear();
            for i in 0..programs {
                let mut p = program.clone();
                if !aliases {
                    p.address = i;
                }
                let mut f = function.clone();
                f.address = p.address;
                if large {
                    f.instructions.resize(4096, f.instructions[0]);
                }
                template.functions.insert(p.function_key(), f);
                template.programs.insert(format!("program_{i}"), p);
            }
            let iterations = 2000;
            let mut elapsed = Duration::ZERO;
            for i in 0..iterations + 200 {
                // All variants include ownership setup, identical mock loads,
                // and teardown. Input cloning alone is outside the timer.
                let mut object = template.clone();
                let start = Instant::now();
                let output: FxHashMap<String, u64> = if mode == "borrow" {
                    load_programs(black_box(object), mock_load).unwrap()
                } else if mode == "arc" {
                    let prepared = black_box(prepare_programs(black_box(&mut object)).unwrap());
                    let output = prepared
                        .into_iter()
                        .map(|(name, p)| (name, mock_load(&p.obj, &p.function).unwrap()))
                        .collect();
                    drop(object);
                    output
                } else {
                    let prepared: FxHashMap<_, _> = object
                        .programs
                        .drain()
                        .map(|(name, obj)| {
                            let function = object.functions[&obj.function_key()].clone();
                            (
                                name,
                                PreviousProgram {
                                    obj,
                                    function,
                                    fd: None,
                                },
                            )
                        })
                        .collect();
                    let prepared = black_box(prepared);
                    let output = prepared
                        .into_iter()
                        .map(|(name, p)| (name, mock_load(&p.obj, &p.function).unwrap()))
                        .collect();
                    drop(object);
                    output
                };
                assert_eq!(black_box(&output).len(), programs as usize);
                drop(output);
                if i >= 200 {
                    elapsed += start.elapsed();
                }
            }

            println!(
                "OWNERSHIP {label} {mode} {:.3}",
                elapsed.as_nanos() as f64 / iterations as f64
            );
        }
    }

    #[test]
    fn rejects_invalid_and_unsupported_objects_before_loading() {
        assert!(
            matches!(ObjectLoader::parse(b"not an ELF"), Err(e) if e.kind() == io::ErrorKind::InvalidData)
        );
        let source = include_str!("../../examples/bpf/counter.c");
        let socket = compile(
            "socket",
            &source.replace("tracepoint/sched/sched_switch", "socket"),
            false,
        );
        assert!(
            matches!(ObjectLoader::parse(&socket), Err(e) if e.kind() == io::ErrorKind::Unsupported)
        );
        let hash = compile(
            "hash",
            &source.replace("switches = {6,", "switches = {1,"),
            false,
        );
        assert!(
            matches!(ObjectLoader::parse(&hash), Err(e) if e.kind() == io::ErrorKind::Unsupported)
        );
        let btf = compile("btf", source, true);
        assert!(
            matches!(ObjectLoader::parse(&btf), Err(e) if e.kind() == io::ErrorKind::Unsupported)
        );
    }
}
