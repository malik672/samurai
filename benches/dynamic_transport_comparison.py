#!/usr/bin/env python3
"""Paired Aya RingBuf versus Mold benchmark for 128-byte pointer captures."""
import argparse, json, os, random, statistics, subprocess, time
from pathlib import Path
from transport_comparison import invoking_user, metadata, run_measured, bootstrap_interval

def build(root, aya, user):
    uid, gid, home, env = user
    subprocess.run([home/".cargo/bin/cargo", "build", "--release", "--example", "dynamic_controlled"], cwd=root, env=env, user=uid, group=gid, check=True)
    subprocess.run(["clang", "-target", "bpfel", "-mcpu=v3", "-O2", "-Wall", "-Wextra", "-Werror", "-I", "examples/bpf", "-DCAPACITY=8192", "-c", "examples/bpf/dynamic_controlled.c", "-o", "target/dynamic-controlled.bpf.o"], cwd=root, env=env, user=uid, group=gid, check=True)
    subprocess.run(["clang", "-target", "bpfel", "-mcpu=v3", "-O2", "-Wall", "-Wextra", "-Werror", "-c", "benches/dynamic_aya.c", "-o", "target/dynamic-aya.bpf.o"], cwd=root, env=env, user=uid, group=gid, check=True)
    subprocess.run([home/".cargo/bin/cargo", "build", "--release", "-p", "aya", "--example", "dynamic_controlled_bench"], cwd=aya, env=env, user=uid, group=gid, check=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--pairs",type=int,default=10); parser.add_argument("--warmups",type=int,default=1)
    parser.add_argument("--calls",type=int,default=100_000); parser.add_argument("--producer-cpus",default="0,1,2,3"); parser.add_argument("--consumer-cpus",default="5,4,6,7")
    parser.add_argument("--shape",choices=("string","bytes","both"),default="both"); args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit("run with sudo")
    root=Path(__file__).resolve().parents[1]; aya=root.parent/"aya"; user=invoking_user(); build(root,aya,user)
    shapes=("string","bytes") if args.shape=="both" else (args.shape,); all_rows=[]
    for shape in shapes:
        commands={
          "aya":[aya/"target/release/examples/dynamic_controlled_bench",shape,root/"target/dynamic-aya.bpf.o",str(args.calls),args.producer_cpus,args.consumer_cpus.split(",")[0]],
          "mold":[root/"target/release/examples/dynamic_controlled",shape,root/"target/dynamic-controlled.bpf.o",str(args.calls),args.producer_cpus,args.consumer_cpus],
        }
        for _ in range(args.warmups):
            for cmd in commands.values(): subprocess.run(list(map(str,cmd)),check=True,stdout=subprocess.DEVNULL)
        rows=[]
        for pair in range(1,args.pairs+1):
            for mode in (("aya","mold") if pair%2 else ("mold","aya")):
                row=run_measured(commands[mode]); row.update(pair=pair,mode=mode,shape=shape); rows.append(row); all_rows.append(row)
                print(f"shape={shape} pair={pair} mode={mode} rate={row['producer_rate']:.0f}/s delivered={row['end_to_end_delivered_rate']:.0f}/s loss={row['loss_pct']:.4f}% task_ms={row['task_clock_ms']:.2f} rss_mib={row['max_rss_kib']/1024:.1f}")
        for metric in ("producer_rate","end_to_end_delivered_rate","task_clock_ms","context_switches","max_rss_kib"):
            pairs={};
            for row in rows:pairs.setdefault(row["pair"],{})[row["mode"]]=row[metric]
            changes=[(p["mold"]/p["aya"]-1)*100 for p in pairs.values()]; lo,hi=bootstrap_interval(changes)
            print(f"shape={shape} metric={metric} mold_change={statistics.mean(changes):+.2f}% bootstrap_95%=[{lo:+.2f}%,{hi:+.2f}%]")
    out=root/"target/dynamic-transport-comparison"/str(time.time_ns());out.mkdir(parents=True)
    (out/"results.json").write_text(json.dumps({"metadata":metadata(user),"args":vars(args),"rows":all_rows},indent=2));print(f"results={out}")
if __name__=="__main__":main()
