#!/usr/bin/python3
# 3.2 해시 테이블 맵 — UID 별 execve 횟수
from time import sleep
from bcc import BPF

program = r"""
BPF_HASH(exec_count);

int hello(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 count = 0;
    u64 *p = exec_count.lookup(&uid);
    if (p != 0) {
        count = *p;
    }
    count++;
    exec_count.update(&uid, &count);
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")
print("ready", flush=True)

while True:
    sleep(2)
    print("\t".join(f"ID {k.value}: {v.value}" for k, v in b["exec_count"].items()), flush=True)
