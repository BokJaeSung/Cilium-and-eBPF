#!/usr/bin/python3
# 3.4 perf 버퍼로 구조체 보내기
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(events);

struct event_t {
    int  pid;
    int  uid;
    char comm[16];
    char msg[12];
};

int hello(void *ctx) {
    struct event_t e = {};
    char msg[12] = "Hello World";

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_kernel(&e.msg, sizeof(e.msg), msg);

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")

def on_event(cpu, data, size):
    e = b["events"].event(data)
    print(f"{e.pid} {e.uid} {e.comm.decode()} {e.msg.decode()}", flush=True)

b["events"].open_perf_buffer(on_event)
while True:
    b.perf_buffer_poll()
