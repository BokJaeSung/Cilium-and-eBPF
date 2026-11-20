#!/usr/bin/python3
# 3.3 링 버퍼 — 3.4 와 같은 구조체를 CPU 공용 버퍼로
from bcc import BPF

program = r"""
BPF_RINGBUF_OUTPUT(events, 8);              // 8 페이지

struct event_t {
    int  pid;
    int  uid;
    char comm[16];
    char msg[12];
};

int hello(void *ctx) {
    struct event_t e = {};
    char msg[12] = "Hello Ring";

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_kernel(&e.msg, sizeof(e.msg), msg);

    events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="hello")

def on_event(ctx, data, size):
    e = b["events"].event(data)
    print(f"{e.pid} {e.uid} {e.comm.decode()} {e.msg.decode()}", flush=True)

b["events"].open_ring_buffer(on_event)
while True:
    b.ring_buffer_poll()
