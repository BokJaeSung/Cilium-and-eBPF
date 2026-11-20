#!/usr/bin/python3
# 4.3 꼬리 호출 — 시스템 콜 번호로 프로그램 고르기 (x86-64 번호)
import ctypes as ct
from bcc import BPF

program = r"""
BPF_PROG_ARRAY(syscall, 500);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    int nr = ctx->args[1];
    syscall.call(ctx, nr);
    bpf_trace_printk("Another syscall: %d", nr);
    return 0;
}

int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1] == 222)      bpf_trace_printk("Creating a timer");
    else if (ctx->args[1] == 226) bpf_trace_printk("Deleting a timer");
    else                          bpf_trace_printk("Some other timer operation");
    return 0;
}

int ignore_nr(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_nr", BPF.RAW_TRACEPOINT)
exec_fn   = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn  = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
for nr in range(222, 227):
    prog_array[ct.c_int(nr)] = ct.c_int(timer_fn.fd)
for nr in (21, 22, 25):
    prog_array[ct.c_int(nr)] = ct.c_int(ignore_fn.fd)

print("attached", flush=True)
b.trace_print()
