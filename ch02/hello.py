#!/usr/bin/python3
# 2.1 Hello World — execve 마다 trace_pipe 에 한 줄
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)                           # 컴파일 + 커널에 로드
syscall = b.get_syscall_fnname("execve")        # 아키텍처별 커널 함수 이름
print("attach:", syscall, flush=True)
b.attach_kprobe(event=syscall, fn_name="hello") # 이벤트에 붙인다
b.trace_print()                                 # 출력을 계속 읽는다
