# ch02 — Programs, Maps and Tail Calls

블로그 글: [Cilium & eBPF.02 Programs, Maps and Tail Calls](https://kukie.tech/posts/cilium-ebpf-02/)

글의 코드를 그대로 GitHub Actions 러너에서 실행한 기록입니다. 워크플로: [`.github/workflows/ch02.yml`](../.github/workflows/ch02.yml)

## 실행 환경

```
arch:   x86_64
kernel: 7.0.0-1014-aws
os:     Ubuntu 24.04.5 LTS
bcc:    0.29.1+ds-1ubuntu7
runner uid: 1001
tracefs: /sys/kernel/tracing / debugfs: (마운트 X)
```

- x86-64라서 글의 함수 이름(`__x64_sys_execve`)과 시스템 콜 번호(59, 222–226)가 그대로 맞습니다.
- 러너에는 debugfs가 마운트되어 있지 않고 tracefs(`/sys/kernel/tracing`)만 있습니다.

## 실행 방법

```bash
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
sudo ./run.sh hello.py 4        # <스크립트> <추가 대기 초>
```

`run.sh`는 다음 순서로 실습 하나를 진행합니다.

1. 스크립트를 백그라운드로 띄웁니다.
2. 스크립트가 `ready`를 출력할 때까지 기다립니다. 이 시점에 컴파일·로드·부착이 끝나 있습니다.
3. 아래 명령을 세 번 반복해 execve와 타이머 시스템 콜을 일으킵니다.
   - `ls` (root)
   - `sudo -u runner true` (UID 1001)
   - `timeout 0.2 sleep 1`
4. SIGINT로 스크립트를 끊습니다.

결과는 `out/<스크립트>.txt`에 남습니다.

| 파일 | 글의 절 | 내용 |
|---|---|---|
| `hello.py` | 2.2–2.4 | kprobe + `bpf_trace_printk` |
| `hello_map.py` | 3.2 | UID별 execve 횟수 해시 맵 |
| `hello_ring.py` | 3.3 | 링 버퍼로 구조체 전달 |
| `hello_perf.py` | 3.4 | perf 버퍼로 구조체 전달 |
| `hello_tail.py` | 4.3 | raw tracepoint + 꼬리 호출 |

## 1. hello.py — trace_pipe 출력

```
ready: b'__x64_sys_execve'
b'           <...>-2477    [001] ...31    88.012141: bpf_trace_printk: Hello World!'
b'           <...>-2478    [001] ...31    88.013339: bpf_trace_printk: Hello World!'
b'           <...>-2482    [001] ...31    88.022803: bpf_trace_printk: Hello World!'
b'           <...>-2482    [001] ...31    88.022809: bpf_trace_printk: Hello World!'
b'           <...>-2482    [001] ...31    88.022810: bpf_trace_printk: Hello World!'
b'           <...>-2482    [001] ...31    88.022811: bpf_trace_printk: Hello World!'
b'         timeout-2488    [001] ...31    88.732481: bpf_trace_printk: Hello World!'
```

- `get_syscall_fnname("execve")`는 `__x64_sys_execve`를 돌려줍니다.
- 프로세스 이름 대부분이 `<...>`로 찍힙니다.
  - ftrace는 기록할 때 이름을 저장하지 않습니다. PID만 저장해 두고, 출력할 때 이름 캐시(`saved_cmdlines`)에서 찾아 붙입니다.
  - `ls`나 `true`처럼 금방 끝나는 프로세스는 캐시에 없어서 이름 대신 `<...>`가 나옵니다.
  - 이름은 기록 시점의 값이 아닙니다. 아래 5절에서 `ls`의 execve가 `ls`라는 이름으로 찍히는 것도 출력 시점에 찾은 이름이기 때문입니다.
- PID 하나에 같은 줄이 네 번 찍힌 것은 `timeout`이 `sleep`을 실행할 때 생깁니다. 이 내용은 3절에서 설명합니다.

## 2. hello_map.py — UID별 횟수

```
ID 0: 25	ID 1001: 3
ID 0: 26	ID 1001: 3
ID 0: 26	ID 1001: 3
ID 0: 27	ID 1001: 3
```

- `ID 1001: 3`은 `sudo -u runner true`를 세 번 실행한 결과입니다. UID가 runner로 바뀐 뒤 `true`를 execve했기 때문에 1001로 셉니다.
- 나머지는 모두 root(0)로 셉니다. 대상은 `run.sh`의 명령과 러너 자체의 백그라운드 작업입니다.
- 맵은 2초마다 읽어도 누적값이 그대로 남아 있습니다. trace_pipe와 달리 읽는다고 비워지지 않습니다.

## 3. hello_perf.py — perf 버퍼

```
2545 0 bash Hello World
2546 0 bash Hello World
2547 0 bash Hello World
2548 1001 sudo Hello World
2549 0 bash Hello World
2550 0 timeout Hello World
2550 0 timeout Hello World
2550 0 timeout Hello World
2550 0 timeout Hello World
```

- `bpf_get_current_comm()`은 이벤트가 일어난 순간의 이름을 읽어 구조체에 담습니다. 그래서 `<...>`가 나오지 않습니다.
- `ls`를 실행했는데도 이름이 `bash`로 찍힙니다. kprobe는 execve의 입구에서 실행되는데, 그 시점에는 아직 실행 이미지가 바뀌지 않았기 때문입니다.
  - `sudo -u runner true`의 execve는 `sudo`·UID 1001로 찍힙니다.
- `timeout` 한 번에 같은 PID로 네 줄이 나옵니다.
  - `timeout`은 `execvp("sleep")`으로 PATH의 디렉터리를 하나씩 시도합니다(`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`). 앞의 세 번은 파일이 없어 실패합니다.
  - kprobe는 함수 입구에 붙어 있으므로, 실패한 execve 시도도 모두 이벤트로 잡힙니다.

## 4. hello_ring.py — 링 버퍼

```
2577 0 bash Hello Ring
2578 0 bash Hello Ring
2579 0 bash Hello Ring
2580 1001 sudo Hello Ring
2581 0 bash Hello Ring
2582 0 timeout Hello Ring
```

- perf 버퍼와 같은 구조체를 `BPF_RINGBUF_OUTPUT` / `ringbuf_output()`으로 보냈습니다.
- 출력 내용은 3절과 같습니다. 차이는 구조에 있습니다. CPU마다 버퍼를 두지 않고 버퍼 하나를 함께 쓰므로, 여러 CPU의 이벤트가 일어난 순서대로 섞여 나옵니다.

## 5. hello_tail.py — 꼬리 호출

출력이 260만 줄이라 워크플로에서 요약만 남겼습니다. 요약 파일은 `out/hello_tail_summary.txt`입니다.

```
total lines: 2600417
--- 꼬리 호출된 프로그램이 찍은 줄
b'            bash-2609    [000] ...3.   118.335927: bpf_trace_printk: Executing a program'
b'              ls-2610    [000] ...3.   118.337432: bpf_trace_printk: Executing a program'
b'            true-2612    [000] ...3.   118.346606: bpf_trace_printk: Executing a program'
b'         timeout-2613    [000] ...3.   118.348283: bpf_trace_printk: Executing a program'
b'           sleep-2614    [000] ...3.   118.349053: bpf_trace_printk: Executing a program'
b'         timeout-2613    [000] ...3.   118.349402: bpf_trace_printk: Creating a timer'
b'         timeout-2613    [000] ...3.   118.349405: bpf_trace_printk: Some other timer operation'
--- Another syscall 상위 번호
2513180 Another syscall: 1
  55582 Another syscall: 0
   3095 Another syscall: 24
   1250 Another syscall: 257
--- 기록한 프로세스 상위
2565533 python3
   5041 (러너 에이전트)
   3094 sudo
```

- 59(execve)는 `hello_exec`로 넘어가 `Executing a program`을 찍습니다.
- 222(`timer_create`)는 `Creating a timer`, 223(`timer_settime`)은 `Some other timer operation`을 찍습니다.
  - 226(`timer_delete`)은 보이지 않습니다. `timeout`이 타이머를 지우지 않고 종료하기 때문입니다.
- 꼬리 호출된 줄에는 `Another syscall`이 함께 찍히지 않습니다. 꼬리 호출은 돌아오지 않는다는 뜻입니다.
- 출력의 97%가 python3의 `write`(1번)입니다.
  - 원인은 되먹임입니다. `trace_print()`가 읽은 줄을 파일에 쓰면 → `write` 시스템 콜이 일어나고 → 그것이 다시 `Another syscall: 1`로 기록되고 → 그 줄을 또 씁니다.
  - 무시 목록(21, 22, 25)만으로는 이 되먹임을 막지 못합니다.
  - 실제로 쓰려면 자기 PID를 거르거나 1번(`write`)과 0번(`read`)도 무시 목록에 넣어야 합니다.

## 6. root 없이 실행

```
bpf: Failed to load program: Operation not permitted
...
Exception: Need super-user privileges to run
```

- 일반 사용자(UID 1001)는 프로그램 로드 단계에서 `EPERM`을 받습니다.
- 권한을 주려면 root나 `CAP_BPF` + `CAP_PERFMON`이 필요합니다.
