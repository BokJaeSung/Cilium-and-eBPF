#!/usr/bin/python3
"""out/*.txt 를 읽어 판정하고 summary.md 를 만든다. 판정 실패가 있으면 종료 코드 1."""
import os
import re
import sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else "out")


def read(name):
    p = out / name
    return p.read_text(errors="replace") if p.exists() else ""


env = read("env.txt")
hello = read("hello.txt")
hmap = read("hello_map.txt")
perf = read("hello_perf.txt")
ring = read("hello_ring.txt")
tail = read("hello_tail_summary.txt")
noroot = read("hello_noroot.txt")

last_map = [l for l in hmap.splitlines() if l.startswith("ID ")]
last_map = last_map[-1] if last_map else ""
uid1001 = re.search(r"ID 1001: (\d+)", last_map)
total = re.search(r"total lines: (\d+)", tail)
write_cnt = re.search(r"(\d+) Another syscall: 1\n", tail)

checks = [
    ("hello", "kprobe 이름이 `__x64_sys_execve`",
     "__x64_sys_execve" in hello),
    ("hello", "`Hello World!` 1줄 이상",
     hello.count("Hello World!") >= 1),
    ("해시 맵", "UID 1001 의 execve 횟수 = 3 (`sudo -u runner true` 3회)",
     bool(uid1001) and uid1001.group(1) == "3"),
    ("해시 맵", "UID 0 항목 존재",
     "ID 0:" in last_map),
    ("perf 버퍼", "`Hello World` 이벤트 수신 + UID 1001 이벤트 포함",
     "Hello World" in perf and " 1001 sudo " in perf),
    ("링 버퍼", "`Hello Ring` 이벤트 수신 + UID 1001 이벤트 포함",
     "Hello Ring" in ring and " 1001 sudo " in ring),
    ("꼬리 호출", "59번 → `Executing a program`",
     "Executing a program" in tail),
    ("꼬리 호출", "222번 → `Creating a timer`",
     "Creating a timer" in tail),
    ("root 없이", "로드 단계에서 거부",
     "Operation not permitted" in noroot or "super-user" in noroot),
]
ok = all(c[2] for c in checks)


def block(text, n=8, pat=None):
    lines = [l for l in text.splitlines() if l.strip() and (pat is None or re.search(pat, l))]
    return "```\n" + "\n".join(lines[:n]) + "\n```\n"


sha = os.environ.get("GITHUB_SHA", "")[:7]
md = []
md.append(f"# ch02 — Programs, Maps and Tail Calls {'✅' if ok else '❌'}\n")
md.append("블로그 글: https://kukie.tech/posts/cilium-ebpf-02/\n")
md.append(f"소스 커밋: `{sha}`\n" if sha else "")
md.append("## 실행 환경\n")
md.append("```\n" + env.strip() + "\n```\n")
md.append("## 판정\n")
md.append("| 실습 | 확인 내용 | 결과 |\n|---|---|---|")
for sec, what, res in checks:
    md.append(f"| {sec} | {what} | {'✅' if res else '❌'} |")
md.append("")
md.append("## 대표 출력\n")
md.append("### hello — trace_pipe\n")
md.append(block(hello, 8))
md.append("이름 칸의 `<...>`: ftrace 는 기록 시 PID 만 저장하고 출력 시 이름을 찾아 붙인다. 금방 끝난 프로세스는 이름 X.\n")
md.append("### 해시 맵 — UID 별 횟수 (2초마다)\n")
md.append(block(hmap, 6, r"^ID "))
md.append("### perf 버퍼 — pid uid comm msg\n")
md.append(block(perf, 9))
md.append("`ls` 실행인데 `bash`: execve 입구 시점에는 이미지 교체 전. `timeout` 4줄: PATH 탐색 중 실패한 execve 도 포착.\n")
md.append("### 링 버퍼\n")
md.append(block(ring, 6))
md.append("### 꼬리 호출 — 요약\n")
md.append(block(tail, 40))
if total and write_cnt:
    pct = 100 * int(write_cnt.group(1)) / int(total.group(1))
    md.append(f"전체 {int(total.group(1)):,}줄 중 `write`(1번) {pct:.0f}% — trace_print 가 쓴 줄이 다시 이벤트가 되는 되먹임.\n")
md.append("### root 없이 실행\n")
md.append(block(noroot, 3, r"bpf:|Exception"))

text = "\n".join(md)
# 러너 내부 프로세스 이름은 남기지 않는다
text = re.sub(r"provjobd\d+", "(러너 에이전트)", text)
(out / "summary.md").write_text(text)
print(text)
sys.exit(0 if ok else 1)
