#!/usr/bin/env bash
# 실습 하나 실행: ./run.sh <script> <seconds>
# 스크립트를 띄워 두고, 그 사이에 execve·타이머를 일으킨 뒤 SIGINT 로 끊는다.
set -u
script=$1; secs=${2:-8}
out="out/${script%.py}.txt"
mkdir -p out
echo > /sys/kernel/tracing/trace 2>/dev/null || true   # 이전 실습 기록 비우기
python3 -u "$script" >"$out" 2>&1 &
pid=$!
for _ in $(seq 120); do grep -q "^ready" "$out" && break; sleep 0.5; done   # 컴파일·로드·부착 대기
for i in 1 2 3; do
  ls / >/dev/null                                       # execve (runner 사용자)
  sudo -u runner true 2>/dev/null || true
  timeout 0.2 sleep 1 || true                           # timer_create / timer_delete
  sleep 0.5
done
sleep "$secs"
kill -INT "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
echo "== $out ($(wc -l <"$out") lines)"
