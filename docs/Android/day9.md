---
layout: default
title: "Android 보안 9일차"
parent: Android
nav_order: 9
---

모바일 앱 분석 (정적·동적 분석)

## 1. 분석 개요

### 정적 분석

- 앱을 **실행하지 않은 상태**에서 분석
- 문자열, 함수, 로직을 **거꾸로 추적**하며 기능 파악
- 주요 도구
  - jadx
  - ghidra
- Java 코드, Smali 코드 기반 분석

### 동적 분석

- 앱을 **실행한 상태**에서 분석
- 함수 호출 흐름, 리턴값, 변수 확인
- 런타임 변조 및 후킹
- 주요 도구
  - Frida
  - Xposed
  - Burp와 유사한 방식의 런타임 조작

------

## 2. 환경 구축

### 필수 구성 요소

- Python
- adb
- 기기 내 `frida-server`
- PC 내 `frida`, `frida-tools`
- 코드 편집기

------

### PC Frida 설치

```
pip install frida-tools
```

------

### 모바일 기기 Frida Server 설치

- PC에 설치한 Frida 버전과 **동일한 버전** 사용
- GitHub Frida Releases에서 다운로드
- 예시:
  - `frida-server-17.5.2-android-x86_64.xz`

------

### Frida Server 기기 배포 및 실행

```
nox_adb push frida-server /sdcard/
nox_adb shell
cd /sdcard
rm /data/local/tmp
mkdir /data/local/tmp
mv frida-server /data/local/tmp/
cd /data/local/tmp
chmod 777 frida-server
./frida-server &
```

- 모바일 기기에서 Frida 서버 실행
- 기본 포트: `27051`
- PC ↔ 모바일 통신 확인

------

## 3. Frida Tools 정리

### 주요 명령어

| 명령어           | 설명                          |
| ---------------- | ----------------------------- |
| frida            | CLI 기반 Frida 쉘             |
| frida-ps         | 실행 중인 프로세스 목록       |
| frida-trace      | 함수 호출 자동 추적           |
| frida-kill       | 실행 중인 앱 종료             |
| frida-ls-devices | 연결된 기기 목록              |
| frida-discover   | 메모리 어셈블리 분석 (비사용) |

------

### 기본 사용법

```
frida -U 앱이름
frida -U -f 패키지명
frida -U -l 공격스크립트.js -f 패키지명
```

- `-U` : USB 디버깅 기기
- `-f` : 앱 spawn 실행

------

### 실행 중 앱 확인

```
frida-ps -U
frida-ps -Uai
```

- `-ai` : 설치된 앱 + PID 출력
- Frida 서버 동작 여부와는 무관

------

## 4. frida-trace 상세

### 목적

- 함수 호출 흐름을 자동으로 추적
- 정확한 분석 전 **전체 구조 파악용**

------

### 기본 사용법

```
frida-trace -U -i '네이티브함수' -j '자바함수' 앱이름
```

옵션 설명:

- `-i` : 네이티브 함수 포함
- `-j` : Java 함수 포함
- `-x`, `-J` : 제외할 함수 지정
- `-f` : 앱 재실행 (spawn)

------

### 예제

```
frida-trace -U -j "패키지명.MainActivity!*" -f 패키지명
frida-trace -U -j "패키지명.GameView!*" -J "패키지명.GameView!draw" -f 패키지명
```

- `draw()` 함수는 호출이 과도하므로 제외

------

### frida-trace 결과 파일

- 자동 생성 위치:

```
_handlers_/클래스명/메소드.js
```

- 생성된 JS 파일은 **frida로 바로 실행 불가**
- 직접 수정 필요

------

## 5. 함수 Hooking 개념

- 함수 실행 시점에 개입
- 인자 값 확인
- 리턴 값 조작
- 로직 변조 가능

------

## 6. Hooking 코드 자동 생성

- Jadx에서 대상 함수 우클릭
- **Frida Snippet 복사**
- JS 후킹 코드로 바로 사용 가능

------

### Hook 실행 예시

```
frida -U -l test.js -f 패키지명
```

------

## 7. 난독화 및 주의 사항

- 함수 오버로딩 문제
  - `a(a1)`
  - `a(a1, a2)`
  - `a(a1, a2, a3)`
- 클래스/메소드 이름 난독화
  - 예: `llii11`, `a-e`, `f-e`
- 정확한 시그니처 지정 필요

------

## 8. 분석 포인트 정리

- Java 함수 vs Native 함수 구분
- frida-trace 결과 해석 방법
- `-i`, `-j`, `-x`, `-J` 옵션 정확한 사용
- `$액티비티명$메소드명$인자` 구조 이해
