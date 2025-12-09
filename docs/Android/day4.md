---
layout: default
title: "Android 보안 4일차"
parent: Android
nav_order: 4
---

# 📱 Android 기본 컴포넌트 & 취약점 개념 정리 (MD 버전)

## 🔷 Android 주요 컴포넌트(Component)

| 컴포넌트              | 설명                                                        |
| --------------------- | ----------------------------------------------------------- |
| **Activity**          | 화면(UI)을 구성하는 요소. 액티비티는 사용자 인터페이스 단위 |
| **Service**           | 화면 없이 백그라운드에서 실행되는 컴포넌트                  |
| **Content Provider**  | 앱 간 데이터를 공유/조회하기 위한 데이터 제공자             |
| **BroadcastReceiver** | 시스템/앱 이벤트를 받아서 동작하는 이벤트 핸들러            |

------

## 🔷 AndroidManifest.xml

Android 앱의 전체 구성 정보를 담고 있는 파일.

- 앱 이름, 퍼미션, Activity/Service/Receiver 선언
- 외부 공개 여부(`exported=true/false`)
- Intent filter 설정 등

------

# 📂 Android 데이터 저장 위치

## 📌 앱 내부 데이터 (private)

```
/data/data/<패키지명>/
```

예:

- shared_prefs
- files
- databases
- cache

→ **root / adb shell 권한** 있어야 접근 가능

------

## 📌 사용자 저장소 (sdcard)

```
/sdcard/
```

대표 경로

- `/DCIM` : 사진
- `/Download` : 다운로드 파일
- `/Documents` : 문서

→ **앱 권한이 있어야 접근 가능 (READ_EXTERNAL_STORAGE 등)**

------

# 🚀 Activity 강제 실행 (ADB 명령)

### ✔ 기본 Activity 실행

```
am start 패키지명/패키지명.액티비티명
```

예시:

```
am start kr.co.eqst.aos.app000/.MainActivity
```

### ✔ Extra 데이터 전달 (Intent 파라미터)

- `--es` : 문자열
- `--ei` : 정수
- `--ez` : boolean

예:

```
am start --es role admin --ei level 9 --ez admin true kr.co.eqst.aos.app019/.AdminActivity
```

------

# 🔐 Activity 내부 Extra 처리

```
getIntent().hasExtra("key")
getIntent().getStringExtra("password")
```

예시:

```
--es password 0810
```

------

# 📡 Content Provider

Content Provider는 다른 앱이 데이터를 **조회/삽입/삭제/업데이트**할 수 있는 인터페이스.

### ✔ Content Provider 호출

```
content query --uri content://패키지명/경로
```

### ✔ SQL 인젝션 취약 Content Provider 예시 구조

```
SELECT id, owner, memo
FROM memos
WHERE owner != 'admin'
  AND ( <selection> )
ORDER BY <sortOrder>
```

### → 공격 포인트

`selection`, `sortOrder` 자리에 인젝션 가능

------

# 📦 AndroGoat / DIVA Android

OWASP 기반의 안드로이드 취약점 학습 앱

📚 주요 취약점:

- Unprotected Android Components
- Insecure Data Storage
- Hardcoded Issues
- Intent Injection
- Content Provider Injection
- Backup/Exported Components

------

# 🛰 Activity 찾기 & 앱 내부 흐름

### ✔ 현재 실행 중인 Activity 확인

```
dumpsys activity activities
```

출력에서:

```
mResumedActivity <--- 현재 화면(Activity)
```

### ✔ 앱 실행 흐름 예시

SplashActivity → finish() → MainActivity

------

# 🔔 BroadcastReceiver 강제 실행

```
am broadcast -a <ACTION> -n <패키지명/.리시버명> -e <KEY> <VALUE>
```

예시:

```
am broadcast -a android.intent.action.BOOT_COMPLETED -n com.test/.BootReceiver
```

------

# 🛠 Service 강제 실행

```
am start-service 패키지명/.서비스명
```

------

# 🔗 URL Scheme / DeepLink

앱을 직접 실행시키는 링크 형태

### 예:

```
am start -a android.intent.action.VIEW -d androgoat://vulnapp
```

웹에서 `androgoat://vulnapp` 링크를 클릭하면 앱이 실행될 수 있음.

### 예: 은행앱 이체 DeepLink

```
bank://transfer?account=123-456-7890&amount=50000
```

------

# ⚠ Unprotected Android Components 취약점

다음 조건에서 취약해짐:

### 🔥 Activity exported=true

→ PIN 없이 바로 내부 화면 실행 가능

### 🔥 Download 기능 Activity 직접 실행

→ 파일 임의 다운로드

### 🔥 DeepLink로 민감 기능 실행

→ (로그인 우회, 특정 기능 동작)

------

# 🧬 Component Attack Summary

| 공격 대상             | 방법                                         |
| --------------------- | -------------------------------------------- |
| **Activity**          | `am start` 로 강제 실행 (Extra 조작 포함)    |
| **Service**           | `am start-service` 로 실행                   |
| **BroadcastReceiver** | `am broadcast -a ACTION` 로 이벤트 강제 전달 |
| **Content Provider**  | `content query --uri` 로 데이터 조작/조회    |

------

# ⚙️ Useful ADB Commands

```
am start -n 패키지명/.메인액티비티
am start -a ACTION -d DATA
am start-service 패키지명/.서비스명
am broadcast -a ACTION -n 패키지명/.리시버명
content query --uri content://패키지명/테이블
dumpsys activity activities
```

------

# ✨ 요약

- **Activity** → 화면 + Intent Extra로 파라미터 조작
- **Service** → 백그라운드 실행
- **ContentProvider** → SQL 인젝션 취약 가능
- **BroadcastReceiver** → 이벤트 강제 트리거 가능
- **DeepLink** → 로그인 우회/기능 실행 위험
- **Manifest** → exported 설정 여부가 보안 핵심
- **adb am/content/broadcast** → 실습 시 반드시 익혀야 하는 명령어