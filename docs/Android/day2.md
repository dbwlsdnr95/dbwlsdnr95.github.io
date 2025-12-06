---
layout: default
title: "Android 보안 2일차"
parent: Android
nav_order: 2
---



## 1. SQL Injection — Oracle 문제 정리

### 🔸 Oracle 8번 문제

```
select * from 계정 
where login_id = '아이디' 
and login_pwd = '비밀번호';
```

예시 공격:

```
where login_id='qwesss2@s.com' or 'q'='w' 
and login_pwd='암호문';
```

Boolean 평가 흐름:

```
T or F and T/F → T or F → T
```

------

### 🔸 Oracle 7번 문제

키워드 검색:

```
select * from 테이블 where keyword like '%검색어%'
order by 컬럼명 ASC/DESC,
(case when 공격쿼리 then 1 else  end)
```

------

## 2. 모바일 앱 분석 환경 구축

| 용도       | 이름                 | 설명                         |
| ---------- | -------------------- | ---------------------------- |
| 에뮬레이터 | Nox App Player       | 구글 검색 후 다운로드 & 설치 |
| 디컴파일러 | jadx                 | GitHub 최신 Release 다운로드 |
| 디컴파일러 | apkstudio            | APK 분석용 GUI               |
| APK 변환   | apkeasytool portable | apktool 기반 CLI 툴          |
| 자바       | Adoptium OpenJDK     | adoptium 검색 후 설치        |
| 파이썬     | Python 3.x           | python download              |
| 디버깅     | adb                  | ADB & Fastboot               |

------

### 🔧 기타 세팅

#### • Rooting / VT-x

- Hyper-V 끄기
  - Windows 기능 → Hyper-V 전체 OFF
  - Windows Sandbox OFF
- VT-x 활성 여부 확인:
  - https://leomoon.com/downloads/desktop-apps/leomoon-cpu-v/

------

## 3. Nox 최초 세팅

1. 실행 중인 에뮬레이터가 64bit인지 확인 (멀티 실행기 Ctrl+6)
2. 기존 에뮬레이터 삭제 후 Android 9 64bit 추가
3. 톱니바퀴(설정)
4. 성능 → 해상도: 스마트폰(540x960)
5. 일반 → ROOT 켜기

------

## 4. ADB(Android Debug Bridge)

### ✔ 개념

PC ↔ 스마트폰을 USB로 연결해 제어/파일관리하는 도구

### ✔ 설치 위치 Path 등록

1. 설정 → 시스템 정보 → 고급 시스템 → 환경 변수
2. Path → 새로 만들기
3. Nox/bin 경로 추가
4. CMD 재실행 필수

------

### ✔ USB 디버깅 활성화

- 설정 → 시스템 → 정보 → **빌드번호 7회 탭**
- 개발자 옵션 활성화
- 개발자 옵션 → USB 디버깅 켜기

------

## 5. ADB 명령어

| 명령어      | 설명                   |
| ----------- | ---------------------- |
| adb devices | 연결된 기기 확인       |
| adb shell   | 스마트폰 OS Shell 접속 |
| adb install | APK 설치               |
| adb pull    | 폰 → PC 파일 추출      |
| adb push    | PC → 폰 파일 전송      |

------

### 📌 설치된 앱 패키지 확인

```
adb shell
pm list packages -f | grep 검색어
```

------

## 6. APK 설치 (수동/ADB)

### 스마트폰 수동 설치

1. 다운로드 폴더에서 APK 실행
2. "알 수 없는 개발자" → 설치 허용

### ADB 설치

```
adb install sample.apk
```

------

## 7. apktool 사용법

```
apktool d 파일.apk     # 디컴파일
apktool b 폴더명       # 리컴파일
```

예시 패키지 구조:

```
com.scottyab.sample.rootbeer
→ com/scottyab/sample/rootbeer
```

------

## 8. Activity 분석

예시:

```
android:name="kr.co.eqst.aos.app008.SplashActivity"
```

경로 구조:

```
kr → co → eqst → aos → app008 → SplashActivity.java
```

### exported = true/false

- `true` : 외부에서 Activity 호출 가능
- `false`: 앱 내부에서만 사용 (보안에 중요함)

예)

```
kr.co.shop → kr.co.kakao.pay.payactivity (exported=false)
```

------

## 9. Android Component 종류

1. Activity
2. Service
3. Broadcast Receiver
4. Content Provider

------

## 10. 앱 종류 비교

### ▲ Web App / Mobile Web

- 설치 필요 없음
- 단점: 기기기능(GPS/카메라 등) 제한

### ▲ Native App

- 빠르고 기능 사용 가능
- Android/iOS 각각 개발 필요

### ▲ Hybrid App

- 웹 기반 + Native 기능 혼합
- 장점: 개발/수정 빠름
- 단점: 일부 기능 느림

------

## 11. WebView 예시 요청

```
GET /
Host: www.naver.com
User-Agent: PC 크롬 또는 모바일 브라우저
```

m.naver.com → 반응형 웹