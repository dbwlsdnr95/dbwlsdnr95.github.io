---
layout: default
title: "Android 보안 1일차"
parent: Android
nav_order: 1
---
#  모바일 보안 기초 정리 (Android & iOS)

## 1. 운영체제 개념

| 구분                | Android (갤럭시)        | iOS (아이폰)                   |
| ------------------- | ----------------------- | ------------------------------ |
| 기반 OS             | Linux 기반              | Unix 기반 (Darwin)             |
| 사용자 커스터마이징 | 높음                    | 낮음                           |
| 앱 설치 방식        | APK 파일 직접 설치 가능 | App Store 우선, 외부 설치 제한 |
| 루팅/탈옥           | 비교적 쉬움             | 매우 어려움                    |

------

# 2. 루팅(Rooting) & 탈옥(Jailbreak)

## Android 루팅 이유

- 기본 UI가 마음에 들지 않음  커스텀 UI
- 오버클럭/언더클럭으로 성능 조절
- 배터리 최적화
- 통신사 기본 앱(블로트웨어) 삭제
- 시스템 파일 수정 가능

## iOS 탈옥 이유

- 없는 기능 추가(예: 뒤로가기 제스처)
- 제한된 부분 해제
- 앱스토어 유료앱을 외부에서 설치 가능  (악성 가능성 매우 높음)

## 공통 위험

- 악성 APK / IPA 설치  Spyware에 노출
- 금융앱·보안앱 실행 불가(루팅 탐지)
- 시스템 보안 강도 저하

------

# 3. Spyware & SpyApp 공격 개념

Spyware는 다음을 **사용자 모르게** 수집한다:

- GPS 위치
- 통화 기록
- 문자·카톡 기록
- 인터넷 검색 내역
- 사진 및 파일 접근

 앱 목록에도 표시되지 않는 경우가 많음.

------

# 4. 제로 클릭 공격 (Zero-Click Attack)

사용자가 직접 클릭하지 않아도 감염되는 공격.

예:

- 받은 이미지 파일 보기만 해도 감염
- 문서 파일 열기
- 메시지 앱 취약점 이용 (MMS, iMessage 등)

 또한 **피싱 링크 클릭**도 주요 감염 벡터.

------

# 5. 고객사 앱 보안 테스트 흐름

1. 앱 분석
2. 앱 변조(Modding)
3. 앱과 서버 간 통신 분석
4. 통신 패킷 변조
5. 서버 공격·취약점 진단

------

# 6. 모바일 개발 언어 & 리버싱 기본

## Android

- 언어: **Java, Kotlin**
- 컴파일: `.class`  DEX  Dalvik/ART VM
- 디컴파일: **쉽다**  Java 코드 거의 복원됨
- Native 라이브러리: `.so` (C/C++ 빌드)
- 구조 분석 난이도: Android > iOS (초보 기준)

## iOS

- 언어: **Swift, Objective-C**
- 바이너리(Mach-O)로 컴파일  디컴파일 매우 어려움
- Swift는 Mangle(Symbol 변환)로 함수 이름 난독화
- 앱 확장자: **.ipa**
- 탈옥 기기 필요

------

# 7. 모바일 리버싱 난이도 비교

| 항목               | Android                  | iOS                            |
| ------------------ | ------------------------ | ------------------------------ |
| 언어               | Java/Kotlin              | Swift/Obj-C                    |
| 코드를 얻는 난이도 | 쉬움(디컴파일 잘됨)      | 어려움(바이너리 분석)          |
| 실행 파일          | APK                      | IPA                            |
| Native 코드        | JNI(.so)                 | 거의 모두 Native               |
| 에뮬레이터         | 가능 (Nox, Bluestack 등) | 어려움(맥 필요)                |
| 보안               | 중간                     | 매우 강함 (탈옥 자체가 어려움) |

------

# 8. Rooting / Jailbreak 도구

###  Android 루팅 도구

- **Magisk** (가장 대표적)
- KernelSU
- APatch
- Custom Recovery (TWRP)
- 패치된 boot.img 사용

###  주의: 벽돌(Brick) 가능

- 잘못하면 기기 부팅 불가
- 해결법: Recovery  Wipe  Firmware 재설치

------

# 9. 실습에 필요한 개념

## Recovery Mode

- 갤럭시: 전원 + 볼륨하 + 빅스비
- 기능:
  - Wipe data/factory reset
  - Wipe cache
  - Firmware 초기화

## 앱 설치 구조

- Android: `/sdcard/` 접근 가능
- Root 권한  `/` 전체 접근 가능
- 앱은 각자 sandbox에서 실행

------

# 10. 앱의 ID 구조: 패키지명 (Package Name)

예:

```
com.facebook.app
```

규칙:

```
도메인 반대로  프로젝트  앱이름
kr.co.company.appname
```

패키지명이 같으면?
  다른 앱이 기존 앱을 **업데이트**처럼 덮어쓰기 가능
  악성앱 공격 벡터 중 하나

------

# 11. 다국어 리소스 구조

Android:

```
values_ko.xml
values_en.xml
values_jp.xml
```

예:

```
app_name = 페이스북
login_fail = 로그인이 실패했습니다.
```

언어 설정만 바꿔도 앱 내용이 다르게 표시됨.

------

# 12. Activity Lifecycle (중요)

```
onCreate()       화면 로딩 직후 실행
onStart()
onResume()       화면에 보이기 시작
onPause()
onStop()
onDestroy()
```

Mobile Hacking에서는
 **취약한 Activity/Function이 어디서 실행되는지 파악하는 용도**로 중요함.

------

# 13. 실습 환경 구성(12/4 예정)

### 기기

- 갤럭시(Android)
- 아이폰(iOS)

### 에뮬레이터

- Nox
- BlueStacks
- Genymotion

### 분석 도구

- **Jadx** (APK 디컴파일)
- **ApkTool / APK Studio**
- **Frida** (런타임 후킹)
- **BurpSuite** (통신 변조)

### 개발 언어

- Java
- Python
- JavaScript

### 실습 예정

- EQST 안드로이드 해킹 워게임
- 실제 APK 분석 및 변조