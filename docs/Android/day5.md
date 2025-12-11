---
layout: default
title: "Android 보안 5일차"
parent: Android
nav_order: 5
---

## 1. Android 개발 기초

- Java → Kotlin(.kt)
- 버튼 클릭 이벤트 처리
- Service 생성
- JNI(Java Native Interface)
- APK 파일 직접 다운로드 후 설치
- "알 수 없는 출처" 앱 설치
- Android Studio 없이도 앱 설치 가능

## 2. Content Provider & adb content 명령어

### ▶ 기본 구조

```
content query --uri content://패키지명/테이블명
              --projection name:phone
              --where 조건
              --sorting 정렬
```

### ▶ 주요 명령

- `content query`
- `content insert`
- `content update`
- `content delete`

### ▶ Content Provider 개념

- 앱 내부 데이터를 외부 앱이 접근할 수 있도록 만든 API
- 예: 카카오톡이 주소록 접근 → 친구 추가 기능
- 실제 데이터 위치 예:
  - `/data/data/com.kakao.talk`
  - `/data/data/com.google.phone`

------

## 3. 워게임 컴포넌트 분석

### ▶ projection 처리

```
String[] strArr = projection == null
    ? new String[]{ProviderContract.Cols.ID, ProviderContract.Cols.OWNER, ProviderContract.Cols.MEMO}
    : projection;
```

### ▶ SELECT 구문 구성

```
SELECT __projection__
FROM memos
WHERE owner != 'admin'
AND (selection)
ORDER BY 정렬
```

### ▶ content query 예제

```
content query --uri content://kr.co.eqst.aos.app022.memos/memos
```

→ `select id, owner, memo from memos where owner != 'admin'`

```
content query --uri content://kr.co.eqst.aos.app022.memos/memos --projection owner:memo
```

→ `select owner, memo from memos where owner != 'admin'`

### ▶ 공격 포인트 예시

```
--where 1=2) or (owner='admin'
```

→ 테이블 전체 출력 가능

------

## 4. Content Provider 데이터 저장 방식

- Excel
- JSON
- TXT

예시:

```
이름, 전화번호, 회사, 이메일, 생일
```

쿼리 예:

```
content query --uri content://주소록 --projection 이름:전화번호 --where 이름='멍멍이'
```

------

## 5. Android 4대 컴포넌트

- `<activity>`
- `<service>`
- `<provider>` (Content Provider)
- `<receiver>` (BroadcastReceiver)

------

## 6. Broadcast 이벤트

```
am broadcast -n 리시버이름
```

------

## 7. Encrypt Shared Preference

### ▶ Shared Preference 개념

- 앱에서 단순 Key-Value 저장 가능

- 경로:

  ```
  /data/data/패키지명/shared_pref/*.xml
  ```

- 자동로그인 / 토큰 보관 등에 사용

### ▶ 암호화 버전 특징

- 키/IV 코드 내 포함 금지
- 안드로이드 시스템이 처리
- 루팅 + 함수 후킹 시 복호화 가능 → 보안 취약

------

## 8. 유용한 Android 명령어

현재 활성(Activity) 확인:

```
dumpsys activity activities | grep Resume
```

------

## 9. AndroGoat 실습 정리

### ▶ Shared Preferences

```
cat /data/data/owasp.sat.agoat/shared_pref/users.xml
```

### ▶ Shared Preferences 변조

```
vi /data/data/owasp.sat.agoat/shared_pref/score.xml
```

### ▶ SQLite DB

```
sqlite3
.open aGoat
select * from users;
```

### ▶ Temp File 위치

```
/data/data/owasp.sat.agoat/user___랜덤____tmp
```

------

## 10. Android 파일 저장소 구조

- 내부저장소:

  ```
  /data/data/패키지명
  ```

- 외부저장소(SDCard):

  ```
  /Android/data/패키지명
  ```

------

## 11. 로그 출력

```
log.v("태그", "내용")
```