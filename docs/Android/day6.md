---
layout: default
title: "Android 보안 6일차"
parent: Android
nav_order: 6
---

## 1. 모바일 API & Web 통신 구조

### 1.1 HTTP API 통신 예시

```
GET /api/v2/ HTTP/1.1
{
  "cmd": "list",
  "data": "board",
  "keyword": "검색어"
}
```

- 모바일 앱  서버 간 API 통신
- PC  모바일 개발자 도구를 통해 트래픽 분석 가능
- Burp Suite, mitmproxy 등으로 **MITM 분석**

------

### 1.2 서버 쿼리 구조 예시

```
SELECT 컬럼들
FROM data입력값
WHERE title LIKE '%검색어%';
```

- 입력값이 서버 쿼리에 직접 사용될 경우 **SQL Injection 위험**

------

## 2. TCP 통신 기반 취약점

### 2.1 TCP 입력값 조작

```
[ 3' AND 1=1 ] 검색
```

- HTTP가 아닌 **Raw TCP 통신**에서도 입력값 검증 미흡 시 취약
- Binary / Hex 기반 데이터 (`2F8BC24`) 분석 필요

------

## 3. Android 앱 내부 구조 공격 포인트

### 3.1 Activity / Memory 변조

- **Activity 변조**
  - 숫자만 입력되도록 제한된 View  강제 변조
- **Memory 변조**
  - 중요 데이터가 메모리에 상주하는 위치 분석

```
String a = "test"; // 메모리에 장시간 남음 (위험)
char[] a = {0x00, 0x00, 0x00}; // 사용 후 초기화 가능 (권장)
```

- Java / Kotlin: `String`  GC 전까지 메모리 잔존
- C 계열: `char[]`  직접 초기화 가능

------

### 3.2 메모리 덤프 관련

```
dumpsys heap 패키지명
frida-dump
```

- 인증 토큰, ID/PW, 개인정보 노출 가능성 점검

------

## 4. 인증 & 자동 로그인 구조

### 4.1 로그인 흐름

```
ID / PW  로그인 성공  인증 토큰 발급
```

- 인증 토큰이 **SharedPreferences**에 저장되는 경우 위험

```
/data/data/패키지명/shared_prefs/*.xml
```

------

### 4.2 SharedPreferences 저장 위치

```
/data/data/패키지명/
  shared_prefs/
  databases/
  files/
```

- Root 환경에서 평문 저장 시 **심각한 취약점**

------

## 5. 보안 솔루션 & 난독화

### 5.1 난독화 기법

```
a.e.f()
iiillll11l()
iilllll1()
```

- 의미 없는 함수/변수명
- **DexGuard / ProGuard** 사용

------

### 5.2 가상 키패드 / 백신

- 키로깅 방지 목적
- 메모리 직접 접근 시 우회 가능성 존재

------

## 6. 리다이렉트 취약점

### 6.1 취약한 URL 예시

```
test.com/login?id=&pw=&url=test.com/member/
```

- 외부 URL 허용 시 **Open Redirect 취약점**
- 피싱, 인증 우회로 악용 가능

------

## 7. APK & 리버스 엔지니어링 기초

### 7.1 APK 구조

```
abank.apk
  AndroidManifest.xml
  classes.dex
  lib/
  assets/
  resources/
```

- APK = 압축 파일
- **디컴파일 필요**

------

### 7.2 디컴파일 도구

| 도구            | 설명             |
| --------------- | ---------------- |
| apktool         | 리소스 분석      |
| jadx / jadx-gui | Java 소스 복원   |
| APK Studio      | GUI 기반         |
| APK Easy Tool   | Windows Portable |

------

### 7.3 코드 변환 흐름

```
Java / Kotlin  class  smali  classes.dex
C / C++  .so  JNI  Java
```

------

## 8. Android Component 구조

| Component          | 설명        |
| ------------------ | ----------- |
| Activity           | 화면        |
| Service            | 백그라운드  |
| Content Provider   | 데이터 공유 |
| Broadcast Receiver | 이벤트 처리 |

------

## 9. Content Provider 취약점

### 9.1 코드 예시

```
Cursor cursor = getContentResolver().query(
  Uri.parse("content://kr.co.eqst.app022.memos"),
  new String[]{"memo"},
  "owner=?",
  new String[]{"user"},
  null
);
```

------

### 9.2 SQL Injection 가능 구조

```
SELECT memo
FROM memos
WHERE owner != 'admin'
AND ( 1=1 ) OR ( 공격쿼리 )
content query \
 --uri content://kr.co.eqst.app022.memos \
 --projection memo \
 --where "1=1) OR (owner='admin')"
```

------

## 10. Intent 취약점

### 10.1 Intent 구조

```
Intent intent = new Intent();
intent.putExtra("role", "99");
```

- 권한 검증 없이 Extra 사용 시 **권한 상승**

------

### 10.2 Activity 강제 실행

```
am start 패키지명/.Activity명 --es role admin
dumpsys activity activities | grep Resumed
```

------

## 11. 시스템 명령어 정리

### 11.1 adb / am / content

```
am start 패키지명/.Activity명
am startservice 패키지명/.Service명
am broadcast -a ACTION -n 패키지명/.Receiver
```

------

### 11.2 SQLite 접근

```
cd /data/data/패키지명/databases
sqlite3 db파일명
SELECT * FROM table;
INSERT INTO table VALUES (...);
```

------

## 12. 무결성 검증 & 리소스 분석

- `classes.dex` 해시값 비교
- 루팅 탐지 / 변조 탐지 여부 확인
- `value-ko.xml` 등 문자열 암호화 여부

```
<string name="error_msg">elfkjqwelfkj</string>
showMessage("오류", decrypt(error_msg));
```

------

## 13. 취약점 실습 앱

| 앱             | 설명                  |
| -------------- | --------------------- |
| AndroGoat      | 공식 취약점 실습      |
| InsecureBankV2 | 은행 앱 취약점        |
| DIVA           | 구버전 Android 취약점 |

------

## 14. 기타

- Termux  Android 내부 Linux 환경
- Unity 앱  C# / DLL  dnSpy / ILSpy 분석
- log4j 취약점  `cmd.jsp?cmd=ls -al`

------

###  정리 포인트

- **입력값  서버/로컬 쿼리 흐름 추적**
- **메모리·스토리지·컴포넌트 접근 제어**
- **Intent / Content Provider 검증**
- **난독화·무결성 검증 유무 확인**
