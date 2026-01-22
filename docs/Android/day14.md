---
layout: default
title: "Android 보안 14일차"
parent: Android
nav_order: 14
---

# JNI (Java Native Interface) 정리

## 1. JNI 개요

### JNI란?

- **Java/Kotlin ↔ C/C++** 간의 상호 호출을 가능하게 하는 인터페이스
- Android에서 **Native 코드(.so)** 를 사용하기 위한 표준 방식

### 기본 구조

- Java/Kotlin → JNI → C/C++
- Native 라이브러리 형태: `.so`

------

## 2. 개발 환경 구축

### Android Studio

- Android 앱 개발용 공식 IDE
- 에뮬레이터는 사용하지 않음 (NOX 사용)

### Ghidra

- 오픈소스 리버싱 도구
- 다운로드
  - Google 검색: `ghidra github`
  - Release 버전 다운로드
- 실행
  - 압축 해제
  - `ghidraRun.bat` 실행

### Java 환경 오류 해결

- 오류 예시
  - `JAVA_HOME`
  - `java version not found`
- 해결 방법
  1. 기존 Java 삭제
  2. **OpenJDK 재설치**
  3. 설치 옵션 전체 선택
  4. `JAVA_HOME` 자동 설정 확인

### OpenJDK 다운로드

- https://adoptium.net/

------

## 3. NOX + ADB 환경 구성

### ADB 파일 교체 이유

- NOX 기본 ADB가 불안정
- Android Studio ADB로 교체 필요

### 원본 ADB 경로

```
C:\Users\사용자\AppData\Local\Android\Sdk\platform-tools\
```

### 복사 대상 파일

- adb.exe
- AdbWinApi.dll
- AdbWinUsbApi.dll

### NOX 경로

```
C:\Program Files (x86)\Nox\bin\
```

### 적용 방법

- 기존 파일 덮어쓰기
- `adb.exe` 복사 → 이름 변경 → `nox_adb.exe`

------

## 4. NOX USB 디버깅 활성화

1. NOX 설정 → 시스템 → 태블릿 정보
2. **빌드 번호 연속 클릭**
3. 개발자 모드 활성화
4. 고급 설정 → 개발자 옵션
5. USB 디버깅 활성화

------

## 5. Android 프로젝트 생성

### 프로젝트 설정

- App Name: `testapp`
- Package Name: `kr.seyong.testapp`
- SDK: 24
- Language: Java
- Native(C/C++): 기본 옵션
- Finish

------

## 6. 설치된 앱 추출

```
adb shell
pm list packages -f | grep 패키지명
```

------

## 7. Java와 C 문자열 차이

### Java String

```
String a = new String("abcd");
```

- 객체
- JVM Heap에 저장

### C String

```
char* a = {'a','b','c','d','\0'};
```

- Null 종료 문자열
- 메모리 직접 관리

------

## 8. JNI를 사용하는 이유

### Google 권장

- “가능하면 JNI 쓰지 마라”
- Kotlin / Java API로 대부분 해결 가능

### 그럼에도 JNI를 쓰는 이유

1. **성능**
   - 게임
   - 그래픽
   - 하드웨어 연산
2. **OS 레벨 접근**
   - 파일 시스템
   - 저수준 연산
3. **보안**
   - 코드 은닉 목적
   - 리버싱 난이도 상승

### 보안 솔루션

- 모바일 보안 솔루션 대부분 JNI 사용
- Native 레벨에서 무결성 / 탐지 수행

------

## 9. JVM vs Native 실행 구조

### Java / Kotlin

- JVM 위에서 실행
- Cross-platform
- 동일 APK → 모든 기기 실행 가능

### Native (C/C++)

- OS / 아키텍처 의존
- 환경별 빌드 필요

| 환경    | 결과           |
| ------- | -------------- |
| Windows | `.exe`, `.dll` |
| Linux   | ELF, `.so`     |
| Android | `.so`          |

------

## 10. ABI와 Native 라이브러리

### ABI 종류

- arm
- arm64-v8a
- x86
- x86_64

### 기본 포함 구조

- 각 ABI별 `.so` 파일 필요
- 32bit / 64bit 에뮬레이터 별도 대응

------

## 11. JNI 라이브러리 로딩

### System.loadLibrary

```
System.loadLibrary("test");
```

- 실제 로드 파일

```
libtest.so
```

- APK 내부 `/lib/<abi>/libtest.so`

### System.load

```
System.load("/sdcard/android/data/lib/arm64/libtest.so");
```

------

## 12. JNI 기본 코드 구조

### Java 코드

```
class MainActivity {

    static {
        System.loadLibrary("testapp");
    }

    public native void callJni();
}
```

### Native 함수 시그니처

```
Java_kr_seyong_testapp_MainActivity_callJni(
    JNIEnv* env,
    jobject thiz
) {
    // Native 로직
}
```

------

## 13. JNI_OnLoad & RegisterNative

### JNI_OnLoad

- 라이브러리 로드 시 자동 실행
- Native 함수 등록 가능

```
JNI_OnLoad(JavaVM* vm, void* reserved) {
    // RegisterNativeMethods
}
```

------

## 14. 문자열 비교 (보안 핵심)

### Java

```
String a = "aaa";
String b = "bbb";

if (a == b) {
    // 주소 비교
}

if (a.equals(b)) {
    // 값 비교
}
```

### C / C++

```
strcmp(a, b); // 값 비교
std::string a = "aaa";
std::string b = "aaa";

if (a == b) // 주소 비교 (의도와 다를 수 있음)
```

------

## 15. 인증 로직 예시

```
private boolean checkPassword(String pw) {
    if (pw.equals("hacker")) {
        return true;
    } else {
        return false;
    }
}
```

- JNI에서 이런 로직을 처리하면
  - Java 코드 노출 감소
  - 리버싱 난이도 증가

------

## 16. 보안 관점 정리

- JNI는 **성능 + 보안 목적**
- Native 코드도 결국 리버싱 가능
- Ghidra / IDA로 분석 가능
- Frida와 결합 시 동적 우회 가능

------

### 요약 한 줄

> JNI는 성능과 보안을 위해 사용되며, Java/Kotlin과 Native 간의 경계를 이해하는 것이 모바일 보안 분석의 핵심이다.

