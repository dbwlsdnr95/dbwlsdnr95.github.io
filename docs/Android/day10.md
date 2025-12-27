---
layout: default
title: "Android 보안 10일차"
parent: Android
nav_order: 10
---

# Frida 기반 동적 분석 정리

------

## 1. Frida 기본 개념

### Frida 구성

- **frida-server**
  - 대상 기기(에뮬레이터/실기기)에서 실행
- **frida / frida-tools**
  - PC에서 실행
  - JavaScript 기반 후킹 코드 실행

```
frida -U -l test.js -f 패키지명
```

- Python은 **외부에서 실행**
- 실제 후킹 로직은 **Frida JavaScript 내부에서 동작**

```
[ Python (frida CLI) ]  <---- IPC ---->  [ Frida JS (App 내부) ]
```

------

## 2. 메모리 개념 정리

### 문자열 / 메모리 구조

```
String key = "1234";
```

- 문자열은 메모리에 **char[] 또는 byte[]** 형태로 저장
- 널 문자(`0x00`) 포함 가능

예시 메모리 표현:

```
"hacker" -> 68 61 63 6b 65 72 00 00 00 00
"test"   -> 74 65 73 74 00
```

- `'test[null][null]' == 'test'`

------

### 메모리 할당

```
Memory.alloc(size)
```

- Native 메모리 직접 할당
- 문자열, 구조체 직접 생성 가능

```
ptr("0x0000")
new NativePointer("0x0000")
```

------

## 3. Native 함수 후킹

### Export 함수 획득

```
Module.getExportByName(null, "fopen");
```

- `null` → 현재 프로세스
- 라이브러리 지정 가능 (예: `libc.so`, `d3d12.dll`)

------

### Native 함수 인터셉트

```
var abc = Module.getExportByName(null, "abc");

Interceptor.attach(abc, {
    onEnter: function (args) {
        // 함수 진입 시
    },
    onLeave: function (retval) {
        // 함수 종료 후
    }
});
```

- `onEnter`: 인자 확인
- `onLeave`: 리턴값 조작 가능

------

### NativeFunction으로 덮어쓰기

```
var newFunc = new NativeFunction(ptr, 'int', ['int', 'int']);
```

- 기존 함수를 새 함수로 대체 가능

------

## 4. Java.use vs Java.choose

### Java.use()

- **Class 설계도 자체**를 가져옴
- 메소드 구현 변경 가능

```
var MainActivity = Java.use("kr.co.eqst.aos.MainActivity");

MainActivity.test.implementation = function (input) {
    this.comp.value = "test";
    return "patched";
};
```

- 아직 생성되지 않은 객체에도 적용됨

------

### Java.choose()

- 이미 생성된 **instance 객체**를 가져옴
- 런타임 상태 변경에 사용

```
Java.choose("kr.co.eqst.aos.app029.MainActivity", {
    onMatch: function (instance) {
        instance.image = "eqst.png";
    }
});
```

- Activity가 이미 생성된 경우 사용

------

## 5. Activity 생성 시점 정리

```
MainActivity ma = new MainActivity();
```

- `$new` → 새 인스턴스 생성
- `Java.choose()` → 기존 인스턴스 접근

| 상황            | 사용            |
| --------------- | --------------- |
| Activity 미생성 | Java.use + $new |
| Activity 생성됨 | Java.choose     |

------

## 6. Smali 조건 분기 정리

```
if-eq v0, v1      같으면 분기
if-neq v0, v1     다르면 분기
if-eqz v0         v0 == 0
if-nez v0         v0 != 0
if-lt v0, v1      v0 < v1
if-le v0, v1      v0 <= v1
if-gt v0, v1      v0 > v1
if-ge v0, v1      v0 >= v1
if-ltz v0         v0 < 0
if-lez v0         v0 <= 0
if-gtz v0         v0 > 0
if-gez v0         v0 >= 0
goto              무조건 점프
```

------

## 7. 무결성 및 탐지 우회

### 동적 분석 특징

- 실행 중 로직 변경 가능
- 무결성 검증, 디버깅 탐지 우회 가능

### 우회 대상

- Frida 탐지
- gdb / lldb 탐지
- CRC 무결성 체크

------

### 예시: Kotlin Intrinsics 우회

```
Java.perform(() => {
    var Intrinsics = Java.use("kotlin.jvm.internal.Intrinsics");

    Intrinsics.areEqual.overload(
        'java.lang.Object',
        'java.lang.Object'
    ).implementation = function (a, b) {

        if (a.toString() !== 'x86_64') {
            return this.areEqual(a, b);
        } else {
            return true;
        }
    };
});
```

------

### CRC 무결성 우회

```
var Zip = Java.use("java.util.zip.ZipEntry");

Zip.getCrc.implementation = function () {
    return 1302005358;
};
```

------

## 8. UI 제어 주의 사항

- UI 관련 함수는 **Main Thread**에서 실행해야 함

```
Java.scheduleOnMainThread(function () {
    Java.choose("kr.co.eqst.aos.app029.MainActivity", {
        onMatch: function (instance) {
            instance.integritycheck();
        }
    });
});
```

------

## 9. Cheat Engine 개념 비교

- 메모리 스캔
- 값 검색 → 필터링 → 덮어쓰기
- 게임 치트, 값 고정에 사용

```
전체 메모리에서 값 05 검색
→ 현재 값 03만 필터
→ 특정 주소 덮어쓰기
```

------

## 10. APK / IPA 구조

- APK = ZIP
- IPA = ZIP
- 내부 바이너리
  - Android: `classes.dex`
  - iOS: ELF / Mach-O 바이너리

------

## 11. Frida 실습 대상

### FridaLab

- Google 검색: `fridalab ross`
- 첫 번째 사이트에서 다운로드
- Frida 실습용 공식 앱

------

## 12. 핵심 요약

- Frida는 **런타임 분석 도구**
- Java.use = 설계도 수정
- Java.choose = 이미 생성된 객체 제어
- Native / Java 후킹 모두 가능
- 무결성·탐지 로직 우회 가능
- 정적 분석 + 동적 분석 병행 필수