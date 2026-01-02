---
layout: default
title: "Android 보안 11일차"
parent: Android
nav_order: 11
---

# Frida 동적 분석 정리

## 1. Frida 기본 구조

### 구성 요소

- **frida-server** : 안드로이드 단말에서 실행
- **frida-tools** : PC에서 실행 (`frida -U -l test.js`)
- **Frida Script** : JavaScript 기반
- **Python 연동 가능** : Python ↔ Frida JS 상호작용

### 기본 실행 흐름

```
adb shell
cd /data/local/tmp
./frida-server &
frida -U -f com.test.app -l test.js --no-pause
```

------

## 2. 메모리 개념 정리

### 문자열과 메모리

- Java `String` → 객체
- Native 영역 → `char[]`, `byte[]`
- Null 종료 문자열

```
h a c k e r 00 00 00
t e s t 00
```

### 포인터

```
ptr("0x0000")
new NativePointer("0x0000")
```

### Native 함수

```
Module.getExportByName("libc.so", "fopen")
```

------

## 3. Native / Java 후킹 차이

### Native

```
var func = Module.getExportByName(null, "abc");

Interceptor.attach(func, {
    onEnter(args) {},
    onLeave(retval) {}
});
```

### Java

```
Java.use("클래스명").메소드.implementation = function() {
    return 값;
};
```

------

## 4. Java.use vs Java.choose

### Java.use

- 클래스 설계도 자체 수정
- static 함수, 메소드 구현 변경

```
var Main = Java.use("MainActivity");
Main.test.implementation = function() {};
```

### Java.choose

- 이미 생성된 인스턴스 탐색
- Activity, Fragment 제어

```
Java.choose("MainActivity", {
  onMatch: function(instance) {
    instance.test();
  }
});
```

------

## 5. 메모리 변조 도구 개념 (Cheat Engine)

- 메모리 주소 검색
- 값 필터링
- 덮어쓰기
- 런타임 상태 변경

예:

- 전체 메모리에서 `05` 검색
- 현재 값이 `03`인 주소만 필터
- 값 변경

------

## 6. APK / IPA 구조

- **APK** = ZIP
- **IPA** = ZIP
- 내부에 ELF / dex 포함

------

## 7. Frida Java API 핵심

### 메소드 후킹

```
Java.use("java.lang.String")
```

### UI 제어는 MainThread 필수

```
Java.scheduleOnMainThread(function() {
    // UI 조작
});
```

------

## 8. 접근 제한자 개념

| 키워드     | 설명               |
| ---------- | ------------------ |
| public     | 외부 접근 가능     |
| private    | 내부 전용          |
| static     | 인스턴스 없이 호출 |
| non-static | 인스턴스 필요      |

```
MainActivity.test      // static
ma.test                // instance
```

------

## 9. Activity 생성 시점

- 이미 생성 → `Java.choose`
- 새로 생성 → `$new`

```
var Main = Java.use("MainActivity");
var ma = Main.$new();
```

------

## 10. Smali 조건 분기 정리

| 명령어 | 의미         |
| ------ | ------------ |
| if-eq  | 같다         |
| if-neq | 다르다       |
| if-eqz | 0이면        |
| if-nez | 0이 아니면   |
| if-ltz | 0보다 작으면 |
| if-lez | 0 이하       |
| if-gtz | 0 초과       |
| if-gez | 0 이상       |
| goto   | 무조건 점프  |

------

## 11. Smali 패치 흐름

1. APK 디컴파일
2. `.smali` 파일 수정
3. 재빌드
4. 재서명
5. 설치
6. 실행

```
am start 패키지/액티비티
```

------

## 12. 무결성 검증 우회 개념

- CRC 체크
- CPU_ABI 체크
- 디버깅 탐지

### 예시

```
var Intrinsics = Java.use("kotlin.jvm.internal.Intrinsics");

Intrinsics.areEqual.implementation = function(a, b) {
    if (a.toString() == "x86_64") {
        return true;
    }
    return this.areEqual(a, b);
};
```

### CRC 우회

```
var Zip = Java.use("java.util.zip.ZipEntry");
Zip.getCrc.implementation = function() {
    return 1302005358;
};
```

------

## 13. UI 제어 예제

```
Java.perform(function () {
    Java.scheduleOnMainThread(function () {
        Java.choose("MainActivity", {
            onMatch: function (instance) {
                instance.integritycheck();
            }
        });
    });
});
```

------

## 14. FridaLab 참고

- FridaLab (Ross Marks)
- Google 검색: `fridalab ross`
- 실습용 난독화 / 무결성 우회 앱

------

## 15. 동적 분석 핵심 정리

- 실행 중 로직 변경
- 무결성 검사 우회 가능
- 메모리 보호는 제한적
- 정적 분석 + 병행 필수
- Smali 패치 + Frida 조합 강력

------

원하면 다음도 바로 해줄 수 있어: