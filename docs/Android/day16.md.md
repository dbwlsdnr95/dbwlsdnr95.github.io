---
layout: default
title: "Android 보안 16일차"
parent: Android
nav_order: 16
---

# JNI (Java Native Interface) 정리

## 1. JNI 개념

### JNI란?

- **Java/Kotlin ↔ C/C++** 를 연결하는 인터페이스
- Android 앱에서 Native 코드(`.so`)를 사용하기 위한 표준 방식

### JNI를 사용하는 이유

- **성능**
  - VM 위가 아닌 Native에서 직접 연산
  - 게임, 그래픽, 대규모 연산
- **기존 라이브러리 활용**
  - 이미 만들어진 C/C++ 라이브러리 재사용
- **메모리 직접 제어**
  - GC 영향 없이 직접 관리
- **보안**
  - Java 코드보다 리버싱 난이도 상승
  - 금융 앱, 게임, 보안 솔루션에서 다수 사용

------

## 2. Java / Native 실행 구조 비교

### Java / Kotlin

- JVM 위에서 실행
- Cross-platform
- 코드 하나로 모든 기기에서 실행 가능

### Native (C/C++)

- OS / 아키텍처 의존
- 환경별로 빌드 필요

| 환경    | 결과           |
| ------- | -------------- |
| Windows | `.exe`, `.dll` |
| Linux   | ELF, `.so`     |
| Android | `.so` (ABI별)  |

------

## 3. JNI 함수 연결 방식

### Java 쪽

```
public native boolean checkPassword(String pw);
```

### Native 쪽 (기본 네이밍)

```
Java_패키지명_클래스명_함수명
```

예:

```
Java_kr_seyong_test_MainActivity_checkPassword
```

### System.load / loadLibrary

```
System.loadLibrary("test");   // libtest.so
System.load("/sdcard/.../libtest.so");
```

- 라이브러리 로딩 시 `JNI_OnLoad` 실행 가능

------

## 4. RegisterNative 방식

- 함수 이름을 직접 매핑
- Java 함수명 ≠ Native 함수명 가능

```
JNI_OnLoad() {
    RegisterNativeMethods(
        Java test() → C qqqq()
    );
}
```

- Ghidra에서 함수명이 난독화되어 보이는 이유

------

## 5. Android / iOS 리버싱 구조 비교

### Android

- APK = ZIP
- `classes.dex → smali → java (jadx)`
- Native: `.so` → Ghidra / IDA

### iOS

- IPA = ZIP
- `Info.plist`
- Binary 추출 후 Ghidra / IDA
- 탈옥 환경: Cydia, Zebra, Sileo
- 설치: appinst, 3uTools, appsync

------

## 6. Native 메모리 구조와 Offset

### 메모리 배치 개념

```
libc.so        libandroid.so        libtest.so
[            ][                  ][            ]
base                            base
```

### Offset 개념

- base 주소로부터 떨어진 거리

```
실제 함수 주소 = module.base + offset
```

예:

```
base   = 0x00100000
offset = 0x000243c0
addr   = 0x001243c0
```

------

## 7. JNI Native 코드 예제 (Ghidra 기준)

```
bool Java_kr_seyong_test_MainActivity_checkPassword(
    JNIEnv *env,
    jobject thiz,
    jstring pw
) {
    int ret;
    char* nativeStr;

    nativeStr = env->GetStringUTFChars(pw, 0);
    ret = strcmp(nativeStr, "hacker");
    env->ReleaseStringUTFChars(pw, nativeStr);

    return ret == 0;
}
```

### 핵심

- `jstring → char*`
- `strcmp` 결과로 인증 판단

------

## 8. Frida Native 후킹 기본 구조

### 라이브러리 & 함수 주소 찾기

```
var lib = Process.findModuleByName("libtest.so");

// 1. 함수명 기반
var funcAddr = lib.findExportByName(
  "Java_kr_seyong_test_MainActivity_checkPassword"
);

// 2. 오프셋 기반
var funcAddr = lib.base.add(0x243c0);
```

------

## 9. Interceptor.attach (함수 후킹)

### 실행 흐름

- **onEnter**: 함수 진입 시
- **onLeave**: 리턴 직전

```
Interceptor.attach(funcAddr, {
    onEnter: function (args) {
        /*
          args[0] = JNIEnv*
          args[1] = jobject (this)
          args[2] = jstring (pw)
        */
    },
    onLeave: function (retval) {
    }
});
```

------

## 10. jstring 값 읽기

```
var env = Java.vm.getEnv();
var pw = env.getStringUtfChars(args[2], null).readCString();
console.log(pw);
```

------

## 11. 리턴값 변조 (인증 우회)

```
onLeave: function (retval) {
    retval.replace(1); // JNI_TRUE
}
```

------

## 12. strcmp 전역 후킹

```
var strcmpAddr = Module.findGlobalExportByName("strcmp");

Interceptor.attach(strcmpAddr, {
    onEnter: function (args) {
        var a = args[0].readCString();
        var b = args[1].readCString();
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
});
```

------

## 13. Native 함수 직접 호출

```
var nativeFunc = new NativeFunction(
    funcAddr,
    "int",
    ["pointer", "pointer", "pointer"]
);

var ret = nativeFunc(a, b, c);
```

------

## 14. 함수 완전 교체 (Interceptor.replace)

```
var newFunc = new NativeCallback(function () {
    return 1;
}, "int", []);

Interceptor.replace(funcAddr, newFunc);
```

- 원본 함수 실행 자체 제거

------

## 15. Java 후킹과 비교

### Java

```
Java.use("Class").method.implementation = function () {
    return true;
};
```

### Native

- 주소 기반
- 메모리 직접 제어

------

## 16. Hook 타이밍 이슈

### 문제

- `-f 패키지명` 실행 시
  - `System.loadLibrary` 미실행
  - lib 주소가 null

### 해결 방법

- `System.loadLibrary` 후킹
- `onCreate` 후킹
- 일정 시간 지연 후 후킹

------

## 17. 조건 분기 (어셈블리 개념)

```
CMP v0, v1
JZ  0x1234   ; 같으면 점프
JNZ 0x1234   ; 다르면 점프
```

Java 코드 대응:

```
if (a == b) {
    // 참
}
```

------

## 18. 핵심 정리

- JNI 분석은 **주소 + 오프셋 사고**
- Java String ≠ C String
- 인증/무결성 로직은 Native에 숨겨지는 경우 많음
- Ghidra + Frida 조합이 가장 강력
- attach = 감시
- replace = 완전 대체