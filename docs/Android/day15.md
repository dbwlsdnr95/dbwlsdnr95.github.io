---
layout: default
title: "Android 보안 15일차"
parent: Android
nav_order: 15
---

# JNI + Frida Native 분석 정리

## 1. Native 라이브러리 메모리 구조

### 실행 시 메모리 배치 개념

```
testapp           libtestapp.so           libc.so
0x00000000        0x00123456              0x00234567
```

- **base address**
  - 앱 또는 라이브러리가 메모리에 적재된 시작 주소
- **offset**
  - base 주소로부터 함수가 위치한 상대 거리

### 주소 계산 공식

```
실제 함수 주소 = module.base + offset
```

예:

```
base = 0x00100000
offset = 0x000245b0
실제 주소 = 0x001245b0
```

------

## 2. JNI 함수 예제 (checkPassword)

### Java 선언부

```
public native boolean checkPassword(String pw);
```

### Native 함수 시그니처

```
Java_kr_seyong_testapp_MainActivity_checkPassword(
    JNIEnv* env,
    jobject thiz,
    jstring pw
)
```

------

## 3. Ghidra에서 본 Native 코드

```
bool Java_kr_seyong_testapp_MainActivity_checkPassword(
    _JNIEnv *env,
    undefined8 thiz,
    _jstring *pw
) {
    int ret;
    char* nativeStr;

    nativeStr = (char*)env->GetStringUTFChars(pw, 0);
    ret = strcmp(nativeStr, "hacker");
    env->ReleaseStringUTFChars(pw, nativeStr);

    return ret == 0;
}
```

### 핵심 포인트

- `jstring  char*` 변환
- `strcmp()` 로 문자열 비교
- `"hacker"` 와 동일하면 true

------

## 4. JNI 분석 순서 정리

1. Java에서 **native 함수 선언부 확인**
2. `System.loadLibrary()` 또는 `System.load()` 확인
3. 실제 `.so` 파일 위치 확인
   - `/lib/<abi>/libxxx.so`
   - `/android/obb/`
4. 현재 실행 환경에 맞는 ABI 선택
5. `.so` 파일 추출
6. Ghidra로 열기
7. Export 함수 목록 확인
8. 분석 대상 함수 확인

------

## 5. Frida에서 Native 제어 개념

### Java vs Native 제어 방식

| 구분      | Java           | Native        |
| --------- | -------------- | ------------- |
| 접근 방식 | Java.use       | NativePointer |
| 기준      | 클래스/메소드  | 메모리 주소   |
| 후킹      | implementation | Interceptor   |

------

## 6. Native 함수 주소 찾기

### Export 기반

```
var lib = Process.findModuleByName("libtestapp.so");
var func = lib.findExportByName(
  "Java_kr_seyong_testapp_MainActivity_checkPassword"
);
```

### Offset 기반

```
var base = lib.base;
var func = base.add(0x245b0);
```

------

## 7. Native 함수 후킹 (Interceptor.attach)

```
Interceptor.attach(func, {
    onEnter: function (args) {
        console.log("checkPassword 호출");

        // args[2] = jstring pw
    },
    onLeave: function (ret) {
        console.log("리턴값:", ret);
    }
});
```

### 인자 구조

```
args[0]  JNIEnv*
args[1]  jobject (this)
args[2]  jstring pw
```

------

## 8. 인자 값 변조 (메모리 조작)

```
Interceptor.attach(func, {
    onEnter: function (args) {
        var newStr = Memory.allocUtf8String("hackernono");
        args[2] = newStr;
    }
});
```

- Native 영역은 **메모리 직접 수정**
- 문자열 끝에 `\0` 필요

------

## 9. 리턴값 변조

```
Interceptor.attach(func, {
    onLeave: function (ret) {
        ret.replace(0x01); // true
    }
});
```

- 인증 로직 강제 통과 가능

------

## 10. 함수 완전 교체 (Interceptor.replace)

```
var newFunc = new NativeCallback(function () {
    return 1;
}, 'int', []);

Interceptor.replace(func, newFunc);
```

- 원래 함수 실행 자체를 제거

------

## 11. Native 함수 직접 호출

```
var nativeFunc = new NativeFunction(
    func,
    'int',
    ['pointer', 'pointer', 'pointer']
);

var result = nativeFunc(a, b, c);
console.log(result);
```

------

## 12. strcmp 후킹 개념

```
var strcmpPtr = ptr("0x79cbc06e4010");
```

주의:

- 문자열 `"0x79cbc06e4010"`  잘못된 타입
- 반드시 `ptr()` 또는 `NativePointer` 사용

------

## 13. 모듈 / 함수 탐색

```
Process.enumerateModules();
Module.enumerateExports();
Module.enumerateImports();
```

------

## 14. JNI 문자열 처리 예제 (정상 구현)

```
const char* jstringToCString(JNIEnv* env, jstring jstr) {
    if (jstr == NULL) return NULL;
    return env->GetStringUTFChars(jstr, NULL);
}
jboolean checkPasswordNative(const char* pw) {
    if (pw == NULL) return JNI_FALSE;
    return strcmp(pw, "hacker") == 0;
}
```

------

## 15. Frida 개발 환경 팁

- Frida JS 자동완성
  - Node.js 설치 필요
- VSCode
  - Extension: **Frida Workbench**
  - 명령 팔레트  `Frida: Enable Hints`

------

## 16. 핵심 정리

- JNI 분석은 **주소 기반 사고**
- offset 개념 필수
- Java 문자열  C 문자열
- Native 후킹은 `Interceptor`
- 인증/무결성 로직은 Native에 숨겨지는 경우가 많음
- Ghidra + Frida 조합이 가장 강력