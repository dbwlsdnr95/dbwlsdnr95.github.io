---
layout: default
title: "Android 보안 17일차"
parent: Android
nav_order: 17
---

# EQST LMS Wargame  JNI 분석 정리

## 1. Frida 버전 이슈

### Export 함수 찾기 변화

- 예전 방식 (동작 X)

```
Module.findExportByName(null, "함수명");
```

- 현재 Frida 권장 방식

```
Module.findGlobalExportByName("함수명");
```

### 버전 호환성

- 최신 Frida에서 일부 Wargame 동작 문제 발생
- **Frida 17  14로 다운그레이드 후 정상 동작**

------

## 2. C / Java boolean 차이

### C / C++

- `bool`
  - `0` : false
  - `1` : true
- 내부적으로 `int`

### Java / JNI

- `boolean`, `jboolean`
- JNI 시그니처에서는 `undefined8` 등으로 보일 수 있음

### JNI 함수 시그니처 예시

```
bool Java_kr_co_eqst_aos_app039_MainActivity_koalavsmonkey(JNIEnv* env, jobject thiz)
```

------

## 3. JNI 함수 호출 구조

- Java Activity에서 Native 함수 호출
- JNI 함수는 항상 다음 인자를 가짐

```
JNIEnv*
jobject (this)
[추가 인자들]
```

------

## 4. 3번 문제  strcmp 리턴값 변조

### 핵심 아이디어

- `strcmp()` 결과를 조작해 조건을 항상 참으로 만들기
- `"eqst"` 와 비교되는 경우만 타겟팅

### Frida 코드

```
var strcmpPtr = Module.findGlobalExportByName("strcmp");
var inja2;

Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
        inja2 = args[1].readCString();
        if (inja2 == "eqst") {
            console.log("비교 대상:", args[0].readCString());
            console.log("strcmp 호출됨");
        }
    },
    onLeave: function (re) {
        if (inja2 == "eqst") {
            console.log("결과를 참으로 변조");
            re.replace(0x0); // strcmp == 0  동일
        }
    }
});
```

------

## 5. Spawn 모드 주의사항

```
frida -U -f 패키지명
```

- Spawn 상태에서는 Native 모듈이 아직 로드되지 않아
  - `Process.findModuleByName()` 실패 가능
- 해결 방법
  - `System.loadLibrary` 이후 후킹
  - `onCreate` 후킹
  - 일정 시간 delay 후 실행

------

## 6. Native 함수 Offset 기반 후킹

### 메모리 구조

```
libnative-lib.so
base = 0x00100000
함수 = 0x00101930
offset = 0x1930
```

### Frida 코드

```
var libMod = Process.findModuleByName("libnative-lib.so");
console.log("native-lib base:", libMod.base);

var funcPtr = libMod.base.add(0x1930);
console.log("LMS 문자열 리턴 함수:", funcPtr);

Interceptor.attach(funcPtr, {
    onLeave: function (ret) {
        var newPtr = Memory.allocUtf8String("eqst");
        ret.replace(newPtr);
    }
});
```

------

## 7. strcmp 모니터링용 후킹 (확인용)

```
var strcmpPtr = Module.findGlobalExportByName("strcmp");
var inja2;

Interceptor.attach(strcmpPtr, {
    onEnter: function (args) {
        inja2 = args[1].readCString();
        if (inja2 == "eqst") {
            console.log("비교 문자열:", args[0].readUtf8String());
            console.log("strcmp 호출됨");
        }
    }
});
```

------

## 8. Native 함수 직접 호출 (Flag 추출)

### 목표

- Native 함수가 반환하는 `jstring` 직접 호출하여 Flag 획득

### Frida 코드

```
Java.perform(function () {

    const soName = "libnative-lib.so";
    const module = Process.getModuleByName(soName);
    const realflagPtr = module.base.add(0x1070);

    console.log("[+] realflag 주소:", realflagPtr);

    const realflag = new NativeFunction(
        realflagPtr,
        "pointer",              // jstring
        ["pointer", "pointer"]  // JNIEnv*, jclass
    );

    const env = Java.vm.getEnv();
    const clazz = ptr(0);

    const jstr = realflag(env.handle, clazz);
    console.log("[+] jstring:", jstr);

    const result = env.getStringUtfChars(jstr).readCString();
    console.log("[+] result:", result);
});
```

------

## 9. 핵심 개념 요약

- `Module.findGlobalExportByName` 사용
- `strcmp == 0`  문자열 동일
- Native 함수는 **base + offset** 사고
- Spawn 모드에서는 Native 로딩 타이밍 중요
- `jstring`은 반드시 `JNIEnv`를 통해 문자열로 변환
- attach = 감시 + 변조
- replace = 완전 치환

