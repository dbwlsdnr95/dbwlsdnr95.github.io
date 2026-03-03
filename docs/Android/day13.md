---
layout: default
title: "Android 보안 13일차"
parent: Android
nav_order: 13
---

# Frida Labs & EQST Wargame 정리

## FridaLabs 7번

### 핵심 개념

- 생성자 변조 외에도 **기존 인스턴스 활용**, **필드 값 직접 변조**, **새 인스턴스 생성** 방식으로 우회 가능
- `Java.use`  클래스
- `Java.choose`  이미 생성된 인스턴스
- `$new()`  새로운 인스턴스 생성

------

### 방법 1. Checker 인스턴스를 새로 생성해서 flag 호출

```
Java.perform(() => {
    var Checker = Java.use("com.ad2001.frida0x7.Checker");
    var ch = Checker.$new(999, 999);

    Java.choose("com.ad2001.frida0x7.MainActivity", {
        onMatch: function (ins) {
            console.log(ins);
            ins.flag(ch);
        },
        onComplete: function () {}
    });
});
```

- 기존 로직 무시
- 조건을 만족하는 객체를 직접 생성해 전달

------

### 방법 2. 기존 Checker 인스턴스 값 변조 후 flag 호출

```
Java.perform(() => {
    Java.choose("com.ad2001.frida0x7.Checker", {
        onMatch: function (ch) {
            ch.num1.value = 999;
            ch.num2.value = 999;

            Java.choose("com.ad2001.frida0x7.MainActivity", {
                onMatch: function (ins) {
                    ins.flag(ch);
                },
                onComplete: function () {}
            });
        },
        onComplete: function () {}
    });
});
```

- 이미 생성된 객체 내부 필드를 직접 수정
- 실행 시점이 중요

------

## EQST LMS / Wargame 개요

### 리버싱 도구

- IDA : Disassembly 기반 분석
- Ghidra : 정적 분석
- JNI : `.so` 파일 (ARM64)
- iOS : IPA Binary 분석

------

## 문제별 정리

------

## 1번  Static 메소드 호출

```
Java.perform(() => {
    var MainActivity = Java.use("kr.co.eqst.aos.app031.MainActivity");
    var flag = MainActivity.getFlag();
    console.log(flag);
});
```

### 포인트

- static 메소드는 인스턴스 불필요
- Kotlin은 static 개념이 다름 (companion object)

------

## 2번  Non-static 메소드 호출

### 방법 1. 기존 인스턴스 사용

```
Java.perform(() => {
    Java.choose("kr.co.eqst.aos.app032.GetInfo", {
        onMatch: function (ins) {
            ins.getFlag();
        },
        onComplete: function () {}
    });
});
```

### 방법 2. 인스턴스 직접 생성

```
Java.perform(() => {
    var ins = Java.use("kr.co.eqst.aos.app032.GetInfo").$new();
    var flag = ins.getFlag();
    console.log(flag);
});
```

------

## 3번  내부 함수 직접 호출

```
Java.perform(() => {
    Java.choose("kr.co.eqst.aos.app033.MainActivity", {
        onMatch: function (ins) {
            ins.callthisfunction();
        },
        onComplete: function () {}
    });
});
```

- UI 클릭 로직 우회
- 내부 로직만 직접 실행

------

## 4번  Boolean 필드 변조 (권한 우회)

### 클래스 기준

```
Java.perform(() => {
    var MainActivity = Java.use("kr.co.eqst.aos.app034.MainActivity");
    MainActivity.isAdmin.value = true;
});
```

### 기존 인스턴스 기준

```
Java.perform(() => {
    Java.choose("kr.co.eqst.aos.app034.MainActivity", {
        onMatch: function (ins) {
            ins.isadmin.value = true;
        },
        onComplete: function () {}
    });
});
```

### 실행 시점 정리

- `Java.use`  이후 생성되는 인스턴스
- `Java.choose`  이미 생성된 인스턴스

------

## 5번  함수 오버라이딩으로 인자 변조

```
Java.perform(() => {
    var MainActivity = Java.use("kr.co.eqst.aos.app035.MainActivity");

    MainActivity.checkparam.implementation = function (a, b) {
        a = "EQSTLab";
        b = "eqstlab";
        return this.checkparam(a, b);
    };
});
```

------

### 내부 변수 직접 변조 방법

#### 생성자 변조

```
MainActivity.$init.implementation = function () {
    this.$init();
    this.changethis1.value = "EQSTLab";
};
```

#### Setter 호출

```
Java.choose("kr.co.eqst.aos.app035.MainActivity", {
    onMatch: function (a) {
        a.setChangethis1("EQSTLab");
    }
});
```

#### Static 변수

```
MainActivity.changethis2.value = "eqstlab";
```

------

## 6번  Kotlin Intrinsics.areEqual 후킹

```
Java.perform(() => {
    var Intrinsics = Java.use("kotlin.jvm.internal.Intrinsics");

    Intrinsics.areEqual
        .overload("java.lang.Object", "java.lang.Object")
        .implementation = function (a, b) {
            if (a.value == "i love koala" && b.value == "i love monkey") {
                return true;
            }
            return this.areEqual(a, b);
        };
});
```

### 핵심 포인트

- Kotlin 문자열 비교는 `Intrinsics.areEqual`
- overload 지정 안 하면 에러 발생 가능
- 여러 시그니처 중 정확한 메소드 지정 필요

------

## 정리 요약

- `Java.use` : 클래스 조작
- `Java.choose` : 기존 인스턴스 조작
- `$new()` : 인스턴스 생성
- implementation : 함수 로직 완전 대체
- 필드 값 변조는 **실행 시점**이 가장 중요