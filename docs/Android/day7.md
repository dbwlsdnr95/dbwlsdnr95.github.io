---
layout: default
title: "Android 보안 7일차"
parent: Android
nav_order: 7
---

# Android Security – (정적 분석)

> **정적 분석(Static Analysis)**
>  앱을 실행하지 않은 상태에서 **APK를 디컴파일**하여 내부 로직, 암호화 방식, 검증 로직 등을 분석하는 기법

------

## 1. 정적 분석 개요

- 앱 **미실행 상태**
- APK → 디컴파일 → 코드 분석
- 주요 분석 대상
  - Java / Kotlin 코드
  - Smali 코드
  - AndroidManifest.xml
  - 암호화 로직
  - 하드코딩된 키 / 힌트

------

## 2. Smali 코드 분석

### 2.1 Smali란?

- Dalvik VM용 어셈블리 코드
- **ASM(어셈블리)와 유사**
- `classes.dex` → smali 변환

```
add v0, v1
sub v2, v3
jmp :label
```

------

### 2.2 Null 체크 코드

```
Intrinsics.checkNotNullParameter(obj, "param");
```

- Kotlin에서 자동 생성
- **의미**
  - 검증 로직이 많다는 뜻 ❌
  - 단순 NPE 방지용 ⭕
- 디버깅 시 **노이즈가 많아짐**
- 보안 검증과 직접적인 연관은 적음

------

## 3. Java 코드 정적 분석 흐름

### 3.1 기본 분석 순서

```
AndroidManifest.xml
 → Activity 선언
   → onCreate()
     → onClick()
       → 특정 메소드 / 로직
```

------

### 3.2 함수 호출 관계 추적

```
function(arg1, arg2, arg3)
```

- 분석 포인트
  - 이 함수는 **어디서 호출되는가**
  - 외부 입력값이 전달되는가
  - Intent / Extra 포함 여부

------

### 3.3 클래스 구조

```
Intent intent = new Intent(this, MainActivity.class);
Class → Instance
new Class()
```

- Activity는 **클래스 기반 객체**
- 외부 Intent 조작 가능성 확인

------

## 4. 정적 분석 실습 1 – ASCII 배열 복원

- ASCII 값 배열 → 문자열 변환
- 암호화 힌트 은닉용으로 자주 사용

```
[65, 66, 67] → "ABC"
```

------

## 5. 정적 분석 실습 2 – XOR 기반 암호화 분석

### 5.1 코드 핵심

```
UIStyles.INSTANCE.showMessageDialog(
  mainActivity,
  "HINT",
  "appPkg: aos\nTEST_HEX: " +
  encrypter.bytesToHex(
    encrypter2.encrypt(bytes, bArrDeriveKey4)
  )
);
```

------

### 5.2 키 생성 로직 분석

```
String str = appPkg + ":" + hint;
// "aos:CUSTOM_XOR_V1"
byte[] bytes = str.getBytes(UTF_8);
int iCrc32 = crc32(bytes);
```

- CRC32 체크섬 계산
- 결과값에서 **4바이트만 키로 사용**

```
return new byte[]{
  (byte)((iCrc32 >>> 24) & 255),
  (byte)((iCrc32 >>> 16) & 255),
  (byte)((iCrc32 >>> 8) & 255),
  (byte)(iCrc32 & 255)
};
```

### 5.3 최종 키

```
KEY = [f6, 70, 77, 23]
```

------

### 5.4 XOR 암호화 원리

#### 논리 연산 정리

| 연산    | 설명               |
| ------- | ------------------ |
| AND (&) | 둘 다 참일 때만 참 |
| OR (    | )                  |
| XOR (^) | 서로 다를 때만 참  |

```
X ^ X = 0
X ^ 0 = X
(X ^ K) ^ K = X
```

------

### 5.5 암호화 로직

```
for (int i = 0; i < length; i++) {
  bArr[i] =
    (byte)(
      (
        (key4[i & 3] + (i * 11)) & 255
      ) ^ plain[i]
    );
}
```

- 키는 4바이트 반복 사용
- `i * 11` 값이 가변성 추가
- **XOR → 복호화도 동일 로직**

------

## 6. 정적 분석 실습 3 – AES 고정 키/IV

### 6.1 코드

```
byte[] key = "0123456789abcdef".getBytes();
byte[] iv  = "fedcba0123456789".getBytes();

cipher.init(
  Cipher.ENCRYPT_MODE,
  new SecretKeySpec(key, "AES"),
  new IvParameterSpec(iv)
);
```

- 알고리즘: **AES/CBC/PKCS5Padding**
- 키 & IV 하드코딩 ❌

------

### 6.2 복호화 절차

1. Base64 디코딩
2. AES 복호화
3. 결과 평문 획득

```
암호문: tq3mPVo8iY+xHYFinxgt/A==
평문: decrypt_easy
```

------

## 7. 정적 분석 실습 4 – IV 포함 암호문 구조

### 7.1 암호문 구조

```
[ IV (16 bytes) ][ 암호화 데이터 ]
iDigXohA4nl1YXWRdNo0LaecV/7XAfeEjRjfyga8OzMS7rxHBmsm5wz/HjTQkqiY
```

------

### 7.2 복호화 절차

1. Base64 디코딩
2. 앞 16바이트 → IV
3. 나머지 → CipherText
4. AES/CBC/PKCS5Padding 복호화

```
Key: 0123456789abcdef
IV : 암호문 앞 16바이트
```

------

## 8. 정적 분석 핵심 체크리스트

✅ AndroidManifest 내 Exported Activity
 ✅ Intent Extra 권한 검증 여부
 ✅ 하드코딩 키 / IV
 ✅ XOR / CRC32 기반 커스텀 암호화
 ✅ 복호화 가능 여부
 ✅ 힌트 문자열 UI 노출 여부

------

## 9. 핵심 요약

- 정적 분석은 **로직을 이해하는 싸움**
- 암호화라도 **키가 노출되면 무의미**
- XOR 기반 암호화는 대부분 **즉시 복호화 가능**
- AES라도 **키/IV 하드코딩은 치명적**
