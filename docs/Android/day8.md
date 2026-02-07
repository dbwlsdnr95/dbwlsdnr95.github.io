---
layout: default
title: "Android 보안 8일차"
parent: Android
nav_order: 8
---

# 정적 분석 정리 (Crypto · Smali · APK 변조)

------

## 정적분석 4번  AES/CBC 기반 암호화 구조 분석

### 1. 암호화 로직 구조

- 암호화 알고리즘
  - `AES/CBC/PKCS5Padding`
- 암호화 키
  - 문자열: `0123456789abcdef`
  - 바이트 배열 변환  `bArr`
- IV (Initialization Vector)
  - `bArr2`
  - 16바이트 랜덤 값
- 평문 암호화
  - `bArrDoFinal = AES.encrypt(plaintext, key=bArr, iv=bArr2)`

------

### 2. 최종 암호문 포맷

```
Base64( IV(16바이트) + CipherText )
```

- `strEncodeToString`
    `bArr2 + bArrDoFinal`을 Base64 인코딩한 문자열

------

### 3. 복호화 절차

1. Base64 디코딩
2. 앞 16바이트 분리  IV
3. 나머지 바이트  암호문
4. AES/CBC/PKCS5Padding 복호화
5. 원문 획득

------

### 4. 실제 분석 데이터

#### 저장 위치

```
/data/data/패키지명/shared_prefs/app_prefs.xml
```

#### 암호화된 플래그

```
iDigXohA4nl1YXWRdNo0LaecV/7XAfeEjRjfyga8OzMS7rxHBmsm5wz/HjTQkqiY
```

------

### 5. Base64 디코딩 결과 (Hex)

```
88 38 a0 5e 88 40 e2 79 75 61 75 91 74 da 34 2d
a7 9c 57 fe d7 01 f7 84 8d 18 df ca 06 bc 3b 33
12 ee bc 47 06 6b 26 e7 0c ff 1e 34 d0 92 a8 98
```

- IV (16바이트)

```
88 38 a0 5e 88 40 e2 79 75 61 75 91 74 da 34 2d
```

- 암호문

```
a7 9c 57 fe d7 01 f7 84 8d 18 df ca 06 bc 3b 33
12 ee bc 47 06 6b 26 e7 0c ff 1e 34 d0 92 a8 98
```

------

### 6. 복호화 정보 요약

| 항목     | 값                   |
| -------- | -------------------- |
| 알고리즘 | AES/CBC/PKCS5Padding |
| 키       | 0123456789abcdef     |
| IV       | 앞 16바이트          |
| 암호문   | 나머지 바이트        |
| 결과     | 평문 플래그          |

------

## 정적분석 5번  AES/GCM + PBKDF2 구조 분석

------

### 1. 암호화 흐름

```
encrypt(평문)
  encrypt(평문, "eqst_lms")
```

------

### 2. 난수 값 생성

- `bArr[16]`
  - 16바이트 랜덤 Salt
- `bArr2[12]`
  - 12바이트 랜덤 IV

------

### 3. 키 파생 (Key Derivation)

```
PBEKeySpec("eqst_lms", salt, 150000, 256)
```

- 알고리즘
  - PBKDF2WithHmacSHA256
  - (일부 구현에서는 PBKDF2WithHmacSHA1 사용)

------

### 4. 암호화 알고리즘

- `AES/GCM/NoPadding`
- `GCMParameterSpec(128, bArr2)`

------

### 5. 최종 암호문 포맷

```
01 | Salt(16) | IV(12) | CipherText | GCM Tag
```

- 전체를 Base64 인코딩하여 반환

------

### 6. 암호문 예시

```
AZ/oUGgQWbCw9isMhikWIkSrSfGQuG+YU82+0jgKjb0bGfwtRWmne9Wku1y7Tyg/c99gKAYGPuIAvTVfdg==
```

------

### 7. Base64 디코딩 결과 (Hex)

```
01
9f e8 50 68 10 59 b0 b0 f6 2b 0c 86 29 16 22 44
ab 49 f1 90 b8 6f 98 53 cd be d2 38
0a 8d bd 1b 19 fc 2d 45 69 a7 7b d5 a4 bb 5c bb
4f 28 3f 73 df 60 28 06 06 3e e2 00 bd 35 5f 76
```

------

### 8. 데이터 분리

- 버전

```
01
```

- Salt (16바이트)

```
9f e8 50 68 10 59 b0 b0 f6 2b 0c 86 29 16 22 44
```

- IV (12바이트)

```
ab 49 f1 90 b8 6f 98 53 cd be d2 38
```

- 암호문

```
0a 8d bd 1b 19 fc 2d 45 69 a7 7b d5 a4 bb 5c bb
```

- GCM Tag

```
4f 28 3f 73 df 60 28 06 06 3e e2 00 bd 35 5f 76
```

------

## Smali 코드 분석 및 APK 변조

------

### Smali 분석 특징

- dex  smali 변조 가능
- Java 코드 직접 변조는 불가
- smali 수정 후 재빌드 필요

------

### APK 변조 흐름

1. APK 디컴파일
2. Java 코드 기준으로 로직 분석
3. 대응되는 `.smali` 코드 탐색
4. smali 코드 직접 수정
5. 재빌드 및 재서명
6. 설치 후 실행

------

### Activity 실행

```
am start 액티비티이름
```

------

### CPU ABI 확인

```
Build.CPU_ABI
```

- 예: `arm64-v8a`, `x86_64`

------

### Smali 조건 분기 정리

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
```

------

### CRC 무결성 확인

- 원본 APK `classes.dex` CRC

```
1302005358
```

- 변조된 APK `classes.dex` CRC

```
2993910671
```
