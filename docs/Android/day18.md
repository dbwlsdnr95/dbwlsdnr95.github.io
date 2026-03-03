---
layout: default
title: "Android 보안 18일차"
parent: Android
nav_order: 18
---

# EQST LMS Wargame 실습 정리

## 1. 문제 7번  파일 삭제 방지 (unlink 후킹)

### 목적

- 앱이 생성한 파일을 **삭제하지 못하게 막아서** 내용을 확인

### 핵심 아이디어

- `unlink()` 호출 시 **삭제 경로를 다른 경로로 바꿔치기**

### Frida 코드

```
var unlinkAddr = Module.findGlobalExportByName("unlink");
console.log("unlink 주소:", unlinkAddr);

var newPathAddr = Memory.allocUtf8String("/asdf");

Interceptor.attach(unlinkAddr, {
    onEnter: function (args) {
        var delPath = args[0].readCString();
        console.log("삭제 시도 파일:", delPath);

        // 삭제 대상 경로 변경
        args[0] = newPathAddr;

        console.log("변경된 삭제 파일:", args[0].readCString());
    }
});
```

------

## 2. 파일 쓰기 내용 확인 (write 후킹)

### 목적

- 파일에 **무슨 내용이 쓰이는지** 확인

### Frida 코드

```
var writeAddr = Module.findGlobalExportByName("write");
console.log("write 주소:", writeAddr);

Interceptor.attach(writeAddr, {
    onEnter: function (args) {
        // args[0] = fd
        // args[1] = buffer
        // args[2] = length
        var text = args[1].readCString();
        console.log("write 호출 내용:", text);
    }
});
```

------

## 3. 네트워크 해킹 개요

### 통신 종류

- **HTTP**
  - 웹사이트, API, 하이브리드 앱
  - Burp Suite, Postman 사용 가능
- **TCP (Native App)**
  - 게임, 코인, 주식
  - 속도 빠름, 연결 유지
  - 자체 프로토콜 + 암호화

------

## 4. HTTP 통신 가로채기 (Burp 연동)

### PC 프록시 설정

- PC 인터넷 설정  프록시 수동 설정 (IP, Port)

### Android 설정

- Wi-Fi  프록시  수동  PC IP / Port

### Burp 인증서 설치 (Android 6 이하)

1. `https://burp/` 접속
2. CA 인증서 다운로드
3. `cert.der  cert.cer`로 변경
4. 설치

------

## 5. Android 7 이상 HTTPS 가로채기

### 문제

- 사용자 인증서 신뢰 안 함
- SSL Pinning 적용 앱은 Burp 무시

### 해결 개요

1. Burp 인증서를 **시스템 인증서**로 등록
2. `/system/etc/security/cacerts/`에 설치

### 인증서 설치 과정

```
# DER  PEM 변환
openssl x509 -inform DER -in burp.der -out burp.pem

# 해시 추출
openssl x509 -inform PEM -subject_hash_old -in burp.pem

# 파일명 변경
ren burp.pem 9a5ba575.0
# 시스템 파티션 쓰기 가능
adb shell "mount -o rw,remount /system"

# 인증서 복사
adb push 9a5ba575.0 /system/etc/security/cacerts/
```

- 설정  보안  신뢰할 수 있는 자격 증명에서 **Portswigger CA 활성화 확인**

------

## 6. SSL Pinning 개념

### 구조

```
앱  (인증서 고정)  서버
```

- 앱 내부에 서버 인증서를 **하드코딩**
- Burp 인증서로는 통신 불가

### 해결 방법

- **Frida SSL Pinning Bypass**
- Codeshare의 Universal Script 사용

### 간단한 Bypass 예제

```
Java.perform(function () {
    var ArrayList = Java.use("java.util.ArrayList");
    var TrustManager = Java.use("com.android.org.conscrypt.TrustManagerImpl");

    TrustManager.checkTrustedRecursive.implementation = function () {
        console.log("SSL Pinning Bypass");
        return ArrayList.$new();
    };
});
```

------

## 7. Android WebView 디버깅

### 상황

- Activity + WebView 기반 앱

### 방법

- Chrome 접속

```
chrome://inspect
```

- WebView 내부 HTML / JS 확인 가능

------

## 8. TCP 통신 가로채기 개요

### 특징

- `send()`, `recv()` 사용
- 자체 프로토콜
- 암호화 적용 많음

### 예시

```
send  -> {"hash":"qwer="}
recv  -> {"result":"false"}
```

------

## 9. TCP  HTTP 변환 (MITMRelay)

### 목적

- **TCP 통신을 HTTP처럼 Burp에서 분석**

### 구성

```
폰  (TCP)  PC(MITMRelay)  Burp  서버
```

------

## 10. iptables 리다이렉션

### 서버 IP 확인

```
nslookup lab.eqst.co.kr
```

- 예:

```
218.233.105.178:8402
218.233.105.177:8402
```

### iptables 설정

```
iptables -A OUTPUT -t nat -p tcp -d 218.233.105.177 --dport 8402 \
-j DNAT --to-destination 192.168.35.25

iptables -A OUTPUT -t nat -p tcp -d 218.233.105.178 --dport 8402 \
-j DNAT --to-destination 192.168.35.25
```

------

## 11. MITMRelay 실행

```
py mitm_relay.py \
-l 192.168.35.25 \
-p 127.0.0.1:8080 \
-r tcp:8402:218.233.105.178:8402
```

### 의미

- `-l` : 리스닝 주소 (내 PC)
- `-p` : Burp 프록시 주소
- `-r` : 실제 서버로 전달할 목적지

------

## 12. 문제 6번  TCP JSON 데이터

### 전송 데이터

```
{
  "os": "android",
  "Qno": "andtcp1",
  "id": "1234",
  "pw": "1234"
}
```

### 목표

- Burp에서 JSON 수정
- 서버 응답 변화 확인

------

## 13. 핵심 요약

- `unlink()` 후킹  파일 삭제 방지
- `write()` 후킹  파일 내용 확인
- HTTP  Burp 직접 분석
- HTTPS  시스템 인증서 + SSL Pinning 우회
- TCP  iptables + MITMRelay + Burp
- Native 통신은 **Frida + 네트워크 우회** 병행 필요