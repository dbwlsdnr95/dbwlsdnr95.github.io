# Frida Labs 실습 정리 (FridaLab)

## 실습 환경

- 대상 앱: **FridaLab (Ross Marks)**
- 분석 방식: **Frida 기반 동적 분석**
- 핵심 기술
  - Java.use
  - Java.choose
  - 메소드 후킹
  - 필드 값 조작
  - UI 제어

------

## Lab 01 — 필드 값 조작

### 목표

- `chall01` 조건을 만족시켜 완료 처리

### 핵심 포인트

- `chall01`은 **static 필드**
- 메소드 호출 없이 **값만 바꾸면 해결**

### Frida 스크립트

```
Java.perform(() => {
    var chall01 = Java.use("uk.rossmarks.fridalab.challenge_01");
    chall01.chall01.value = 1;
});
```

------

## Lab 02 — 인스턴스 메소드 호출

### 목표

- `chall02()` 메소드 직접 호출

### 핵심 포인트

- static 아님 → `Java.use` 불가
- **이미 생성된 MainActivity 인스턴스 필요**
- `Java.choose()` 사용

### Frida 스크립트

```
Java.perform(() => {
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        onMatch: function (ins) {
            ins.chall02();
        },
        onComplete: function () {}
    });
});
```

------

## Lab 03 — 리턴값 강제 변경

### 목표

- `chall03()` 결과를 무조건 성공 처리

### 핵심 포인트

- 메소드 후킹
- 리턴값을 `true`로 하드코딩

### Frida 스크립트

```
Java.perform(() => {
    var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");
    MainActivity.chall03.implementation = function () {
        return true;
    };
});
```

------

## Lab 04 — Activity 생성 타이밍 제어

### 목표

- `chall04("frida")`를 정확한 시점에 호출

### 핵심 포인트

- Activity 생성 직후 실행 필요
- `onCreate()` 후킹 + `Java.choose()`

### Frida 스크립트

```
Java.perform(() => {
    var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");

    MainActivity.onCreate.implementation = function (bundle) {
        this.onCreate(bundle);

        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function (ins) {
                ins.chall04("frida");
            },
            onComplete: function () {}
        });
    };
});
```

------

## Lab 05 — 인자 값 강제 변경

### 목표

- `chall05(String str)` 조건 만족

### 핵심 포인트

- 함수 인자 값을 **실행 중 조작**
- 항상 `"frida"` 전달

### Frida 스크립트

```
Java.perform(() => {
    var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");

    MainActivity.chall05.implementation = function (str) {
        return this.chall05("frida");
    };
});
```

------

## Lab 06 — 누적 값 조건 우회

### 목표

- `chall06` 값이 특정 범위를 넘기지 않도록 제어

### 핵심 포인트

- 내부에서 랜덤 값이 계속 누적됨
- 조건 초과 시 값 리셋됨
- **add 함수 후킹 or 값 직접 조작**으로 해결 가능

```
0 + 43 = 43 + 49 = 92 +14 = 106 +52 = 158 ...... 13 9002 9015  X -> 13
    public static void addChall06(int i) {
        chall06 += i;
        if (chall06 > 9000) {
            chall06 = i;
        }
    }
1초마다 랜덤한 1~50숫자 뽑아서 addChall06(숫자) 계속 실행해~
        challenge_06.addChall06(new Random().nextInt(50) + 1);
        new Timer().scheduleAtFixedRate(new TimerTask() { // from class: uk.rossmarks.fridalab.MainActivity.2
            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                int iNextInt = new Random().nextInt(50) + 1;
                challenge_06.addChall06(iNextInt);

            }
        }, 0L, 1000L);
```



------

## Lab 07 — 내부 비밀값 추출

### 목표

- 내부에 저장된 비밀번호 확인 후 전달

### 핵심 포인트

- static 필드에 값 저장됨
- 값을 읽어서 그대로 메소드에 전달

### Frida 스크립트

```
Java.perform(() => {
    var chall07 = Java.use("uk.rossmarks.fridalab.challenge_07");
    var password = chall07.chall07.value;

    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        onMatch: function (ins) {
            ins.chall07(password);
        },
        onComplete: function () {}
    });
});
```

------

## Lab 08 — UI 동적 조작

### 목표

- 버튼 텍스트를 `"Confirm"`으로 변경

### 핵심 포인트

- UI 조작은 **Main Thread 필수**
- `onResume()` 후킹
- `findViewById()` → Button → `setText()`

### Frida 스크립트

```
Java.perform(function () {
    const Activity = Java.use("android.app.Activity");
    const Button = Java.use("android.widget.Button");
    const StringCls = Java.use("java.lang.String");

    Activity.onResume.implementation = function () {
        this.onResume();

        Java.scheduleOnMainThread(() => {
            const res = this.getResources();
            const pkg = this.getPackageName();
            const id = res.getIdentifier("check", "id", pkg);

            if (id !== 0) {
                const btn = Java.cast(this.findViewById(id), Button);
                btn.setText(StringCls.$new("Confirm"));
            }
        });
    };
});
```

------

## 종합 정리

### Frida Labs 핵심 포인트

- **Java.use**
  - 클래스 설계도 수정
  - 메소드 구현 변경
- **Java.choose**
  - 이미 생성된 인스턴스 제어
- **동적 분석의 장점**
  - 무결성 검사 우회
  - 조건 분기 강제 통과
  - UI / 로직 실시간 조작 가능
- **실무 활용**
  - CTF 문제 풀이
  - 모바일 앱 취약점 검증
  - 보안 솔루션 우회 분석