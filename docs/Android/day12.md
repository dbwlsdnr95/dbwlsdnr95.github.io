---
layout: default
title: "Android 보안 12일차"
parent: Android
nav_order: 12
---

Frida Labs 직접 실습

## Challenge 풀이 요약

### 1️⃣ chall01

- 대상 클래스: `challenge_01.chall01`

- 내부 필드 값을 직접 수정하여 **값을 1로 설정**

- 함수 호출 없이 필드 조작만으로 해결

  ```
  Java.perform(() => {
      var chall01 = Java.use("uk.rossmarks.fridalab.challenge_01");
      chall01.chall01.value = 1;
  });
  ```

  

------

### 2️⃣ chall02

- `MainActivity` 인스턴스를 찾아

- `chall02()` 메서드를 **직접 호출**

- 파라미터 없이 호출 시 자동으로 완료

  ```
  Java.perform(function () {
      Java.choose("uk.rossmarks.fridalab.MainActivity", {
          onMatch: function (instance) {
              instance.chall02();
          },
          onComplete: function () { }
      });
  });
  ```

  

------

### 3️⃣ chall03

- 대상 메서드: `MainActivity.chall03()`

- 반환값을 항상 `true`로 **후킹하여 고정**

- 로직 무시 방식

  ```
  Java.perform(() => {
     var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");
      MainActivity.chall03.implementation = function () {
          return true;
  };
  });
  ```

  

------

### 4️⃣ chall04

- `MainActivity.chall04("frida")` 호출

- 문자열 비교 로직을 만족하도록 **입력값 조작**

- 인자 값 `"frida"` 전달로 해결

  ```
  Java.perform(() => {
      Java.choose("uk.rossmarks.fridalab.MainActivity", {
          onMatch(instance) {
              instance.chall04("frida");
          },
          onComplete() {}
      });
  });
  ```

  

------

### 5️⃣ chall05

- `MainActivity.chall05` 메서드 후킹

- 어떤 입력이 오더라도 내부에서 `"frida"`로 치환

- 입력 무력화 방식

  ```
  Java.perform(() => {
      var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");
  
      MainActivity.chall05.implementation = function (str) {
          return this.chall05("frida");
      };
  });
  ```

  

------

### 6️⃣ chall06

- 앱 실행 후 **10초 대기 (총 11초 이상)**

- `challenge_06.chall06` 내부 값 읽기

- 해당 값을 `MainActivity.chall06(value)`로 전달

- **타이밍 + 값 추출** 조합 문제

  ```
  Java.perform(() => {
      setTimeout(function () {
          const Challenge06 = Java.use("uk.rossmarks.fridalab.challenge_06");
          Java.choose("uk.rossmarks.fridalab.MainActivity", {
              onMatch(instance) {
                  const value = Challenge06.chall06.value;
                  instance.chall06(value);
              },
              onComplete() {}
          });
      }, 11000);
  });
  ```

  

------

### 7️⃣ chall07

- PIN 코드 **0000 ~ 9999 전체 브루트포스**

- `chall07(pin)` 반복 호출

- 성공 조건:

  ```
  completeArr[6] === 1
  ```

- 자동화 스크립트로 해결

  ```
  Java.perform(() => {
      setTimeout(() => {
          Java.choose("uk.rossmarks.fridalab.MainActivity", {
              onMatch(instance) {
  
                  for (let i = 0; i <= 9999; i++) {
                      const pin = ("0000" + i).slice(-4);
  
                      instance.chall07(pin);
  
                      if (instance.completeArr.value[6] === 1) {
                          console.log("[비밀번호 확인] =", pin);
                          break;
                      }
                  }
  
              },
              onComplete() {}
          });
      }, 1000);
  });
  ```

  

------

### 8️⃣ chall08

- 버튼 ID: `check`

- 버튼 텍스트를 `"Confirm"`으로 변경

- 이후 `chall08()` 메서드 호출

- **UI 조작 + 함수 호출** 문제

  ```
  Java.perform(() => {
      const Button = Java.use("android.widget.Button");
      const JString = Java.use("java.lang.String");
      const checkId = Java.use("uk.rossmarks.fridalab.R$id").check.value;
  
      Java.choose("uk.rossmarks.fridalab.MainActivity", {
          onMatch(instance) {
              const view = instance.findViewById(checkId);
              if (!view) return;
  
              const btn = Java.cast(view, Button);
              btn.setText(JString.$new("Confirm"));
          },
          onComplete() {}
      });
  });
  ```

9️⃣ 전체 합친 코드

````
// challenge 1
Java.perform(() => {
    var chall01 = Java.use("uk.rossmarks.fridalab.challenge_01");
    chall01.chall01.value = 1;
});

// challenge 2
Java.perform(function () {
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        onMatch: function (instance) {
            instance.chall02();
        },
        onComplete: function () { }
    });
});

// challenge 3
Java.perform(() => {
   var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");
    MainActivity.chall03.implementation = function () {
        return true;
};
});

// challenge 4
Java.perform(() => {
    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        onMatch(instance) {
            instance.chall04("frida");
        },
        onComplete() {}
    });
});

// challenge 5
Java.perform(() => {
    var MainActivity = Java.use("uk.rossmarks.fridalab.MainActivity");

    MainActivity.chall05.implementation = function (str) {
        return this.chall05("frida");
    };
});

// challenge 6
Java.perform(() => {
    setTimeout(function () {
        const Challenge06 = Java.use("uk.rossmarks.fridalab.challenge_06");
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch(instance) {
                const value = Challenge06.chall06.value;
                instance.chall06(value);
            },
            onComplete() {}
        });
    }, 11000);
});

// challenge 7
Java.perform(() => {
    setTimeout(() => {
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch(instance) {

                for (let i = 0; i <= 9999; i++) {
                    const pin = ("0000" + i).slice(-4);

                    instance.chall07(pin);

                    if (instance.completeArr.value[6] === 1) {
                        console.log("[?????? ???] =", pin);
                        break;
                    }
                }

            },
            onComplete() {}
        });
    }, 1000);
});

// challenge 8
Java.perform(() => {
    const Button = Java.use("android.widget.Button");
    const JString = Java.use("java.lang.String");
    const checkId = Java.use("uk.rossmarks.fridalab.R$id").check.value;

    Java.choose("uk.rossmarks.fridalab.MainActivity", {
        onMatch(instance) {
            const view = instance.findViewById(checkId);
            if (!view) return;

            const btn = Java.cast(view, Button);
            btn.setText(JString.$new("Confirm"));
        },
        onComplete() {}
    });
});

````

