---
layout: default
title: "Android 보안 3일차"
parent: Android
nav_order: 3
---

#  Android 기본 컴포넌트 및 보안 분석 정리

##  Android Component

| 컴포넌트              | 역할                       | 예시                                                 |
| --------------------- | -------------------------- | ---------------------------------------------------- |
| **Activity**          | 사용자 화면(UI) 구성       | 로그인 액티비티, 친구 목록 액티비티, 대화창 액티비티 |
| **Service**           | 백그라운드 실행 기능       | 음악 재생, 파일 다운로드 등                          |
| **ContentProvider**   | 저장된 데이터 공유 및 전달 | 주소록, 메모, 앱 간 데이터 공유                      |
| **BroadcastReceiver** | 이벤트 감지 및 처리        | 배터리 상태, 네트워크 변화 등                        |

------

##  exported 속성

- `android:exported="false"`  외부 앱에서 접근 불가
- `android:exported="true"`  다른 앱에서도 호출 가능 (주의 필요)

예시:

```
<activity
    android:name=".MainActivity"
    android:exported="false" />
```

------

##  예시 앱 구조

| 앱           | 주요 기능              |
| ------------ | ---------------------- |
| **전화앱**   | 통화, 연락처 접근      |
| **카카오톡** | 메신저, 친구목록, 대화 |

------

##  Logcat (로그 출력)

- **로그 확인**
   Android Studio  `Logcat` 창
   또는 ADB 명령어:

  ```
  adb logcat
  ```

- **출력 예시**

  ```
  I/MainActivity: 로그인 성공
  E/Database: Connection failed
  ```

------

##  데이터 저장소 구조

| 저장 방식             | 경로                                  | 설명                                    |
| --------------------- | ------------------------------------- | --------------------------------------- |
| **SharedPreferences** | `/data/data/<패키지명>/shared_prefs/` | 간단한 key-value 저장 (예: 로그인 정보) |
| **SQLite Database**   | `/data/data/<패키지명>/databases/`    | 구조화된 데이터 저장                    |
| **Sandbox**           | 앱별 독립 저장 공간                   | 앱 간 접근 제한                         |

------

##  SharedPreferences 예시

- 저장:

  ```
  SharedPreferences pref = getSharedPreferences("userInfo", MODE_PRIVATE);
  pref.edit().putString("id", "user123").apply();
  ```

- 파일 예시 (`userInfo.xml`):

  ```
  <map>
      <string name="id">user123</string>
  </map>
  ```

------

##  SQLite Database 분석

- 경로:

  ```
  /data/data/<패키지명>/databases/
  ```

- 접근:

  ```
  adb shell
  cd /data/data/<패키지명>/databases/
  sqlite3 test.db
  .tables
  SELECT * FROM user;
  ```

------

##  메모리 내 중요 정보 분석

| 명령어                          | 설명                        |
| ------------------------------- | --------------------------- |
| `am dumpheap <pid> <경로>`      | 앱 프로세스 메모리 덤프     |
| `strings test.hprof > test.txt` | 메모리 내 문자열 추출       |
| `adb shell ps`                  | 현재 실행중인 프로세스 확인 |

**예시**

```
adb shell ps | grep aos.app017
adb shell am dumpheap 29429 /data/local/tmp/test.hprof
adb shell chmod 777 /data/local/tmp/test.hprof
adb shell strings /data/local/tmp/test.hprof > /sdcard/test.txt
```

------

##  Activity 강제 실행 (Activity Manager)

```
adb shell am start 패키지명/.액티비티이름
```

###  Extra 전달 예시

| 타입    | 옵션   | 예시                    |
| ------- | ------ | ----------------------- |
| Boolean | `--ez` | `--ez check true`       |
| String  | `--es` | `--es title "공지사항"` |
| Integer | `--ei` | `--ei postid 3`         |

**예시 명령:**

```
adb shell am start --es title abc --es content asdf --ei postid 3
```

------

##  리눅스 기본 명령어 요약

| 명령어        | 설명                  |
| ------------- | --------------------- |
| `pwd`         | 현재 경로 출력        |
| `whoami`      | 현재 사용자 확인      |
| `cd`          | 경로 이동             |
| `ls`          | 파일 목록 보기        |
| `cat`         | 파일 내용 보기        |
| `grep`        | 문자열 검색           |
| `ps -ef`      | 실행 중 프로세스 확인 |
| `cp`          | 파일 복사             |
| `mv`          | 파일 이동             |
| `vi`          | 텍스트 편집기         |
| `su` / `sudo` | 루트 권한 실행        |
| `touch`       | 빈 파일 생성          |

------

##  보안 분석 포인트

| 분석 항목         | 설명                                    |
| ----------------- | --------------------------------------- |
| **저장 위치**     | SharedPrefs / SQLite / Internal storage |
| **저장 데이터**   | ID, Token, Password 등                  |
| **저장 방식**     | 암호화 여부 확인                        |
| **복호화 가능성** | CyberChef 등으로 역산 가능성 분석       |

------

##  참고 도구

- **ADB (Android Debug Bridge)**  단말기 제어 및 데이터 추출
- **Logcat**  실시간 로그 모니터링
- **CyberChef**  문자열/암호화 복호화 도구
- **SQLite Browser**  DB 분석 GUI 툴
- **jadx / apktool**  APK 디컴파일 도구

------

###  핵심 기억 포인트

>  앱의 중요한 데이터는 `/data/data/<패키지명>/` 안에 있다
>   `SharedPreferences`, `SQLite`, `ContentProvider` 등 저장소 구조를 파악
>   Activity, Service, Provider, Receiver의 exported 속성 주의
>   Logcat, dumpheap, adb로 동적 정보 추출 가능
