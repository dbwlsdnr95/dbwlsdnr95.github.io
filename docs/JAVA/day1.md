---
layout: default
title: "java 공부 1일차"
parent: JAVA
nav_order: 2
---

#  Java 입문 - Hello World

##  개발 환경 설정

### IDE 선택

- **IntelliJ IDEA** (추천)
  - 빠른 속도와 편의성
  - 대부분의 회사가 IntelliJ를 사용
- **Eclipse**
  - 과거에는 많이 사용했으나 현재는 비추천

### 운영체제

- Mac을 사용하는 기업이 많지만 **Windows도 문제없음**
- 강의에서는 Mac 기준이지만 Windows 단축키와 화면도 함께 설명됨

------

## IntelliJ 설치 및 설정

1. [JetBrains IntelliJ IDEA 다운로드](https://www.jetbrains.com/ko-kr/idea/download)
2. **Community Edition (무료 버전)** 선택
3. OS에 맞는 버전 다운로드
   - Windows  `.exe`
   - macOS (M1/M2/M3)  Apple Silicon

------

## 새 프로젝트 만들기

**New Project 설정**

- Name: `java-start`
- Location: 원하는 폴더
- Language: Java
- Build System: IntelliJ
- JDK: 17 이상
- Add sample code:  체크

**JDK 설치**

- Version: `21`
- Vendor: `Oracle OpenJDK` 또는 `Eclipse Temurin`
- Location: 기본값 유지

------

## 첫 실행

1. 프로젝트 생성 후 자동으로 `Main.java`가 생성됨
2. 초록색  버튼 클릭  `Run 'Main.main()'`
3. 콘솔에 `Hello World!` 출력

> 참고: Java 25 이상에서는 `System.out.println()` 대신 `IO.print()`도 사용 가능함1. Hello World.

------

## 자바 코드 구조 이해

```
public class HelloJava {
    public static void main(String[] args) {
        System.out.println("hello java");
    }
}
```

### 주요 구성

| 구문                                     | 설명            |
| ---------------------------------------- | --------------- |
| `public class HelloJava`                 | 클래스 선언     |
| `public static void main(String[] args)` | 프로그램 시작점 |
| `System.out.println()`                   | 콘솔 출력 명령  |
| `;`                                      | 문장 끝 구분자  |

**실행 과정**

1. 프로그램 시작
2. `main()` 실행
3. `"hello java"` 출력
4. 종료

------

##  주석(Comment)

- **한 줄 주석**: `//`
- **여러 줄 주석**: `/* ... */`

```
public class CommentJava {
    public static void main(String[] args) {
        // 한 줄 주석
        /* 여러 줄 주석 */
        System.out.println("hello java");
    }
}
```

> 주석은 프로그램에 영향을 주지 않으며, 사람이 읽기 위한 설명용이다1. Hello World.

##  자바란?

자바는 **표준 스펙**과 **구현체**로 구성됨.

| 표준 스펙          | 구현체 예시     |
| ------------------ | --------------- |
| 자바 컴파일러, JVM | Oracle OpenJDK  |
|                    | Eclipse Temurin |
|                    | Amazon Corretto |

 모두 **서로 호환 가능**
  OpenJDK에서 Temurin으로 바꿔도 대부분 문제 없이 동작

------

## 컴파일과 실행 과정

1. `.java` (소스 코드)  `javac` 컴파일러  `.class` (바이트코드)
2. `.class` 실행 시  JVM(Java Virtual Machine)이 작동

```
javac Hello.java
java Hello
```

> IntelliJ에서는 이 과정이 자동으로 처리됨.

##  자바와 OS 독립성

| 일반 프로그램           | 자바 프로그램                |
| ----------------------- | ---------------------------- |
| OS 전용 실행파일 (.exe) | JVM 위에서 실행되는 `.class` |
| OS 간 호환 불가         | 모든 OS에서 실행 가능        |

즉,
 Windows에서 작성한 Java 코드  Mac/Linux에서도 실행 가능.
 운영체제 호환 문제를 **JVM이 해결**해 준다1. Hello World.

------

## 개발과 배포 환경

| 구분    | 환경          | 설명                           |
| ------- | ------------- | ------------------------------ |
| 개발 PC | Windows / Mac | OpenJDK 사용                   |
| 서버    | Linux         | Amazon Corretto 자바 사용 가능 |

자바의 운영체제 독립성 덕분에
 **개발 환경과 서버 환경이 달라도 문제 없이 동작**한다1. Hello World.

------

## 정리

- IntelliJ + JDK 21 설치 후 시작
- `HelloJava.java` 파일로 첫 코드 실행
- 자바는 **한 번 작성, 어디서나 실행 (Write Once, Run Anywhere)** 언어
- 학습 초기에는 **Eclipse Temurin 21** 사용 권장