---
layout: default
title: "java 공부 4일차"
parent: JAVA
nav_order: 5
---

# 조건문 (Conditional Statements)

조건문은 **특정 조건에 따라 서로 다른 코드를 실행**하기 위해 사용한다.
 자바의 대표적인 조건문은 `if`, `switch`, `삼항 연산자`가 있다. 4. 조건문

------

## 1. if 문

### 1.1 if 기본 구조

```
if (condition) {
    // 조건이 참(true)일 때 실행
}
```

- 조건식은 `true` 또는 `false`로 평가됨
- `{}` 안의 코드를 **코드 블록**이라 함

------

### 1.2 if 단독 사용 예제

```
if (age >= 18) {
    System.out.println("성인입니다.");
}
```

- 조건이 참일 경우에만 실행
- 거짓이면 아무 동작도 하지 않음

------

## 2. if - else 문

### 2.1 기본 구조

```
if (condition) {
    // 조건이 참일 때
} else {
    // 조건이 거짓일 때
}
```

- 두 경우 중 **하나만 실행**
- 서로 배타적인 조건에 사용

### 예제

```
if (age >= 18) {
    System.out.println("성인입니다.");
} else {
    System.out.println("미성년자입니다.");
}
```

------

## 3. else if 문

### 3.1 필요성

여러 조건을 **순서대로 비교**해야 할 때 사용
 앞의 조건이 참이면 뒤 조건은 **검사하지 않음**

### 3.2 기본 구조

```
if (condition1) {
    // 실행
} else if (condition2) {
    // 실행
} else {
    // 모두 거짓일 때
}
```

------

### 3.3 예제 (연령 분류)

```
if (age <= 7) {
    System.out.println("미취학");
} else if (age <= 13) {
    System.out.println("초등학생");
} else if (age <= 16) {
    System.out.println("중학생");
} else if (age <= 19) {
    System.out.println("고등학생");
} else {
    System.out.println("성인");
}
```

#### 특징

- **조건은 위에서 아래로 평가**
- **딱 하나의 블록만 실행**

------

## 4. if vs else if vs 여러 if

### 4.1 else if 사용 (서로 연관된 조건)

```
if (condition1) {
} else if (condition2) {
}
```

- 하나만 실행됨

### 4.2 여러 if 사용 (독립 조건)

```
if (condition1) {
}
if (condition2) {
}
```

- 조건이 맞으면 **모두 실행 가능**

------

### 4.3 할인 시스템 예제 (독립 조건)

```
if (price >= 10000) {
    discount += 1000;
}
if (age <= 10) {
    discount += 1000;
}
```

- 여러 할인 **동시 적용 가능**
- 이 경우 `else if` 사용 x

------

## 5. if 문 중괄호 `{}` 생략

### 5.1 생략 가능 조건

```
if (true)
    System.out.println("실행됨");
```

### 5.2 주의점 (버그 유발)

```
if (true)
    System.out.println("실행됨");
    System.out.println("항상 실행됨");
```

###  권장 스타일

```
if (true) {
    System.out.println("실행됨");
    System.out.println("함께 실행");
}
```

- 가독성 
- 유지보수성 

------

## 6. switch 문

### 6.1 switch 기본 구조

```
switch (value) {
    case 1:
        // 실행
        break;
    default:
        // 나머지
}
```

- **값의 일치 여부만 비교**
- 조건식(`>`, `<`) 사용 불가

------

### 6.2 switch 예제

```
switch (grade) {
    case 1:
        coupon = 1000;
        break;
    case 2:
        coupon = 2000;
        break;
    case 3:
        coupon = 3000;
        break;
    default:
        coupon = 500;
}
```

------

### 6.3 break 없는 switch (fall-through)

```
case 2:
case 3:
    coupon = 3000;
    break;
```

- 여러 case를 하나로 묶을 수 있음

------

## 7. if 문 vs switch 문

| 구분   | if 문            | switch 문           |
| ------ | ---------------- | ------------------- |
| 조건   | 논리식 가능      | 값 비교만           |
| 범위   | 넓음             | 제한적              |
| 가독성 | 복잡해질 수 있음 | 특정 값 분기에 적합 |

------

## 8. Java 14 새로운 switch 문

```
int coupon = switch (grade) {
    case 1 -> 1000;
    case 2 -> 2000;
    case 3 -> 3000;
    default -> 500;
};
```

### 특징

- `->` 사용
- 값 반환 가능
- 코드 간결

------

## 9. 삼항 연산자 (조건 연산자)

### 9.1 기본 형태

```
(조건) ? 참_표현식 : 거짓_표현식
```

### 예제

```
String status = (age >= 18) ? "성인" : "미성년자";
```

### 특징

- if-else를 한 줄로 표현
- **표현식만 가능** (코드 블록 x)

------

## 10. 문제 풀이 핵심 정리

### 10.1 학점 계산

```
if (score >= 90) {
    System.out.println("A");
} else if (score >= 80) {
    System.out.println("B");
} else {
    System.out.println("F");
}
```

------

### 10.2 거리별 이동 수단

```
if (distance <= 1) {
    System.out.println("도보");
} else if (distance <= 10) {
    System.out.println("자전거");
}
```

------

### 10.3 삼항 연산자 활용

```
int max = (a > b) ? a : b;
String result = (x % 2 == 0) ? "짝수" : "홀수";
```

------

##  최종 정리

- **if / else if**  조건 분기
- **여러 if**  독립 조건
- **switch**  특정 값 분기
- **삼항 연산자**  단순 조건 처리
- **중괄호는 항상 사용하는 것이 안전**
