---
layout: default
title: "AWS 1일차"
parent: AWS
nav_order: 2
---

# ☁️ AWS Basic → IAM 전체 정리

# #1. 클라우드 컴퓨팅 기본 개념

test

## 🌐 클라우드 컴퓨팅이란?

> **필요한 IT 자원을 인터넷을 통해 필요할 때 즉시 제공받는 서비스**

특징:

- 온디맨드(On-Demand)
- 탄력성(Elasticity)
- 확장성(Scalability)
- 사용한 만큼만 비용 지불(Pay-as-you-go)
- 관리 부담 감소 (AWS가 인프라 운영)

------

# #2. 클라우드 배포 모델

### ☁️ Public Cloud

- AWS, Azure, GCP 등
- 다수 고객이 공유 인프라를 사용
- 저렴하고 확장 쉬움

### 🏢 Private Cloud

- 기업 내부 전용 클라우드
- 높은 보안, 비용은 큼

### 🔁 Hybrid Cloud

- Public + Private 조합
- 민감한 데이터는 Private, 나머지는 Public

------

# #3. AWS 글로벌 인프라

## 🌍 리전(Region)

- AWS 인프라가 있는 물리적 위치 (한국: **ap-northeast-2**)
- 재해 대비/법적 규제/지연 시간 고려하여 선택

## 🏢 가용 영역(AZ, Availability Zone)

- 같은 리전 내의 독립적인 데이터센터
- 장애 대비 위해 최소 2개 AZ 사용 권장

## 🌐 Edge Location

- CloudFront CDN이 사용하는 전 세계 캐시 서버

------

# #4. AWS 공유 책임 모델 (Shared Responsibility Model)

## 🛡 AWS 책임 (Security **of** the Cloud)

- 하드웨어, 네트워크, 물리적 보안
- 가상화 계층 관리

## 👤 고객 책임 (Security **in** the Cloud)

- IAM 권한 관리
- OS, 애플리케이션 보안 패치
- 데이터 보호, 암호화 설정

> 즉, AWS는 인프라를, 고객은 설정을 책임진다.

------

# #5. AWS 핵심 서비스(간단 정리)

| 영역       | 서비스              | 설명                  |
| ---------- | ------------------- | --------------------- |
| Compute    | **EC2**             | 가상 서버             |
| Storage    | **S3**              | 객체 스토리지         |
| Database   | **RDS / DynamoDB**  | 관계형 / NoSQL DB     |
| Networking | **VPC**             | 네트워크 구성         |
| Security   | **IAM / KMS / WAF** | 권한, 암호화, 웹 보안 |

------

# #6. IAM (Identity and Access Management)

IAM은 AWS 리소스에 대한 접근을 제어하는 **보안 핵심 서비스**이다.

------

# ## IAM 구성 요소

## 👤 1. 사용자(User)

- 사람 또는 시스템용 계정
- 비밀번호(콘솔), Access Key(API/CLI) 사용 가능

------

## 👥 2. 그룹(Group)

- 여러 사용자에게 동일 권한을 부여하기 위한 묶음
- 그룹 자체로 로그인은 불가

------

## 🔐 3. 정책(Policy)

AWS에서 가장 중요한 부분.

- JSON 형태의 **권한 문서**
- “누가 무엇을 할 수 있는지” 정의

### 예시 (S3 ReadOnly 정책)

```
{
  "Effect": "Allow",
  "Action": ["s3:Get*", "s3:List*"],
  "Resource": "*"
}
```

------

## 🆔 4. 역할(Role)

- 사람이 사용하지 않음
- AWS 리소스가 다른 AWS 서비스에 접근할 수 있도록 하는 자격증명

예:

- EC2 → S3 접근을 허용하는 IAM Role
- Lambda → DynamoDB 접근 허용 Role

------

# ## IAM 보안 베스트 프랙티스

### 1️⃣ Root 계정 사용 금지

- MFA 활성화 후 보관
- 결제, 계정 설정 외에는 사용하지 않음

### 2️⃣ 최소 권한 원칙(Least Privilege)

- 필요한 리소스만 최소 권한으로 허용

### 3️⃣ MFA 활성화

- 사용자별 MFA 적용 필수

### 4️⃣ Access Key 노출 금지

- 사용하지 않는 키는 즉시 삭제
- 역할(Role) 우선 사용

### 5️⃣ CloudTrail 활성화

- IAM 변경 사항 및 API 호출 기록 모니터링

------

# ## IAM 정책 유형

| 정책 타입        | 설명                              |
| ---------------- | --------------------------------- |
| AWS 관리형 정책  | AWS가 제공하는 표준 정책          |
| 고객 관리형 정책 | 직접 정의한 JSON 정책             |
| 인라인 정책      | 특정 사용자/역할/그룹에 직접 삽입 |

------

# ## IAM 인증 방식

| 방식            | 설명                        |
| --------------- | --------------------------- |
| 비밀번호        | 콘솔 로그인                 |
| Access Key      | CLI/API 요청                |
| Temporary Token | STS를 통한 일시적 권한 부여 |

------

# ## IAM 핵심 서비스 연결 흐름

```
User → IAM User → Policy → API/Console → AWS Resource
```

역할(Role) 사용 시:

```
EC2 → IAM Role → Policy → AWS Resource
```

------

# #7. IAM 관련 AWS 시험 포인트

- IAM은 리전(global) 서비스이다 (전 세계 동일하게 적용)
- 최소 권한 모델 기반 운영(LP: Least Privilege)
- Root 계정은 가능한 한 사용하지 않는다
- 사용자 그룹으로 권한을 관리하는 것이 효율적
- EC2 인스턴스에 Access Key 넣지 말 것 → 반드시 **IAM Role** 사용

시험에 아주 자주 나오는 포인트들이다.

------

# ✅ 마무리 요약

IAM은 AWS 보안의 기초이며,
 다음과 같은 질문에 답할 수 있어야 한다:

- 누가 로그인할 수 있는가? (사용자)
- 어떤 권한을 주는가? (정책)
- 어떤 방식으로 AWS 서비스에 접근하는가? (자격증명)
- 어떤 서비스가 대신 다른 서비스에 접근하는가? (역할)