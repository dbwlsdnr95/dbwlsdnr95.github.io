---
layout: default
title: "AWS 2일차"
parent: AWS
nav_order: 3
---

# Elastic Load Balancing & Auto Scaling

## 시스템 아키텍처 핵심 개념

### 확장성 (Scalability)

- **수직 확장 (Vertical Scaling)**
  - 인스턴스 사양 자체를 상향
  - 예: t2.micro → t2.large
  - 시스템 중단 필요
- **수평 확장 (Horizontal Scaling)**
  - 인스턴스 개수 자체를 증가
  - 시스템 중단 없이 확장 가능
  - 클라우드 환경에서 일반적으로 사용

------

### 고가용성 (High Availability)

- 장애 상황에서도 지속적으로 정상 서비스 제공
- 여러 **가용 영역(AZ)** 에 시스템 분산 배치
- 하나의 AZ 장애 시 다른 AZ에서 서비스 유지

------

### 느슨한 결합 (Loosely Coupled Architecture)

- 한 구성 요소 장애가 다른 요소에 최소한만 영향
- 로드 밸런서를 통해 트래픽 분산
- 확장성과 장애 대응에 유리

------

## Elastic Load Balancing (ELB)

### 로드 밸런서 개요

- 네트워크 트래픽을 여러 대상에 자동 분산
- 비정상 대상은 자동으로 트래픽 제외
- 대상이 정상화되면 자동 복구

------

### ELB 종류

#### Application Load Balancer (ALB)

- L7 (HTTP/HTTPS)
- URL, 헤더 기반 라우팅
- 웹 애플리케이션에 적합

#### Network Load Balancer (NLB)

- L4 (TCP/UDP/TLS)
- 대규모 트래픽 처리
- 초저지연 네트워크

#### Classic Load Balancer

- 이전 세대 로드 밸런서
- EC2-Classic 환경 전용

#### Gateway Load Balancer (GWLB)

- L3/L4
- 방화벽, IDS/IPS 같은 보안 어플라이언스 연동
- GENEVE 프로토콜 사용

------

### Target Group 구성

- 트래픽을 전달할 대상의 집합
- 대상 유형
  - EC2 인스턴스
  - Auto Scaling Group
  - IP 주소
  - Lambda 함수

### Health Check

- 대상의 정상 여부 주기적 확인
- 비정상 대상은 자동 제외

------

## EC2 Auto Scaling

### 개요

- 트래픽 수요에 따라 EC2 인스턴스를 자동으로 확장/축소
- Scale Out / Scale In 자동 수행

------

### Auto Scaling 구성 요소

- **Auto Scaling Group**
- **Launch Template**
- **조정 정책 (Scaling Policy)**

------

### 조정 방식

#### 고정 용량 유지

- 항상 동일한 인스턴스 수 유지

#### 수동 조정

- 최소/최대/원하는 용량 직접 설정

#### 일정 기반 조정

- 특정 시간·요일 기준 확장

#### 동적 조정 (Dynamic Scaling)

- CPU, 네트워크 등 지표 기반

##### Target Tracking

- 목표 지표 유지 (예: CPU 50%)

##### Step Scaling

- 단계별 증가/감소

##### Simple Scaling

- 단순 경보 기반 조정

#### 예측 조정 (Predictive Scaling)

- 머신러닝 기반 용량 예측

------

### Auto Scaling 장점

- 비용 최적화
- 장애 인스턴스 자동 교체
- Multi-AZ 기반 고가용성

------

# Serverless 컴퓨팅

## Serverless 개념

- 서버 운영/관리 불필요
- 인프라 운영은 AWS가 담당
- 사용자는 코드와 비즈니스 로직에만 집중

### 대표 서비스

- AWS Lambda
- AWS Fargate
- Amazon S3
- DynamoDB
- Aurora Serverless
- SNS / SQS / API Gateway

------

## AWS Lambda

### Lambda 개요

- 이벤트 기반 서버리스 컴퓨팅
- 요청이 있을 때만 실행
- 실행 횟수 + 실행 시간 기반 과금

------

### Lambda 특징

- 서버 관리 불필요
- 자동 확장
- 다양한 언어 지원
  - Python, Node.js, Java, C#, Ruby 등

------

### Lambda 연계 구조

- 단독 사용보다 서비스 결합이 일반적
- 주요 연계 서비스
  - S3
  - API Gateway
  - DynamoDB
  - SNS / SQS
  - CloudFront

------

# 배치 & 컨테이너 컴퓨팅

## AWS Batch

### 개요

- 대규모 배치 작업 실행 서비스
- 작업량에 따라 리소스 자동 프로비저닝
- Docker 컨테이너 기반 실행

### 활용 사례

- 생명과학 분석
- 영상 렌더링
- 대규모 데이터 처리

------

## 컨테이너 개념

### Container

- 애플리케이션과 라이브러리를 패키징
- OS 환경과 무관하게 실행 가능
- 독립적인 실행 환경
- 마이크로서비스 아키텍처에 적합

------

## AWS 컨테이너 서비스

### Amazon ECS (Elastic Container Service)

- AWS 자체 컨테이너 오케스트레이션
- Docker 기반
- 간단한 운영

------

### Amazon EKS (Elastic Kubernetes Service)

- AWS 관리형 Kubernetes
- 대규모 컨테이너 워크로드에 적합
- 오픈소스 Kubernetes 사용

------

### AWS Fargate

- 서버리스 컨테이너 실행 환경
- 서버/클러스터 관리 불필요
- ECS 및 EKS와 함께 사용

------

## 컨테이너 서비스 비교 요약

| 구분           | ECS      | EKS        | Fargate   |
| -------------- | -------- | ---------- | --------- |
| 오케스트레이션 | AWS 자체 | Kubernetes | 서버리스  |
| 서버 관리      | 필요     | 필요       | 불필요    |
| 난이도         | 낮음     | 높음       | 매우 낮음 |
| 확장성         | 높음     | 매우 높음  | 자동      |

---

## AWS Elastic Beanstalk

### 개요

- **애플리케이션 배포를 자동화**하는 PaaS 서비스
- 인프라 설정 없이 **코드만 업로드**하면 실행 환경 자동 구성

------

### Elastic Beanstalk 특징

- EC2, Auto Scaling, ELB, RDS 등을 **자동으로 프로비저닝**
- 사용자는 애플리케이션 코드에만 집중
- 인프라는 AWS가 관리하지만 **EC2 자체 접근은 가능**

------

### 지원 언어 / 플랫폼

- Java
- .NET
- Python
- Node.js
- PHP
- Ruby
- Go
- Docker

------

### Elastic Beanstalk 요약

- **PaaS**
- 서버 접근 가능
- 빠른 애플리케이션 배포
- 운영 부담 감소

------

### 시험 포인트

- ❌ 서버리스 아님
- ✅ EC2 기반
- ✅ 인프라 자동 관리

------

## Amazon Lightsail

### 개요

- **간단한 가상 서버(VPS)** 서비스
- AWS를 처음 사용하는 사용자 또는 소규모 서비스용

------

### Lightsail 특징

- EC2보다 단순한 UI
- 월 정액 요금
- 서버, 스토리지, 네트워크 패키지 제공
- WordPress, LAMP, Node.js 등 사전 구성 이미지 제공

------

### 사용 사례

- 개인 프로젝트
- 소규모 웹사이트
- 테스트 서버
- 스타트업 초기 서비스

------

### Lightsail 요약

- EC2의 간소화 버전
- 설정이 매우 쉬움
- 대규모 확장에는 부적합

------

### 시험 포인트

- ✅ 초보자용 AWS 서비스
- ❌ 복잡한 인프라 설계용 아님

------

## Amazon WorkSpaces

### 개요

- **클라우드 기반 가상 데스크톱(VDI)** 서비스
- 어디서든 동일한 데스크톱 환경 제공

------

### WorkSpaces 특징

- Windows / Linux 데스크톱 제공
- 기업용 원격 근무 환경
- 로컬 PC 데이터 저장 불필요
- 보안 강화 (데이터 중앙 집중 관리)

------

### 사용 사례

- 재택근무
- 외부 협력사 환경 제공
- 보안이 중요한 업무 환경

------

## Amazon AppStream 2.0

### 개요

- **애플리케이션 스트리밍 서비스**
- 데스크톱 전체가 아닌 **앱 단위 제공**

------

### AppStream 2.0 특징

- 웹 브라우저로 애플리케이션 실행
- 클라이언트 설치 불필요
- 고성능 그래픽 앱 지원

------

### WorkSpaces vs AppStream 2.0

| 항목      | WorkSpaces    | AppStream 2.0 |
| --------- | ------------- | ------------- |
| 제공 범위 | 전체 데스크톱 | 애플리케이션  |
| 사용 방식 | 지속 사용     | 필요 시       |
| 설치      | 필요 없음     | 필요 없음     |
| 목적      | 업무 환경     | 앱 제공       |

------

### 시험 포인트

- 데스크톱 → WorkSpaces
- 앱만 제공 → AppStream 2.0

------

## AWS Outposts

### 개요

- **AWS 인프라를 온프레미스에 설치**
- 하이브리드 클라우드 구성

------

### Outposts 특징

- AWS 서버/스토리지를 고객 데이터센터에 배치
- AWS 콘솔로 동일하게 관리
- 낮은 지연 시간
- 데이터 로컬 처리 요구 사항 충족

------

### 사용 사례

- 금융
- 공공기관
- 제조업
- 데이터 레지던시 요구 환경

------

### 시험 포인트

- ✅ AWS 서비스의 온프레미스 확장
- ❌ 단순 VPN 아님

------

## AWS Wavelength

### 개요

- **5G 네트워크 기반 초저지연 컴퓨팅**
- 통신사 네트워크 내부에 AWS 인프라 배치

------

### Wavelength 특징

- 지연 시간 극소화 (ms 단위)
- 모바일, AR/VR, 자율주행에 적합
- EC2 인스턴스를 통신사 엣지에서 실행

------

### 사용 사례

- 실시간 게임
- AR / VR
- IoT
- 자율주행

------

### 시험 포인트

- 5G
- 초저지연
- 모바일 중심

------

## AWS Local Zones

### 개요

- **AWS 리전을 사용자 가까운 위치로 확장**
- 특정 도시 단위 서비스 제공

------

### Local Zones 특징

- 리전과 연결된 확장 영역
- 지연 시간 최소화
- EC2, EBS, RDS 등 일부 서비스 제공

------

### Wavelength vs Local Zones

| 항목      | Local Zones   | Wavelength         |
| --------- | ------------- | ------------------ |
| 위치      | AWS 확장 지역 | 통신사 5G 네트워크 |
| 목적      | 낮은 지연     | 초저지연           |
| 주요 대상 | 엔터프라이즈  | 모바일/5G          |

------

## 컴퓨팅 서비스 전체 흐름 정리

```
EC2
 ├─ Auto Scaling
 ├─ ELB
 ├─ Elastic Beanstalk
 ├─ Lightsail
 ├─ Lambda
 ├─ Batch
 ├─ ECS / EKS / Fargate
 ├─ WorkSpaces / AppStream
 ├─ Outposts
 ├─ Local Zones
 └─ Wavelength
```

------

## 시험 대비 한 줄 요약

- **Elastic Beanstalk** → 코드만 올리면 배포
- **Lightsail** → 초보자용 VPS
- **WorkSpaces** → 가상 데스크톱
- **AppStream 2.0** → 앱 스트리밍
- **Outposts** → AWS 온프레미스
- **Wavelength** → 5G 초저지연
- **Local Zones** → 도시 단위 저지연

------

- ##  컴퓨팅 서비스 핵심 정리 

  ### 기본 인프라 & 확장

  - **EC2**
    - AWS의 기본 가상 서버
    - 사용자가 OS·패치·보안 직접 관리
    - 유연하지만 운영 부담 큼
  - **ELB (Elastic Load Balancing)**
    - 트래픽을 여러 대상에 자동 분산
    - 장애 인스턴스 자동 제외
    - 고가용성 구성의 핵심
  - **Auto Scaling**
    - 트래픽 변화에 따라 EC2 자동 증감
    - 비용 최적화 + 장애 복구
    - ELB와 함께 사용 시 효과 극대화

  ➡️ **ELB + Auto Scaling = 안정적·확장형 인프라**

  ------

  ### 애플리케이션 배포 & 간소화

  - **AWS Elastic Beanstalk**
    - 코드만 업로드하면 실행 환경 자동 구성
    - EC2, ELB, Auto Scaling을 자동 관리
    - PaaS 개념
    - 서버 접근 가능 (서버리스 아님)
  - **Amazon Lightsail**
    - 초보자용 VPS 서비스
    - 간단한 UI + 월 정액 요금
    - 소규모 웹사이트, 개인 프로젝트에 적합
    - 대규모 확장에는 부적합

  ------

  ### 서버리스 컴퓨팅

  - **AWS Lambda**
    - 이벤트 기반 서버리스 컴퓨팅
    - 서버 관리 불필요
    - 실행한 만큼만 비용 지불
    - 자동 확장

  ➡️ **Lambda = 이벤트 기반 서버리스**

  ------

  ### 배치 & 대규모 연산

  - **AWS Batch**
    - 대규모 배치 작업 처리
    - 작업량에 따라 컴퓨팅 자원 자동 프로비저닝
    - 컨테이너 기반 실행
    - 과학 계산, 렌더링, 대량 데이터 처리에 적합

  ------

  ### 컨테이너 & 마이크로서비스

  - **Amazon ECS**
    - AWS 자체 컨테이너 오케스트레이션
    - Docker 기반
    - 설정과 운영이 비교적 단순
  - **Amazon EKS**
    - 관리형 Kubernetes 서비스
    - 대규모·복잡한 컨테이너 환경에 적합
    - 오픈소스 Kubernetes 사용
  - **AWS Fargate**
    - 서버리스 컨테이너 실행 환경
    - 서버·클러스터 관리 불필요
    - ECS / EKS와 함께 사용

  ➡️ **ECS / EKS / Fargate = 컨테이너 기반 마이크로서비스**

  ------

  ### 가상 데스크톱 & 애플리케이션 제공

  - **Amazon WorkSpaces**
    - 클라우드 가상 데스크톱(VDI)
    - 재택근무·보안 환경에 적합
    - 전체 데스크톱 제공
  - **Amazon AppStream 2.0**
    - 애플리케이션 스트리밍 서비스
    - 데스크톱이 아닌 앱 단위 제공
    - 웹 브라우저로 실행

  ➡️ 데스크톱 → **WorkSpaces**
   ➡️ 앱만 제공 → **AppStream 2.0**

  ------

  ### 하이브리드 & 엣지 컴퓨팅

  - **AWS Outposts**
    - AWS 인프라를 온프레미스에 설치
    - 동일한 AWS 콘솔로 관리
    - 데이터 로컬 처리 및 규제 대응
  - **AWS Local Zones**
    - 특정 도시 단위로 AWS 리전 확장
    - 낮은 지연 시간 제공
    - 엔터프라이즈 워크로드 대상
  - **AWS Wavelength**
    - 통신사 5G 네트워크 내부에 AWS 인프라 배치
    - 초저지연(ms 단위)
    - 모바일·AR/VR·실시간 서비스에 적합

  ------

  ## ✅ Cloud Practitioner 시험 최종 암기 포인트

  - **ELB + Auto Scaling** → 안정적·확장형 인프라
  - **Elastic Beanstalk** → 코드만 업로드하는 PaaS
  - **Lightsail** → 초보자용 VPS
  - **Lambda** → 이벤트 기반 서버리스
  - **Batch** → 대규모 배치 연산
  - **ECS / EKS / Fargate** → 컨테이너 기반 마이크로서비스
  - **WorkSpaces** → 가상 데스크톱
  - **AppStream 2.0** → 애플리케이션 스트리밍
  - **Outposts** → AWS 온프레미스
  - **Local Zones** → 도시 단위 저지연
  - **Wavelength** → 5G 초저지연

  👉 Cloud Practitioner 시험에서 **“서비스 개념 비교 문제”로 매우 자주 출제**
