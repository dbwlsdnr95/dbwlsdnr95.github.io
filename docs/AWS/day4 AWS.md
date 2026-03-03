---
layout: default
title: "AWS 4일차"
parent: AWS
nav_order: 5
---

# AWS 네트워크 서비스 (VPC)

------

## 1. Amazon VPC (Virtual Private Cloud)

### 1.1 VPC 개요

- AWS 클라우드 내에서 **논리적으로 격리된 가상 네트워크**
- 사용자가 직접 네트워크 구조를 설계 가능
- IP 주소 범위, 서브넷, 라우팅, 보안 설정 제어

### 핵심 특징

- **리전 단위**로 생성
- CIDR 블록으로 IP 범위 지정
- 완전한 네트워크 제어권 제공

------

## 2. CIDR (Classless Inter-Domain Routing)

### 개요

- IP 주소 범위를 표현하는 방식
- 형식: `IP주소/프리픽스`

### 예시

```
10.0.0.0/16
```

- 총 IP 개수: 65,536
- VPC 생성 시 필수 설정

------

## 3. 서브넷 (Subnet)

### 3.1 개요

- VPC 내부를 나눈 **IP 주소 범위**
- **가용 영역(AZ) 단위**로 생성됨

### 서브넷 유형

- **퍼블릭 서브넷**
  - 인터넷 게이트웨이와 연결
  - EC2에 공인 IP 할당 가능
- **프라이빗 서브넷**
  - 외부 인터넷 직접 접근 불가
  - DB 서버 등에 사용

------

## 4. 인터넷 게이트웨이 (Internet Gateway)

### 개요

- VPC와 인터넷 간 통신을 가능하게 하는 구성 요소

### 특징

- 퍼블릭 서브넷 필수 요소
- 공인 IP가 있는 리소스만 인터넷 접근 가능
- VPC에 **1개만 연결 가능**

------

## 5. 라우팅 테이블 (Route Table)

### 개요

- 네트워크 트래픽의 **경로를 정의**
- 각 서브넷은 반드시 하나의 라우팅 테이블과 연결

### 기본 라우트 예시

```
0.0.0.0/0  Internet Gateway
```

------

## 6. NAT Gateway

### 개요

- **프라이빗 서브넷 리소스가 외부 인터넷에 접근**하도록 지원
- 인바운드 트래픽은 차단

### 특징

- 퍼블릭 서브넷에 위치
- 공인 IP(EIP) 필요
- 관리형 서비스 (고가용성)

------

## 7. 보안 그룹 (Security Group)

### 개요

- **가상 방화벽**
- 인스턴스 수준에서 동작

### 특징

- **상태 저장(Stateful)**
- 허용 규칙만 설정 (거부 규칙 없음)
- 인바운드/아웃바운드 규칙 정의

------

## 8. 네트워크 ACL (NACL)

### 개요

- 서브넷 수준에서 적용되는 보안 정책

### 특징

- **상태 비저장(Stateless)**
- 허용 + 거부 규칙 모두 설정 가능
- 규칙 번호 순서대로 평가

------

## 9. 보안 그룹 vs NACL

| 구분      | 보안 그룹 | NACL        |
| --------- | --------- | ----------- |
| 적용 대상 | 인스턴스  | 서브넷      |
| 상태      | Stateful  | Stateless   |
| 규칙      | 허용만    | 허용 + 거부 |
| 평가 방식 | 전체      | 순서        |

------

## 10. VPC Peering

### 개요

- 두 VPC 간 **프라이빗 통신** 연결

### 특징

- 다른 리전 / 다른 계정 가능
- **전이적 연결 불가**
- CIDR 겹치면 불가

------

## 11. AWS VPN

### 개요

- 온프레미스  AWS VPC 간 **암호화된 연결**

### 유형

- **Site-to-Site VPN**
- **Client VPN**

------

## 12. AWS Direct Connect

### 개요

- 온프레미스와 AWS 간 **전용 회선 연결**

### 특징

- 안정적
- 낮은 지연 시간
- 대규모 트래픽에 적합

------

## 13. VPC 엔드포인트 (VPC Endpoint)

### 개요

- 인터넷을 거치지 않고 AWS 서비스에 연결

### 유형

- **Gateway Endpoint**
  - S3, DynamoDB
- **Interface Endpoint**
  - PrivateLink 기반
  - 대부분 AWS 서비스

------

## 14. Elastic Load Balancing (ELB)

### 개요

- 트래픽을 여러 대상에 분산

### 유형

- **ALB (Application Load Balancer)**
  - HTTP/HTTPS
  - Layer 7
- **NLB (Network Load Balancer)**
  - TCP/UDP
  - 고성능
- **CLB**
  - 레거시

------

## 15. Route 53 (DNS 서비스)

### 개요

- AWS의 **관리형 DNS 서비스**

### 주요 기능

- 도메인 등록
- 트래픽 라우팅
- 헬스 체크

------

## 16. 네트워크 아키텍처 핵심 정리 (시험 포인트)

- VPC = 가상 네트워크
- Subnet = AZ 단위
- Public Subnet = IGW 연결
- Private Subnet = NAT Gateway
- Security Group = 인스턴스 방화벽
- NACL = 서브넷 방화벽
- Direct Connect = 전용 회선
- VPC Endpoint = 인터넷 없이 AWS 서비스 접근

------

## 17. Amazon CloudFront

### 17.1 개요

- AWS의 **CDN(Content Delivery Network)** 서비스
- 전 세계에 분산된 **엣지 로케이션(Edge Location)** 을 통해 콘텐츠 제공
- 사용자와 가장 가까운 위치에서 콘텐츠 전달  **지연 시간 감소**

------

### 17.2 제공 콘텐츠 유형

- **정적 콘텐츠**
  - 이미지, CSS, JS, HTML
- **동적 콘텐츠**
  - API 응답
  - 로그인 페이지
  - 실시간 데이터

------

### 17.3 주요 구성 요소

- **Origin**
  - 원본 서버
  - S3, EC2, ALB, 외부 서버 가능
- **Distribution**
  - CloudFront 설정 단위
  - Web Distribution 사용
- **Edge Location**
  - 캐시 저장 위치
  - 사용자 요청을 최초로 처리

------

### 17.4 보안 기능

- HTTPS 기본 지원
- **AWS Shield Standard** 기본 제공
- **AWS WAF 연동 가능**
- **서명된 URL / 서명된 쿠키**
  - 콘텐츠 접근 제어

------

### 17.5 사용 사례

- 글로벌 정적 웹 사이트
- 미디어 스트리밍
- API 가속
- 트래픽 폭증 대응

------

## 18. AWS Global Accelerator

### 18.1 개요

- AWS 글로벌 네트워크 기반 **애플리케이션 가속 서비스**
- 사용자  가장 가까운 엣지  AWS 백본 네트워크

------

### 18.2 주요 특징

- **고정 Anycast IP 주소 제공**
- TCP / UDP 트래픽 가속
- 상태 기반 헬스 체크
- 자동 장애 조치

------

### 18.3 CloudFront vs Global Accelerator

| 항목      | CloudFront  | Global Accelerator       |
| --------- | ----------- | ------------------------ |
| 목적      | 콘텐츠 전달 | 네트워크 가속            |
| 캐싱      | O           | X                        |
| 프로토콜  | HTTP/HTTPS  | TCP/UDP                  |
| IP 주소   | 변경 가능   | 고정 Anycast             |
| 사용 대상 | 웹 콘텐츠   | 게임, API, 실시간 서비스 |

------

## 19. AWS 요금 모델 (Pricing)

### 19.1 기본 원칙

- **Pay-As-You-Go**
- 선불 없음
- 사용량 기반 과금

------

### 19.2 비용에 영향을 주는 요소

- 컴퓨팅 사용량
- 스토리지 사용량
- 데이터 전송량 (특히 아웃바운드)

------

## 20. AWS 구매 옵션

### 20.1 온디맨드(On-Demand)

- 사용한 만큼 지불
- 약정 없음
- 단기·테스트 환경에 적합

------

### 20.2 예약 인스턴스 (Reserved Instances)

- 1년 / 3년 약정
- 최대 **72% 비용 절감**
- 예측 가능한 워크로드

------

### 20.3 Savings Plans

- 사용량 기반 약정
- EC2, Fargate, Lambda 적용
- 인스턴스 유형 변경 가능

------

### 20.4 스팟 인스턴스 (Spot)

- 유휴 자원 활용
- 최대 **90% 할인**
- 중단 가능  배치 작업에 적합

------

## 21. AWS 비용 관리 도구

### 21.1 AWS Pricing Calculator

- 서비스별 예상 비용 계산
- 아키텍처 설계 단계에서 사용

------

### 21.2 AWS Cost Explorer

- 실제 사용 비용 시각화
- 서비스 / 계정 / 기간별 분석

------

### 21.3 AWS Budgets

- 비용 또는 사용량 한도 설정
- 임계값 초과 시 알림

------

### 21.4 Cost Allocation Tags

- 리소스별 비용 추적
- 부서 / 프로젝트 단위 관리

------

##  22. AWS Support Plans

### 22.1 Basic Support

- 무료
- 계정 및 결제 지원
- AWS 문서 및 커뮤니티 접근

------

### 22.2 Developer Support

- 업무 시간 내 기술 지원
- 1명의 사용자
- 테스트 / 개발 환경

------

### 22.3 Business Support

- 24/7 기술 지원
- 프로덕션 워크로드
- Trusted Advisor 전체 기능

------

### 22.4 Enterprise Support

- 대규모 기업용
- 전담 TAM(Technical Account Manager)
- 미션 크리티컬 환경

------

## 23. AWS Well-Architected Framework

### 23.1 개요

- AWS 아키텍처 설계 **모범 사례 프레임워크**
- 안전하고 효율적인 시스템 설계 목적

------

### 23.2 6가지 핵심 원칙(Pillars)

1. **Operational Excellence**
   - 운영 자동화
   - 지속적 개선
2. **Security**
   - 데이터 보호
   - 접근 제어
   - 로그 및 모니터링
3. **Reliability**
   - 장애 대응
   - 자동 복구
   - 고가용성
4. **Performance Efficiency**
   - 적절한 리소스 선택
   - 글로벌 배포
5. **Cost Optimization**
   - 불필요한 비용 제거
   - 사용량 기반 설계
6. **Sustainability**
   - 에너지 효율
   - 환경 영향 최소화

------

## p.202 ~ p.244 최종 시험 핵심 요약

- CloudFront = CDN + 캐싱
- Global Accelerator = 네트워크 가속
- 요금 = Pay-As-You-Go
- RI / Savings Plans / Spot 차이 중요
- Cost Explorer vs Budgets 구분
- Support Plan 단계별 특징
- Well-Architected = 6 Pillars
