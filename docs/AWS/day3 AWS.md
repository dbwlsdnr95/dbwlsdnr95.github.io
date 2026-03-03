---
layout: default
title: "AWS 3일차"
parent: AWS
nav_order: 4
---

# 4. 스토리지 서비스

## 1. Amazon S3 (Simple Storage Service)

### 1.1 개요 및 특징

- **오브젝트 스토리지**
  - 데이터를 **객체(Object)** 단위로 저장
  - 각 객체는 **고유 식별자(Key)**, 데이터, 메타데이터 포함
- **무제한 용량**
  - 거의 무제한 저장 가능
  - 개별 객체 최대 크기: **5TB**
- **고가용성 및 내구성**
  - 최소 **3개 이상의 가용 영역(AZ)** 에 자동 분산 저장
  - 매우 높은 내구성 제공
- **버킷(Bucket)**
  - 객체를 저장하는 최상위 컨테이너
  - **리전 단위로 생성**
  - **버킷 이름은 전 세계에서 유일**해야 함

------

### 1.2 주요 기능

- **버전 관리 (Versioning)**
  - 객체의 여러 버전 보존
  - 실수로 삭제·덮어쓰기 시 복구 가능
- **데이터 암호화**
  - 서버 측 암호화
    - `SSE-S3`
    - `SSE-KMS`
    - `SSE-C`
  - 전송 중 암호화
    - `SSL / TLS`
- **액세스 관리**
  - 버킷 정책 (JSON 형식)
  - ACL
  - 퍼블릭 액세스 차단 설정

------

### 1.3 스토리지 클래스

- **S3 Standard**
  - 자주 액세스하는 데이터용 (범용)
- **S3 Intelligent-Tiering**
  - 액세스 패턴이 불분명하거나 변하는 데이터
  - 자동 비용 최적화
- **S3 Standard-IA**
  - 자주 액세스하지 않지만 즉시 접근 필요
  - 최소 **30일 보관**
- **S3 One Zone-IA**
  - 중요도가 낮은 데이터
  - 단일 가용 영역 저장  비용 저렴
- **S3 Glacier Instant Retrieval**
  - 아카이브 데이터
  - **밀리초 단위 즉시 검색**
- **S3 Glacier Flexible Retrieval**
  - 분~시간 단위 검색
  - 연 **1회 정도 액세스** 데이터
- **S3 Glacier Deep Archive**
  - 최저 비용 스토리지
  - **7~10년 장기 보관**
  - 검색 시간: **12~48시간**

------

### 1.4 부가 기능

- **수명 주기 정책 (Lifecycle Policy)**
  - 일정 기간 후 스토리지 클래스 자동 변경
  - 객체 자동 삭제
  - 비용 절감 목적
- **S3 Transfer Acceleration**
  - 전 세계 **엣지 로케이션** 활용
  - 장거리 파일 전송 속도 향상

------

## 2. 하이브리드 및 마이그레이션 스토리지

### 2.1 AWS Storage Gateway

- 온프레미스 데이터 센터와 AWS 스토리지를 연결하는 **하이브리드 서비스**
- **유형**
  - S3 파일 게이트웨이
  - FSx 파일 게이트웨이
  - 볼륨 게이트웨이
  - 테이프 게이트웨이

------

### 2.2 Amazon FSx

- 고성능 **타사 파일 시스템 제공**
- **유형**
  - FSx for Lustre (HPC용)
  - FSx for Windows File Server (SMB 지원)
  - FSx for NetApp ONTAP
  - FSx for OpenZFS

------

### 2.3 AWS Snow Family

- 물리적 장치를 배송하여 **대용량 데이터 마이그레이션**
- **장치**
  - Snowcone: **8TB**
  - Snowball Edge: **80TB / 210TB**
  - Snowmobile: **100PB**

------

### 2.4 AWS DataSync

- 온프레미스  AWS 스토리지 간
- **데이터 복사 자동화 및 가속화 서비스**

#  5. 데이터베이스 서비스

## 1. 관계형 데이터베이스 (RDS)

- **Amazon RDS**
  - 관리형 관계형 DB 서비스
  - 하드웨어 프로비저닝, 패치, 백업을 AWS가 담당
- **Amazon Aurora**
  - AWS 전용 RDS 호환 DB
  - MySQL 대비 **5배**
  - PostgreSQL 대비 **3배** 빠름
- **가용성 옵션**
  - **Read Replica**
    - 읽기 성능 향상
  - **Multi-AZ**
    - 고가용성 보장

------

## 2. NoSQL 및 기타 데이터베이스

- **Amazon DynamoDB**
  - 서버리스 NoSQL
  - 10ms 미만 지연 시간
  - 무제한 확장
- **Amazon ElastiCache**
  - 인메모리 캐시 (Redis, Memcached)
  - 응답 성능 개선
- **기타 전용 DB**
  - DocumentDB (문서)
  - Neptune (그래프)
  - QLDB (원장)
  - Timestream (시계열)

------

# 6. 데이터 분석 서비스

- **Amazon Athena**
  - S3 데이터를 표준 SQL로 쿼리
  - 서버리스
- **Amazon Redshift**
  - 대규모 데이터 웨어하우스
  - BI 분석에 적합
- **Amazon OpenSearch**
  - 로그 분석
  - 실시간 모니터링 및 검색
- **AWS Glue**
  - 서버리스 ETL 서비스
  - 데이터 추출·변환·로드
- **Amazon EMR**
  - Hadoop / Spark 기반
  - 대규모 빅데이터 처리
- **Amazon QuickSight**
  - 클라우드 기반 BI 시각화 도구
