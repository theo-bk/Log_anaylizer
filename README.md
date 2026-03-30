# NF4 Log Analyzer

NetFUNNEL 4 로그 파일을 분석하는 웹 애플리케이션입니다.

NF4 액세스 로그를 업로드하거나 서버 로컬 경로를 지정하여, 유량제어 세션 통계(진입/대기/완료/이탈), 상태코드 분포, 서버별 처리량, IP별 사용자 추적 등을 시각적으로 확인할 수 있습니다.

## 주요 기능

- 로그 파일 업로드 또는 서버 로컬 경로 지정 분석 (3GB+ 대용량 지원)
- KPI 대시보드: 진입 IP 수, 요청/대기/완료/이탈 사용자 수, 이탈률
- RPS 간격 분석 및 Hold 정책 분석
- 대기시간 통계 (진입 성공 vs 이탈)
- 서버(Sticky) 별 처리량 분포
- 비정상 상태코드 상세 목록
- IP별 사용자 추적 (시간대 필터 지원)
- CSV 다운로드

## 실행 방법

### 요구사항

- Python 3.12+

### 1. 압축 해제

공유드라이브에서 다운로드한 zip 파일을 원하는 위치에 압축 해제합니다.

### 2. 가상환경 생성 및 활성화

```bash
cd log_analyze

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 3. 패키지 설치

```bash
pip install -r requirements.txt
```

### 4. DB 초기화

```bash
python manage.py migrate
```

### 5. 서버 실행

```bash
python manage.py runserver
```

브라우저에서 http://127.0.0.1:8000 에 접속합니다.

## API 엔드포인트

| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/` | GET | 웹 UI |
| `/api/analyze/` | POST | 파일 업로드 분석 |
| `/api/range/` | POST | 파일 업로드 시간범위 조회 |
| `/api/analyze_path/` | GET | 서버 로컬 파일 경로 분석 |
| `/api/range_path/` | GET | 서버 로컬 파일 시간범위 조회 |
| `/api/trace/` | GET | IP별 사용자 추적 |
| `/api/csv/` | POST | CSV 다운로드 |
