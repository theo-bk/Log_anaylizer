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

## 로컬 실행 방법

### 요구사항

- Python 3.12+

### 설치 및 실행

```bash
git clone https://github.com/theo-bk/Log_anaylizer.git
cd Log_anaylizer

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

브라우저에서 http://127.0.0.1:8000 에 접속합니다.

## 퍼블릭 접근 (외부에서 실행)

로컬에 프로젝트를 다운로드하지 않고 실행하는 방법입니다.

### 방법 1: GitHub Codespaces

1. 이 저장소 페이지에서 **Code** > **Codespaces** > **Create codespace on main** 클릭
2. 터미널이 열리면 다음을 실행:
   ```bash
   pip install -r requirements.txt
   python manage.py migrate
   python manage.py runserver
   ```
3. Codespaces가 자동으로 포트 포워딩하여 브라우저에서 접근 가능

### 방법 2: GitPod

브라우저 주소창에 다음을 입력합니다:

```
https://gitpod.io/#https://github.com/theo-bk/Log_anaylizer
```

터미널에서 동일하게 설치 및 실행합니다.

### 방법 3: pip + 원격 실행 (다운로드 없이)

```bash
pip install Django>=6.0
python -c "
import subprocess, tempfile, os
d = tempfile.mkdtemp()
subprocess.run(['git', 'clone', 'https://github.com/theo-bk/Log_anaylizer.git', d])
os.chdir(d)
subprocess.run(['python', 'manage.py', 'migrate'])
subprocess.run(['python', 'manage.py', 'runserver'])
"
```

### 방법 4: Docker (선택)

```bash
docker run --rm -it -p 8000:8000 -w /app -v /tmp:/tmp python:3.12-slim bash -c "
  pip install Django>=6.0 &&
  git clone https://github.com/theo-bk/Log_anaylizer.git /app &&
  cd /app &&
  python manage.py migrate &&
  python manage.py runserver 0.0.0.0:8000
"
```

브라우저에서 http://localhost:8000 에 접속합니다.

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
