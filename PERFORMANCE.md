# 성능 최적화 설정 가이드

대용량 로그 파일(3GB+)을 빠르게 처리하기 위한 성능 최적화 모듈입니다.

## 설치

```bash
pip install -r requirements.txt
```

### 설치된 성능 최적화 모듈

| 모듈 | 용도 | 성능 향상 | 필수 여부 |
|------|------|---------|---------|
| **regex** | 정규식 처리 최적화 | 2-10배 빠름 | 권장 |
| **orjson** | JSON 인코딩 최적화 | 5-10배 빠름 | 권장 |
| **psutil** | 메모리 모니터링 | - | 선택 |
| **numba** | JIT 컴파일 (향후 사용) | 10-100배 빠름 | 선택 |

## 각 모듈의 역할

### 1. regex (필수)
표준 `re` 모듈 대체. 정규식 처리 성능 2-10배 향상.
- 자동으로 적용됨 (`parser.py`에서 import 시도)
- 설치되지 않으면 표준 `re` 모듈로 폴백

### 2. orjson (권장)
JSON 응답 인코딩 최적화. 대용량 결과 응답 5-10배 향상.
- Django의 표준 `JsonResponse`보다 5-10배 빠름
- `views.py`에서 자동 적용

### 3. psutil (선택)
프로세스 메모리/CPU 모니터링. 성능 디버깅용.
```python
from analyzer.perf_utils import get_memory_usage, log_memory

mem = get_memory_usage()  # 현재 메모리 사용량 (MB)
print(f"Memory: {mem} MB")
```

### 4. numba (선택, 향후)
JIT 컴파일로 수치 계산 10-100배 가속. 복잡한 통계 계산에 사용 예정.

## 성능 개선 결과

### 측정 환경
- 파일 크기: 3GB 로그 파일
- 라인 수: 약 3,000만 줄
- 시스템: 8 CPU, 16GB RAM

### 성능 비교 (예상)

| 항목 | 최적화 전 | 최적화 후 | 개선 | 
|------|---------|---------|------|
| 로그 분석 | 180초 | 90-120초 | **30-50%** ↓ |
| JSON 응답 | 5초 | 0.5-1초 | **80-90%** ↓ |
| **총 처리시간** | **185초** | **90-120초** | **40-50%** ↓ |

## 최적화된 모듈 사용 예시

### parser.py (자동 최적화)
```python
# regex 모듈이 자동으로 사용됨 (더 빠른 정규식 처리)
try:
    import regex as re  # 2-10배 빠름
except ImportError:
    import re  # 폴백
```

### views.py (JSON 응답 최적화)
```python
# orjson 자동 사용 (더 빠른 JSON 인코딩)
try:
    import orjson
    def json_response(data, **kwargs):
        content = orjson.dumps(data)
        return HttpResponse(content, content_type='application/json')
except ImportError:
    json_response = JsonResponse
```

### 메모리 모니터링
```python
from analyzer.perf_utils import get_memory_usage

print(f"Current memory: {get_memory_usage()} MB")
```

## 추가 최적화 팁

### 1. Django 설정 최적화 (`settings.py`)
```python
# 대용량 요청 처리 위해 타임아웃 증가
DATA_UPLOAD_MAX_MEMORY_SIZE = 1073741824  # 1GB
FILE_UPLOAD_MAX_MEMORY_SIZE = 1073741824  # 1GB

# 캐싱 활성화
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
```

### 2. 운영 체제 레벨 최적화
```bash
# Linux: 파일 디스크립터 한계 증가
ulimit -n 65536

# 버퍼 캐시 크기 증가 (대용량 파일용)
# /etc/sysctl.conf 수정:
# vm.dirty_ratio = 10
# vm.dirty_background_ratio = 5
```

### 3. Python 런타임 최적화
```bash
# PyPy 사용 (CPython보다 2-3배 빠름)
pypy3 manage.py runserver

# 또는 Uvicorn + Gunicorn (비동기 처리)
gunicorn -w 4 -k uvicorn.workers.UvicornWorker log_analyze.wsgi
```

## 성능 모니터링

### 분석 성능 측정
```bash
# views.py에서 자동으로 elapsed 시간 반환
# 응답: {"data": {..., "elapsed": 95.2, "lineCount": 30000000}}
```

### 메모리 사용량 모니터링
```python
from analyzer.perf_utils import log_memory

log_memory("분석 시작")
# ... 분석 처리 ...
log_memory("분석 완료")
```

## 트러블슈팅

### regex 설치 실패
```bash
# 선택사항: regex 없어도 표준 re로 동작하지만 느림
pip install regex --no-binary regex
```

### orjson 설치 실패
```bash
# Rust 컴파일러 필요 (macOS에서는 Command Line Tools 설치)
xcode-select --install
pip install orjson
```

### 메모리 부족 (Out of Memory)
1. 동시 분석 개수 제한
2. 파일 크기 분할 (청크 단위 분석)
3. Docker 메모리 할당 증가
4. AWS/클라우드 인스턴스 메모리 업그레이드

## 향후 최적화 계획

- [ ] Cython으로 핵심 반복문 컴파일
- [ ] Polars/DuckDB로 SQL 기반 분석
- [ ] Redis 캐싱 추가
- [ ] 비동기 처리 (asyncio)
- [ ] GPU 가속 (CUDA, cuDF) - 향후

## 참고 자료

- [regex 모듈 문서](https://pypi.org/project/regex/)
- [orjson 문서](https://github.com/ijl/orjson)
- [psutil 문서](https://psutil.readthedocs.io/)
- [Django 성능 최적화](https://docs.djangoproject.com/en/stable/topics/performance/)
