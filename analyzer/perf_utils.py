"""
perf_utils.py — 성능 최적화 유틸리티

- 메모리 프로파일링
- 캐싱
- 벡터화 연산
"""

import psutil
import os
from functools import lru_cache

def get_memory_usage():
    """현재 프로세스의 메모리 사용량 (MB)."""
    process = psutil.Process(os.getpid())
    return round(process.memory_info().rss / 1024 / 1024, 1)

def log_memory(label=''):
    """메모리 사용량 로깅 (디버그용)."""
    mem = get_memory_usage()
    print(f"[MEM] {label}: {mem} MB")

# 빠른 문자열 검색 캐시
@lru_cache(maxsize=256)
def contains_substring(text, substring):
    """캐시된 부분 문자열 검색."""
    return substring in text

# 배치 처리용 청크 나누기
def chunk_iterator(iterator, chunk_size=1000):
    """이터레이터를 지정된 크기의 청크로 나눔."""
    chunk = []
    for item in iterator:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

# 통계 계산 최적화
def fast_stat(arr):
    """빠른 통계 계산 (min, max, avg, count)."""
    if not arr:
        return {'min': 0, 'max': 0, 'avg': 0, 'count': 0}
    n = len(arr)
    return {
        'min': min(arr),
        'max': max(arr),
        'avg': sum(arr) / n,
        'count': n,
    }

# 필터링 최적화
def filter_by_time_range(rows, start_sec=None, end_sec=None, time_key='timestamp_sec'):
    """시간 범위로 필터링 (최적화)."""
    if start_sec is None and end_sec is None:
        return rows

    filtered = []
    for row in rows:
        t = row.get(time_key, 0)
        if start_sec is not None and t < start_sec:
            continue
        if end_sec is not None and t > end_sec:
            continue
        filtered.append(row)
    return filtered
