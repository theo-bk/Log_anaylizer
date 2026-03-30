import csv
import json
import os
import time

from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .parser import analyze_file, compute_range


# ===== 분석 결과 캐시 (사용자추적 on-demand 조회용) =====
_last_result_cache = {
    'sessions': None,
    'dropout_201': None,
    'dropout_200': None,
    'ip_counts': None,
    'ip_times': None,
}


def _stream_lines_from_file(file_path, chunk_size=4 * 1024 * 1024):
    """디스크 파일을 4MB 청크로 읽어 줄 단위 yield. 메모리 최소 사용."""
    leftover = ''
    with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            chunk = leftover + chunk
            lines = chunk.split('\n')
            leftover = lines.pop()
            for line in lines:
                yield line
    if leftover:
        yield leftover


def _stream_lines_from_upload(uploaded_file, chunk_size=4 * 1024 * 1024):
    """Django UploadedFile을 청크 단위로 읽어 줄 단위로 yield."""
    uploaded_file.seek(0)
    leftover = ''
    while True:
        chunk = uploaded_file.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, bytes):
            chunk = chunk.decode('utf-8', errors='replace')
        chunk = leftover + chunk
        lines = chunk.split('\n')
        leftover = lines.pop()
        for line in lines:
            yield line
    if leftover:
        yield leftover


def _limit_result(result):
    """응답 크기 제한."""
    for cd in result.get('codeDetails', []):
        if len(cd.get('rows', [])) > 500:
            cd['rows'] = cd['rows'][:500]


def _strip_internal(result):
    """내부 캐시 데이터를 JSON 응답에서 제거."""
    return {k: v for k, v in result.items() if not k.startswith('_')}


def _cache_internal(result):
    """분석 결과의 내부 데이터를 캐시에 저장."""
    _last_result_cache['sessions'] = result.get('_sessions')
    _last_result_cache['dropout_201'] = result.get('_dropout_201')
    _last_result_cache['dropout_200'] = result.get('_dropout_200')
    _last_result_cache['ip_counts'] = result.get('_ip_counts')
    _last_result_cache['ip_times'] = result.get('_ip_times')
    _last_result_cache['ip_to_tids'] = result.get('_ip_to_tids')


def index(request):
    return render(request, 'analyzer/index.html')


def _get_params(request):
    """POST/GET 파라미터 파싱 공통."""
    g = request.POST.get if request.method == 'POST' else request.GET.get
    pj = (g('pj') or '').strip()
    seg = (g('seg') or '').strip()
    seg_all = g('segAll') == 'true'
    start_sec = g('startSec')
    end_sec = g('endSec')
    start_sec = int(start_sec) if start_sec else None
    end_sec = int(end_sec) if end_sec else None
    rps_enabled = g('rpsEnabled') == 'true'
    rps_min = float(g('rpsMin') or 1)
    rps_max = float(g('rpsMax') or 10)
    hold_enabled = g('holdEnabled') == 'true'
    hold_sec_val = float(g('holdSec') or 60)
    return dict(
        pj=pj, seg=seg, seg_all=seg_all,
        start_sec=start_sec, end_sec=end_sec,
        rps_enabled=rps_enabled, rps_min=rps_min, rps_max=rps_max,
        hold_enabled=hold_enabled, hold_sec=hold_sec_val,
    )


# ===== 서버 로컬 파일 경로로 분석 (대용량 3GB+) =====

@csrf_exempt
def analyze_by_path(request):
    """
    GET /api/analyze_path/?path=...&pj=...&seg=...
    서버에서 파일을 직접 읽어 분석 후 JSON 반환.
    """
    file_path = request.GET.get('path', '').strip()
    if not file_path or not os.path.isfile(file_path):
        return JsonResponse({'error': f'파일을 찾을 수 없습니다: {file_path}'}, status=400)

    params = _get_params(request)
    file_size = os.path.getsize(file_path)
    start_time = time.time()

    lines_iter = _stream_lines_from_file(file_path)

    result = analyze_file(
        lines_iter,
        pj=params['pj'], seg=params['seg'], seg_all=params['seg_all'],
        start_sec=params['start_sec'], end_sec=params['end_sec'],
        rps_enabled=params['rps_enabled'], rps_min=params['rps_min'],
        rps_max=params['rps_max'],
        hold_enabled=params['hold_enabled'], hold_sec=params['hold_sec'],
    )

    elapsed = round(time.time() - start_time, 1)

    # 내부 데이터 캐시 (사용자추적 API용)
    _cache_internal(result)

    # 응답 데이터 준비
    response_data = _strip_internal(result)
    _limit_result(response_data)
    response_data['elapsed'] = elapsed
    response_data['fileSize'] = file_size
    response_data['fileSizeMB'] = round(file_size / 1024 / 1024, 1)

    return JsonResponse({'data': response_data})


@csrf_exempt
def range_by_path(request):
    """GET /api/range_path/?path=... → 시간범위만 빠르게 반환 (첫/끝 100줄만 스캔)."""
    file_path = request.GET.get('path', '').strip()
    if not file_path or not os.path.isfile(file_path):
        return JsonResponse({'error': f'파일을 찾을 수 없습니다: {file_path}'}, status=400)

    file_size = os.path.getsize(file_path)

    first_ts = None
    last_ts = None

    from .parser import parse_timestamp

    with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
        for i, line in enumerate(fh):
            if i >= 100:
                break
            dt = parse_timestamp(line)
            if dt:
                sec = int(dt.timestamp())
                if first_ts is None or sec < first_ts:
                    first_ts = sec
                if last_ts is None or sec > last_ts:
                    last_ts = sec

    tail_size = min(file_size, 50 * 1024)
    with open(file_path, 'rb') as fh:
        fh.seek(max(0, file_size - tail_size))
        tail_bytes = fh.read()
    tail_text = tail_bytes.decode('utf-8', errors='replace')
    for line in tail_text.split('\n')[-100:]:
        dt = parse_timestamp(line)
        if dt:
            sec = int(dt.timestamp())
            if first_ts is None or sec < first_ts:
                first_ts = sec
            if last_ts is None or sec > last_ts:
                last_ts = sec

    from .parser import to_iso
    return JsonResponse({
        'startSec': first_ts,
        'endSec': last_ts,
        'startISO': to_iso(first_ts),
        'endISO': to_iso(last_ts),
        'fileSize': file_size,
        'fileSizeMB': round(file_size / 1024 / 1024, 1),
    })


# ===== 사용자 추적 API (on-demand) =====

@csrf_exempt
def trace_ip(request):
    """
    GET /api/trace/?ip=...&from=2026-02-11 09:00:00&to=2026-02-11 10:00:00
    해당 IP의 tid 세션 상세 반환. 시간대 필터 지원.
    """
    ip = request.GET.get('ip', '').strip()
    if not ip:
        return JsonResponse({'error': 'IP를 입력하세요.'}, status=400)

    sessions = _last_result_cache.get('sessions')
    ip_to_tids = _last_result_cache.get('ip_to_tids')
    if not sessions or not ip_to_tids:
        return JsonResponse({'error': '먼저 로그 분석을 실행하세요.'}, status=400)

    dropout_201 = _last_result_cache.get('dropout_201', set())
    dropout_200 = _last_result_cache.get('dropout_200', set())
    ip_counts = _last_result_cache.get('ip_counts', {})
    ip_times = _last_result_cache.get('ip_times', {})

    # 역인덱스로 O(1) 조회
    tid_list = ip_to_tids.get(ip)
    if not tid_list:
        return JsonResponse({'data': None})

    # 시간대 필터 파라미터
    time_from = request.GET.get('from', '').strip()
    time_to = request.GET.get('to', '').strip()

    from .parser import epoch_to_str

    # 상세 생성 (시간대 필터 적용, 전체 반환)
    # session format: [ip, flags, start_sec, wait_end_sec, last_req_sec]
    # flags: bit 0=has_5101, bit 1=has_5002, bit 2=has_5004
    tid_details = []
    for t in tid_list:
        s = sessions[t]
        flags = s[1]
        st = s[2]
        we = s[3]
        start_str = epoch_to_str(st) if st else ''

        # 시간대 필터
        if time_from and start_str and start_str < time_from:
            continue
        if time_to and start_str and start_str > time_to:
            continue

        has_5004 = flags & 4
        has_5002 = flags & 2
        has_5101 = flags & 1
        status = '완료(5004)' if has_5004 else (
            '대기중이탈' if t in dropout_201 else (
                '진입후이탈' if t in dropout_200 else '진행중'))
        wait_sec = round(we - st, 1) if (has_5002 and st and we) else 0
        opcode = '5101+5002' if (has_5101 and has_5002) else (
            '5101' if has_5101 else ('5002' if has_5002 else '-'))
        tid_details.append({
            'tid': t,
            'status': status,
            'start': start_str,
            'end': epoch_to_str(we) if we else '',
            'waitSec': wait_sec,
            'opcode': opcode,
        })
    tid_details.sort(key=lambda x: x['start'])

    total_count = len(tid_details)
    # 프론트 표시용으로 최대 500개 (시간대 필터 시 충분)
    truncated = len(tid_details) > 500
    tid_details = tid_details[:500]

    times = ip_times.get(ip, ('', ''))
    c = ip_counts.get(ip, [0, 0, 0, 0, 0, 0.0])

    return JsonResponse({'data': {
        'tidCount': len(tid_list),
        'filteredCount': total_count,
        'truncated': truncated,
        'firstSeen': times[0] if isinstance(times, tuple) else '',
        'lastSeen': times[1] if isinstance(times, tuple) else '',
        'totalWaitSec': round(c[5], 1) if len(c) > 5 else 0,
        'tids': tid_details,
    }})


# ===== 업로드 방식 (소용량용, 기존 호환) =====

@csrf_exempt
@require_POST
def analyze(request):
    f = request.FILES.get('file')
    if not f:
        return JsonResponse({'error': '파일이 없습니다.'}, status=400)

    params = _get_params(request)
    lines = _stream_lines_from_upload(f)

    result = analyze_file(
        lines,
        pj=params['pj'], seg=params['seg'], seg_all=params['seg_all'],
        start_sec=params['start_sec'], end_sec=params['end_sec'],
        rps_enabled=params['rps_enabled'], rps_min=params['rps_min'],
        rps_max=params['rps_max'],
        hold_enabled=params['hold_enabled'], hold_sec=params['hold_sec'],
    )

    _cache_internal(result)
    response_data = _strip_internal(result)
    _limit_result(response_data)
    return JsonResponse({'data': response_data})


@csrf_exempt
@require_POST
def get_range(request):
    f = request.FILES.get('file')
    if not f:
        return JsonResponse({'error': '파일이 없습니다.'}, status=400)
    lines = _stream_lines_from_upload(f)
    result = compute_range(lines)
    return JsonResponse(result)


@csrf_exempt
@require_POST
def download_csv(request):
    body = json.loads(request.body)
    filename = body.get('filename', 'export.csv')
    headers = body.get('headers', [])
    rows = body.get('rows', [])

    if not rows:
        return HttpResponse('데이터 없음', status=400)

    if not headers:
        headers = list(rows[0].keys())

    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.DictWriter(response, fieldnames=headers, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    return response
