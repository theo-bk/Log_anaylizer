import csv
import json
import os
import time
from collections import defaultdict

from django.http import JsonResponse, HttpResponse, StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .parser import analyze_file, compute_range, stat, percent, to_iso, epoch_to_str


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


def _cache_internal(result, params=None):
    """단일 서버 분석 결과의 내부 데이터를 캐시에 저장."""
    _last_result_cache['sessions'] = result.get('_sessions')
    _last_result_cache['dropout_201'] = result.get('_dropout_201')
    _last_result_cache['dropout_200'] = result.get('_dropout_200')
    _last_result_cache['ip_counts'] = result.get('_ip_counts')
    _last_result_cache['ip_times'] = result.get('_ip_times')
    _last_result_cache['ip_to_tids'] = result.get('_ip_to_tids')
    _last_result_cache['server_prefix_map'] = {}
    if params:
        _last_result_cache['analysis_params'] = {
            'pj': params.get('pj', ''),
            'seg': params.get('seg', ''),
            'timeout_sec': params.get('timeout_sec', 20),
            'log_tz': params.get('log_tz', 'UTC'),
        }


def _cache_multi_internal(labeled_results, params=None):
    """멀티서버 분석 결과를 서버 인덱스 prefix로 구분하여 캐시에 저장.
    session key: (sid, aid, tid) → ('N:sid', aid, tid) 형태로 prefix.
    trace_ip에서 tid_k(=key[2])만 표시에 사용하므로 sid prefix는 투명함.
    """
    merged_sessions = {}
    merged_dropout_201 = set()
    merged_dropout_200 = set()
    merged_ip_counts = defaultdict(lambda: [0, 0, 0, 0, 0, 0.0])
    merged_ip_times = {}
    merged_ip_to_tids = defaultdict(list)

    for idx, (label, result) in enumerate(labeled_results):
        prefix = f'{idx}:'
        for key, sess in (result.get('_sessions') or {}).items():
            new_key = (prefix + key[0], key[1], key[2])
            merged_sessions[new_key] = sess
        for key in (result.get('_dropout_201') or set()):
            merged_dropout_201.add((prefix + key[0], key[1], key[2]))
        for key in (result.get('_dropout_200') or set()):
            merged_dropout_200.add((prefix + key[0], key[1], key[2]))
        for ip, counts in (result.get('_ip_counts') or {}).items():
            m = merged_ip_counts[ip]
            for j in range(5):
                m[j] += counts[j]
            m[5] += counts[5]
        for ip, times in (result.get('_ip_times') or {}).items():
            if isinstance(times, tuple) and len(times) == 2:
                mn, mx = times
                if ip not in merged_ip_times:
                    merged_ip_times[ip] = (mn, mx)
                else:
                    prev_mn, prev_mx = merged_ip_times[ip]
                    merged_ip_times[ip] = (
                        min(prev_mn, mn) if (mn and prev_mn) else (mn or prev_mn),
                        max(prev_mx, mx) if (mx and prev_mx) else (mx or prev_mx),
                    )
        for ip, tid_list in (result.get('_ip_to_tids') or {}).items():
            for key in tid_list:
                merged_ip_to_tids[ip].append((prefix + key[0], key[1], key[2]))

    _last_result_cache['sessions'] = merged_sessions
    _last_result_cache['dropout_201'] = merged_dropout_201
    _last_result_cache['dropout_200'] = merged_dropout_200
    _last_result_cache['ip_counts'] = dict(merged_ip_counts)
    _last_result_cache['ip_times'] = merged_ip_times
    _last_result_cache['ip_to_tids'] = dict(merged_ip_to_tids)
    # trace_ip에서 session key prefix → 서버 라벨 변환용
    _last_result_cache['server_prefix_map'] = {
        f'{idx}:': label for idx, (label, _) in enumerate(labeled_results)
    }
    if params:
        _last_result_cache['analysis_params'] = {
            'pj': params.get('pj', ''),
            'seg': params.get('seg', ''),
            'timeout_sec': params.get('timeout_sec', 20),
            'log_tz': params.get('log_tz', 'UTC'),
        }


def merge_results(labeled_results):
    """labeled_results: list of (label: str, result: dict) — 멀티서버 결과를 통합."""
    # 시간 범위
    starts = [r['range']['startSec'] for _, r in labeled_results if r['range'].get('startSec')]
    ends = [r['range']['endSec'] for _, r in labeled_results if r['range'].get('endSec')]

    # 진입 IP: 서버 간 union
    all_entry_ips = set()
    for _, r in labeled_results:
        all_entry_ips.update(r.get('_raw', {}).get('entry_ips', []))

    # KPI 합산
    kpis_list = [r['kpis'] for _, r in labeled_results]
    req_user      = sum(k['reqUserCnt'] for k in kpis_list)
    wait_user     = sum(k['waitUserCnt'] for k in kpis_list)
    done_user     = sum(k['doneUserCnt'] for k in kpis_list)
    quit_wait     = sum(k['quitWaitCnt'] for k in kpis_list)
    post_enter    = sum(k['postEnterLeaveCnt'] for k in kpis_list)
    entry_success = sum(k.get('entrySuccessCount', 0) for k in kpis_list)

    qw_rate = percent(quit_wait, wait_user)
    pe_rate = percent(post_enter, entry_success)

    # raw 배열 연결
    def concat(field):
        out = []
        for _, r in labeled_results:
            out.extend(r.get('_raw', {}).get(field, []))
        return out

    all_gaps        = concat('gaps')
    all_over_ttlmax = concat('over_ttlmax')
    all_between     = concat('between')
    all_over_keep   = concat('over_keep')
    all_returned    = concat('returned_wait')
    all_dropped     = concat('dropped_wait')
    all_durations   = concat('durations')

    # topWaitTids: 서버별 pool 병합 후 상위 5개
    all_top_pool = []
    for label, r in labeled_results:
        pool = r.get('_raw', {}).get('top_wait_pool', r.get('topWaitTids', []))
        for item in pool:
            item_copy = dict(item)
            item_copy['server'] = label
            all_top_pool.append(item_copy)
    all_top_pool.sort(key=lambda x: x['wait_secs'], reverse=True)

    # codeDetails: 코드별 병합 (실제 건수 = code_cnt, rows는 최대 500)
    code_cnt_merged = defaultdict(int)
    code_rows_merged = defaultdict(list)
    for _, r in labeled_results:
        raw_code_cnt = r.get('_raw', {}).get('code_cnt', {})
        for cd in r.get('codeDetails', []):
            code = str(cd['code'])
            true_cnt = raw_code_cnt.get(code, cd['cnt'])
            code_cnt_merged[code] += true_cnt
            existing = code_rows_merged[code]
            if len(existing) < 500:
                existing.extend(cd.get('rows', [])[:500 - len(existing)])
    code_details = sorted(
        [{'code': c, 'cnt': cnt, 'rows': code_rows_merged[c]} for c, cnt in code_cnt_merged.items()],
        key=lambda x: x['cnt'], reverse=True,
    )

    # 이탈 row 병합 (server 라벨은 views.py에서 미리 스탬프됨)
    quit_rows, post_rows = [], []
    for _, r in labeled_results:
        quit_rows.extend(r.get('quitWaitRows', []))
        post_rows.extend(r.get('postEnterRows', []))

    # IP 통계 병합
    merged_ip_counts = defaultdict(lambda: [0, 0, 0, 0, 0, 0.0])
    for _, r in labeled_results:
        for ip, c in (r.get('_ip_counts') or {}).items():
            m = merged_ip_counts[ip]
            for j in range(5):
                m[j] += c[j]
            m[5] += c[5]

    def top_ip(idx, limit=50):
        items = [(ip, c[idx]) for ip, c in merged_ip_counts.items() if c[idx] > 0]
        items.sort(key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': v} for ip, v in items[:limit]]

    top_issue_ip = top_ip(0)
    top_wait_ip = [{'ip': ip, 'count': round(c[5], 1)}
                   for ip, c in merged_ip_counts.items() if c[5] > 0]
    top_wait_ip.sort(key=lambda x: x['count'], reverse=True)
    top_wait_ip = top_wait_ip[:50]
    top_qw_ip = top_ip(3)
    top_pe_ip = top_ip(4)

    # 시간대별 시리즈 병합
    ts_req_m = defaultdict(int)
    ts_wait_m = defaultdict(int)
    ts_done_m = defaultdict(int)
    for _, r in labeled_results:
        for k, v in (r.get('_raw') or {}).get('ts_req', {}).items():
            ts_req_m[k] += v
        for k, v in (r.get('_raw') or {}).get('ts_wait', {}).items():
            ts_wait_m[k] += v
        for k, v in (r.get('_raw') or {}).get('ts_done', {}).items():
            ts_done_m[k] += v
    _all_min_m = sorted(set(ts_req_m) | set(ts_wait_m) | set(ts_done_m))
    merged_time_series = [
        {'time': epoch_to_str(m), 'req': ts_req_m.get(m, 0), 'wait': ts_wait_m.get(m, 0), 'done': ts_done_m.get(m, 0)}
        for m in _all_min_m
    ]

    # 처리시간 분포 병합
    merged_timeout = max((r.get('timeoutSec', 20) for _, r in labeled_results), default=20)
    if all_durations and merged_timeout > 0:
        _bsize = merged_timeout / 5
        _hcnt = [0] * 5
        for _d in all_durations:
            _hcnt[min(int(_d / _bsize), 4)] += 1
        merged_dur_histogram = [
            {'label': f'{int(i * _bsize)}~{int((i + 1) * _bsize)}초', 'count': _hcnt[i]}
            for i in range(5)
        ]
    else:
        merged_dur_histogram = []

    return {
        'range': {
            'startSec': min(starts) if starts else None,
            'endSec':   max(ends)   if ends   else None,
            'startISO': to_iso(min(starts)) if starts else '',
            'endISO':   to_iso(max(ends))   if ends   else '',
        },
        'kpis': {
            'enterIPCnt':        len(all_entry_ips),
            'reqUserCnt':        req_user,
            'waitUserCnt':       wait_user,
            'doneUserCnt':       done_user,
            'quitWaitCnt':       quit_wait,
            'postEnterLeaveCnt': post_enter,
            'qwRate':            qw_rate,
            'peRate':            pe_rate,
            'entrySuccessCount': entry_success,
        },
        'rpsStats': {
            'all':     stat(all_gaps),
            'overMax': stat(all_over_ttlmax),
            'holdAct': stat(all_between),
            'holdOver': stat(all_over_keep),
        },
        'waitDurStats': {
            'enter': stat(all_returned),
            'quit':  stat(all_dropped),
        },
        'durationStats': stat(all_durations),
        'timeSeries': merged_time_series,
        'durHistogram': merged_dur_histogram,
        'timeoutSec': merged_timeout,
        'topWaitTids':   all_top_pool[:5],
        'codeDetails':   code_details,
        'quitWaitRows':  quit_rows,
        'postEnterRows': post_rows,
        'anomRows':      [],
        'totalCodes':    sum(code_cnt_merged.values()),
        'lineCount':     sum(r.get('lineCount', 0) for _, r in labeled_results),
        'topIssueIP':    top_issue_ip,
        'topWaitIP':     top_wait_ip,
        'topQwIP':       top_qw_ip,
        'topPeIP':       top_pe_ip,
    }


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
    timeout_sec = float(g('timeoutSec') or 20)
    log_tz = (g('logTz') or 'UTC').upper()
    if log_tz not in ('UTC', 'KST'):
        log_tz = 'UTC'
    return dict(
        pj=pj, seg=seg, seg_all=seg_all,
        start_sec=start_sec, end_sec=end_sec,
        rps_enabled=rps_enabled, rps_min=rps_min, rps_max=rps_max,
        hold_enabled=hold_enabled, hold_sec=hold_sec_val,
        timeout_sec=timeout_sec, log_tz=log_tz,
    )


# ===== 서버 로컬 파일 경로로 분석 (대용량 3GB+) =====

@csrf_exempt
def analyze_by_path(request):
    """
    GET /api/analyze_path/?path=...&pj=...&seg=...
    서버에서 파일을 직접 읽어 분석 후 JSON 반환.
    """
    file_path = request.GET.get('path', '').strip().strip("'\"")
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
        timeout_sec=params['timeout_sec'], log_tz=params['log_tz'],
    )

    elapsed = round(time.time() - start_time, 1)

    # 내부 데이터 캐시 (사용자추적 API용)
    _cache_internal(result, params)

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
    file_path = request.GET.get('path', '').strip().strip("'\"")
    if not file_path or not os.path.isfile(file_path):
        return JsonResponse({'error': f'파일을 찾을 수 없습니다: {file_path}'}, status=400)

    log_tz = (request.GET.get('logTz') or 'UTC').upper()
    if log_tz not in ('UTC', 'KST'):
        log_tz = 'UTC'
    tz_adjust = -32400 if log_tz == 'KST' else 0

    file_size = os.path.getsize(file_path)

    first_ts = None
    last_ts = None

    from .parser import parse_timestamp, _SID_RE, _AID_RE, to_iso

    sids = set()
    aids = set()
    field_scanned = 0

    with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
        for i, line in enumerate(fh):
            if i >= 200_000:
                break
            dt = parse_timestamp(line)
            if dt:
                sec = int(dt.timestamp()) + tz_adjust
                if first_ts is None or sec < first_ts:
                    first_ts = sec
                if last_ts is None or sec > last_ts:
                    last_ts = sec
            if field_scanned < 200_000 and 'ts.wseq' in line:
                field_scanned += 1
                m3 = _SID_RE.search(line)
                m4 = _AID_RE.search(line)
                if m3:
                    sids.add(m3.group(1))
                if m4:
                    aids.add(m4.group(1))

    tail_size = min(file_size, 50 * 1024)
    with open(file_path, 'rb') as fh:
        fh.seek(max(0, file_size - tail_size))
        tail_bytes = fh.read()
    tail_text = tail_bytes.decode('utf-8', errors='replace')
    for line in tail_text.split('\n')[-100:]:
        dt = parse_timestamp(line)
        if dt:
            sec = int(dt.timestamp()) + tz_adjust
            if first_ts is None or sec < first_ts:
                first_ts = sec
            if last_ts is None or sec > last_ts:
                last_ts = sec

    return JsonResponse({
        'startSec': first_ts,
        'endSec': last_ts,
        'startISO': to_iso(first_ts),
        'endISO': to_iso(last_ts),
        'fileSize': file_size,
        'fileSizeMB': round(file_size / 1024 / 1024, 1),
        'sids': sorted(sids),
        'aids': sorted(aids),
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
    server_prefix_map = _last_result_cache.get('server_prefix_map') or {}  # {prefix: label}

    # 역인덱스로 O(1) 조회
    tid_list = ip_to_tids.get(ip)
    if not tid_list:
        return JsonResponse({'data': None})

    # 시간대 필터 파라미터
    time_from = request.GET.get('from', '').strip()
    time_to = request.GET.get('to', '').strip()

    from .parser import epoch_to_str

    # 상세 생성 (시간대 필터 적용, 전체 반환)
    # session key: (sid, aid, tid) 복합키
    # session format: [ip, flags, start_sec, wait_end_sec, last_req_sec]
    # flags: bit 0=has_5101, bit 1=has_5002, bit 2=has_5004
    tid_details = []
    for t in tid_list:
        s = sessions[t]
        _sid, _aid, tid_k = t   # 복합키 언패킹
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

        # 서버 라벨: _sid prefix로 역조회 (멀티서버 시 '0:', '1:' 등으로 시작)
        server = ''
        for prefix, srv_label in server_prefix_map.items():
            if _sid.startswith(prefix):
                server = srv_label
                break

        tid_details.append({
            'tid': tid_k,
            'status': status,
            'start': start_str,                          # 키 발급 시각
            'end': epoch_to_str(we) if we else '',       # 대기 종료(진입) 시각
            'done': epoch_to_str(s[4]) if (has_5004 and s[4]) else '',  # 키 반납(5004) 시각
            'waitSec': wait_sec,
            'opcode': opcode,
            'server': server,
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


# ===== 세션 타임라인 API =====

@csrf_exempt
def timeline(request):
    """GET /api/timeline/?from=...&to=...&offset=0&limit=500
    캐시된 전체 세션을 시간순으로 반환. 시간대 필터·페이지네이션 지원."""
    sessions = _last_result_cache.get('sessions')
    if not sessions:
        return JsonResponse({'error': '먼저 로그 분석을 실행하세요.'}, status=400)

    time_from = request.GET.get('from', '').strip()
    time_to   = request.GET.get('to',   '').strip()
    try:
        offset = max(0, int(request.GET.get('offset', 0)))
        limit  = min(2000, max(1, int(request.GET.get('limit', 500))))
    except ValueError:
        offset, limit = 0, 500

    dropout_201       = _last_result_cache.get('dropout_201') or set()
    dropout_200       = _last_result_cache.get('dropout_200') or set()
    server_prefix_map = _last_result_cache.get('server_prefix_map') or {}
    ap = _last_result_cache.get('analysis_params') or {}
    timeout_sec = float(ap.get('timeout_sec', 20))

    rows = []
    for t, s in sessions.items():
        _sid, _aid, tid_k = t
        flags  = s[1]
        st     = s[2]   # 키 발급 시각
        we     = s[3]   # 대기 종료 시각
        done_t = s[4]   # 키 반납(5004) 시각

        start_str = epoch_to_str(st) if st else ''
        if time_from and start_str and start_str < time_from:
            continue
        if time_to and start_str and start_str > time_to:
            continue

        has_5004 = bool(flags & 4)
        has_5002 = bool(flags & 2)
        has_5101 = bool(flags & 1)

        status = '완료' if has_5004 else (
            '대기이탈' if t in dropout_201 else (
                '진입이탈' if t in dropout_200 else '진행중'))
        entry = '5101+5002' if (has_5101 and has_5002) else (
            '5101' if has_5101 else ('5002' if has_5002 else '-'))
        wait_sec = round(we - st, 1) if (has_5002 and st and we) else 0
        dur_sec  = round(done_t - st, 1) if (has_5004 and st and done_t) else None
        dur_exceeded = (dur_sec is not None and dur_sec > timeout_sec)

        server = ''
        for prefix, srv_label in server_prefix_map.items():
            if _sid.startswith(prefix):
                server = srv_label
                break

        rows.append({
            'start':       start_str,
            'tid':         tid_k,
            'ip':          s[0],
            'entry':       entry,
            'status':      status,
            'end':         epoch_to_str(we) if we else '',
            'done':        epoch_to_str(done_t) if (has_5004 and done_t) else '',
            'waitSec':     wait_sec,
            'durSec':      dur_sec,
            'durExceeded': dur_exceeded,
            'server':      server,
        })

    rows.sort(key=lambda x: x['start'])
    total = len(rows)
    return JsonResponse({
        'total':   total,
        'offset':  offset,
        'limit':   limit,
        'isMulti': bool(server_prefix_map),
        'rows':    rows[offset:offset + limit],
        'analysisParams': {
            'pj':         ap.get('pj', ''),
            'seg':        ap.get('seg', ''),
            'timeoutSec': timeout_sec,
        },
    })


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
        timeout_sec=params['timeout_sec'], log_tz=params['log_tz'],
    )

    _cache_internal(result, params)
    response_data = _strip_internal(result)
    _limit_result(response_data)
    return JsonResponse({'data': response_data})


@csrf_exempt
@require_POST
def get_range(request):
    f = request.FILES.get('file')
    if not f:
        return JsonResponse({'error': '파일이 없습니다.'}, status=400)
    log_tz = (request.POST.get('logTz') or 'UTC').upper()
    if log_tz not in ('UTC', 'KST'):
        log_tz = 'UTC'
    lines = _stream_lines_from_upload(f)
    result = compute_range(lines, log_tz=log_tz)
    return JsonResponse(result)


@csrf_exempt
def dashboard_filter(request):
    """
    GET /api/dashboard_filter/?from=YYYY-MM-DD HH:MM:SS&to=YYYY-MM-DD HH:MM:SS
    캐시된 세션 데이터를 시간 범위로 필터링해 IP Top 통계 반환.
    """
    sessions = _last_result_cache.get('sessions')
    ip_to_tids = _last_result_cache.get('ip_to_tids')
    if not sessions or not ip_to_tids:
        return JsonResponse({'error': '먼저 로그 분석을 실행하세요.'}, status=400)

    dropout_201 = _last_result_cache.get('dropout_201') or set()
    dropout_200 = _last_result_cache.get('dropout_200') or set()

    time_from = request.GET.get('from', '').strip()
    time_to = request.GET.get('to', '').strip()

    from .parser import epoch_to_str

    # ip -> [tid수, 대기시간합계, 대기이탈수, 진입이탈수]
    ip_stats = defaultdict(lambda: [0, 0.0, 0, 0])

    for ip, tid_list in ip_to_tids.items():
        for t in tid_list:
            s = sessions.get(t)
            if not s:
                continue
            st = s[2]
            start_str = epoch_to_str(st) if st else ''
            if time_from and start_str and start_str < time_from:
                continue
            if time_to and start_str and start_str > time_to:
                continue

            flags = s[1]
            we = s[3]
            has_5002 = flags & 2

            c = ip_stats[ip]
            c[0] += 1
            if has_5002 and st and we:
                c[1] += we - st
            if t in dropout_201:
                c[2] += 1
            if t in dropout_200:
                c[3] += 1

    def sort_top(idx, limit=50):
        items = [(ip, c[idx]) for ip, c in ip_stats.items() if c[idx] > 0]
        items.sort(key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': round(v, 1) if isinstance(v, float) else v}
                for ip, v in items[:limit]]

    return JsonResponse({'data': {
        'topIssueIP': sort_top(0),
        'topWaitIP': sort_top(1),
        'topQwIP': sort_top(2),
        'topPeIP': sort_top(3),
    }})


# ===== 멀티서버 통합 분석 (파일업로드 + 서버경로 혼합 지원) =====

@csrf_exempt
@require_POST
def analyze_multi(request):
    """
    POST /api/analyze_multi/
    FormData:
      count=N
      label_0=서버1  (file_0=FILE | path_0=/path/to/log)
      label_1=서버2  (file_1=FILE | path_1=/path/to/log)
      ...공통 분석 파라미터(pj, seg, timeoutSec 등)...
    Response: {data: {combined result + servers: [{label, data}, ...]}}
    """
    params = _get_params(request)
    count = int(request.POST.get('count', 0))
    if count < 1:
        return JsonResponse({'error': '서버를 1개 이상 입력하세요.'}, status=400)

    start_time = time.time()
    total_size = 0
    labeled_results = []

    for i in range(count):
        label = (request.POST.get(f'label_{i}') or f'서버 {i + 1}').strip()
        path = request.POST.get(f'path_{i}', '').strip().strip("'\"")
        f = request.FILES.get(f'file_{i}')

        if path:
            if not os.path.isfile(path):
                return JsonResponse({'error': f'[{label}] 파일을 찾을 수 없습니다: {path}'}, status=400)
            total_size += os.path.getsize(path)
            lines = _stream_lines_from_file(path)
        elif f:
            total_size += f.size
            lines = _stream_lines_from_upload(f)
        else:
            return JsonResponse({'error': f'[{label}] 파일 또는 경로가 필요합니다.'}, status=400)

        result = analyze_file(
            lines,
            pj=params['pj'], seg=params['seg'], seg_all=params['seg_all'],
            start_sec=params['start_sec'], end_sec=params['end_sec'],
            rps_enabled=params['rps_enabled'], rps_min=params['rps_min'],
            rps_max=params['rps_max'],
            hold_enabled=params['hold_enabled'], hold_sec=params['hold_sec'],
            timeout_sec=params['timeout_sec'], log_tz=params['log_tz'],
        )
        labeled_results.append((label, result))

    elapsed = round(time.time() - start_time, 1)

    # view 레이어에서 서버 라벨 스탬프 (parser는 라벨 불필요)
    for label, result in labeled_results:
        for item in result.get('topWaitTids', []):
            item['server'] = label
        for item in result.get('_raw', {}).get('top_wait_pool', []):
            item['server'] = label
        for row in result.get('quitWaitRows', []):
            row['server'] = label
        for row in result.get('postEnterRows', []):
            row['server'] = label

    # 통합 결과 생성
    if len(labeled_results) > 1:
        combined = merge_results(labeled_results)
    else:
        combined = labeled_results[0][1]

    # trace_ip용 캐시 저장 (멀티서버 prefix 적용)
    _cache_multi_internal(labeled_results, params)

    def prepare(result, label=None):
        rd = _strip_internal(result)
        _limit_result(rd)
        if label:
            rd['serverLabel'] = label
        return rd

    combined_data = prepare(combined)
    combined_data['elapsed'] = elapsed
    combined_data['fileSize'] = total_size
    combined_data['fileSizeMB'] = round(total_size / 1024 / 1024, 1)
    combined_data['servers'] = [
        {'label': label, 'data': prepare(result, label)}
        for label, result in labeled_results
    ]

    return JsonResponse({'data': combined_data})


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
