"""
parser.py — test.py(원본 CLI) 파싱 방식 기반.
로그 포맷:
  IP ELAPSED DAY, DD Mon YYYY HH:MM:SS "METHOD /ts.wseq?opcode=...&key=...&sid=...&aid=... HTTP/1.1"
  HTTP_STATUS BYTES "Referer" "UA" NF_STATUS TID PROJECT.SEGMENT

핵심: parts[-1]=proj.seg, parts[-2]=tid, parts[-3]=nf_status
3GB+ 파일도 스트리밍으로 처리. 성능 최적화: datetime 대신 epoch seconds 사용.
"""
import re
import math
from datetime import datetime, timezone
from collections import defaultdict
from calendar import timegm

# ===================== Helpers =====================

_MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def to_iso(sec):
    if sec is None or not isinstance(sec, (int, float)) or not math.isfinite(sec):
        return ''
    return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat()


def epoch_to_str(sec):
    """epoch seconds → 'YYYY-MM-DD HH:MM:SS' (KST = UTC+9)."""
    if not sec:
        return ''
    dt = datetime.utcfromtimestamp(sec + 32400)  # UTC+9 (KST)
    return f'{dt.year:04d}-{dt.month:02d}-{dt.day:02d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}'


# ---- Timestamp (fast, no strptime) ----
_DT_RE = re.compile(r'\w{3},\s+(\d{2})\s(\w{3})\s(\d{4})\s(\d{2}):(\d{2}):(\d{2})')


def parse_timestamp(line):
    """Returns datetime object for range/external use."""
    m = _DT_RE.search(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(f'{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}:{m.group(5)}:{m.group(6)}', '%d %b %Y %H:%M:%S')
        return dt
    except ValueError:
        return None


def _parse_epoch(line):
    """Fast epoch seconds parser — no datetime object creation."""
    m = _DT_RE.search(line)
    if not m:
        return None
    mon = _MONTHS.get(m.group(2))
    if not mon:
        return None
    return timegm((int(m.group(3)), mon, int(m.group(1)),
                   int(m.group(4)), int(m.group(5)), int(m.group(6))))


# ---- Core field extraction: 끝 3토큰 ----
_STATUS_RE = re.compile(r'^\d{3}$')


def parse_core_fields(parts):
    if len(parts) < 3:
        return None
    status_str, tid, proj_seg = parts[-3], parts[-2], parts[-1]
    if not _STATUS_RE.match(status_str):
        return None
    return tid, int(status_str), proj_seg


# ---- Opcode / sid / aid ----
_OPCODE_RE = re.compile(r'opcode=(\d+)')
_SID_RE    = re.compile(r'sid=([^&\s"]+)')
_AID_RE    = re.compile(r'aid=([^&\s"]+)')


def extract_opcode(url):
    m = _OPCODE_RE.search(url)
    return int(m.group(1)) if m else None


# ---- Request URL ----
_REQ_RE = re.compile(r'"([^"]+)"')
_PATH_HEAD = re.compile(r'^/ts\.wseq\b')


def extract_request_url(line):
    m = _REQ_RE.search(line)
    if not m:
        return None
    tokens = m.group(1).split()
    return tokens[1] if len(tokens) >= 2 else tokens[0]


# ---- Client IP ----
def extract_client_ip(parts):
    """Simple: first token is IP."""
    return parts[0] if parts else ''


# ---- Sticky ----
_STICKY_RE = re.compile(r'sticky=(nf[0-9a-zA-Z_-]+)', re.IGNORECASE)


def extract_sticky(line):
    m = _STICKY_RE.search(line)
    return m.group(1).lower() if m else None


# ---- Stats ----
def stat(arr):
    if not arr:
        return {'min': 0, 'max': 0, 'avg': 0, 'count': 0}
    return {'min': min(arr), 'max': max(arr), 'avg': sum(arr) / len(arr), 'count': len(arr)}


def percent(part, total):
    return (float(part) / total * 100) if total > 0 else 0.0


# ===================== Range Scanner =====================

def compute_range(lines_iter, max_field_scan=200_000):
    """타임스탬프 범위를 스캔하면서 sid(프로젝트)/aid(세그먼트) 고유값도 수집."""
    first_ts = None
    last_ts = None
    sids = set()
    aids = set()
    field_scanned = 0
    for raw_line in lines_iter:
        line = raw_line.rstrip('\r\n') if isinstance(raw_line, str) else raw_line.decode('utf-8', errors='replace').rstrip('\r\n')
        dt = parse_timestamp(line)
        if dt is not None:
            sec = int(dt.timestamp())
            if first_ts is None or sec < first_ts:
                first_ts = sec
            if last_ts is None or sec > last_ts:
                last_ts = sec
        if field_scanned < max_field_scan and 'ts.wseq' in line:
            field_scanned += 1
            m3 = _SID_RE.search(line)
            m4 = _AID_RE.search(line)
            if m3:
                sids.add(m3.group(1))
            if m4:
                aids.add(m4.group(1))
    return {
        'startSec': first_ts, 'endSec': last_ts,
        'startISO': to_iso(first_ts), 'endISO': to_iso(last_ts),
        'sids': sorted(sids), 'aids': sorted(aids),
    }


# ===================== Analyze =====================

def analyze_file(lines_iter, pj='', seg='', seg_all=False,
                 start_sec=None, end_sec=None,
                 ttl_sec=180, keep_sec=15,
                 rps_enabled=False, rps_min=1, rps_max=10,
                 hold_enabled=False, hold_sec=60,
                 timeout_sec=20,
                 progress_callback=None):
    target_proj_seg = f'{pj}.{seg}' if pj and seg and not seg_all else None

    TTL_MIN = max(0, rps_min) if rps_enabled else 1
    TTL_MAX = max(TTL_MIN, rps_max) if rps_enabled else 10
    KEEP_ORDER = max(TTL_MAX, hold_sec) if hold_enabled else 60

    # 세션 키: (sid, aid, tid) 복합키 — 같은 tid라도 sid·aid가 다르면 별개 세션
    # session value: list [ip, flags, start_sec, wait_end_sec, last_req_sec]
    # flags: bit 0=has_5101, bit 1=has_5002, bit 2=has_5004
    # Index: 0=ip, 1=flags, 2=start_sec, 3=wait_end_sec, 4=last_req_sec
    sessions = {}
    # 5004 fallback용 보조 인덱스: raw_tid → [composite_key, ...]
    # 5004 URL에 sid/aid 가 없거나 달라 정확한 복합키 조회 실패 시 사용
    tid_index = defaultdict(list)

    tids_with_5101 = set()
    tids_with_5002 = set()
    tids_with_5004 = set()
    wait_user_tids = set()
    entry_success_tids = set()
    entry_ips = set()

    gaps_5002 = []
    ts_req  = defaultdict(int)   # minute_epoch → 요청 수 (5101/5002 200·201)
    ts_wait = defaultdict(int)   # minute_epoch → 대기 수 (5002 201)
    ts_done = defaultdict(int)   # minute_epoch → 완료 수 (5004)

    code_cnt = defaultdict(int)
    code_map = defaultdict(list)

    first_ts_sec = None
    last_ts_sec = None
    line_count = 0

    for raw_line in lines_iter:
        line_count += 1
        if progress_callback and line_count % 200000 == 0:
            progress_callback(line_count)

        if 'ts.wseq' not in raw_line:
            continue

        parts = raw_line.split()
        if len(parts) < 3:
            continue
        status_str = parts[-3]
        if len(status_str) != 3 or not status_str.isdigit():
            continue
        status_code = int(status_str)
        tid = parts[-2]
        proj_seg = parts[-1]

        # 프로젝트.세그먼트 필터
        if target_proj_seg:
            if proj_seg != target_proj_seg:
                continue
        elif pj:
            dot = proj_seg.find('.')
            file_pj = proj_seg[:dot] if dot >= 0 else proj_seg
            if file_pj != pj:
                continue

        # URL 추출 (인라인)
        m = _REQ_RE.search(raw_line)
        if not m:
            continue
        tokens = m.group(1).split()
        url = tokens[1] if len(tokens) >= 2 else tokens[0]
        if not url.startswith('/ts.wseq'):
            continue

        # 타임스탬프 (epoch seconds, no datetime)
        tsec = _parse_epoch(raw_line)
        if not tsec:
            continue

        if first_ts_sec is None or tsec < first_ts_sec:
            first_ts_sec = tsec
        if last_ts_sec is None or tsec > last_ts_sec:
            last_ts_sec = tsec

        if start_sec is not None and tsec < start_sec:
            continue
        if end_sec is not None and tsec > end_sec:
            continue

        # opcode (인라인)
        m2 = _OPCODE_RE.search(url)
        if not m2:
            continue
        opcode = int(m2.group(1))

        # sid / aid 추출 → 세션 복합키 (같은 tid여도 sid·aid가 다르면 별개 세션)
        m3 = _SID_RE.search(url)
        m4 = _AID_RE.search(url)
        sid = m3.group(1) if m3 else ''
        aid = m4.group(1) if m4 else ''
        session_key = (sid, aid, tid)

        # IP (first token)
        client_ip = parts[0]

        # session lookup — 5004는 URL에 sid/aid 가 없을 수 있으므로 fallback 탐색
        sess = sessions.get(session_key)
        if sess is None:
            if opcode == 5004:
                # 정확한 복합키 없음 → 동일 raw tid 의 미완료 세션 중 탐색
                for candidate_key in reversed(tid_index.get(tid, [])):
                    candidate = sessions.get(candidate_key)
                    if candidate and (candidate[1] & 3) and not (candidate[1] & 4):
                        session_key = candidate_key
                        sess = candidate
                        break
                if sess is None:
                    continue  # 매칭 세션 없음, 이 라인 스킵
            else:
                sess = [client_ip, 0, 0, 0, 0]  # ip, flags, start, wait_end, last_req
                sessions[session_key] = sess
                tid_index[tid].append(session_key)

        sess[0] = client_ip

        if opcode == 5101:
            sess[1] |= 1  # has_5101
            tids_with_5101.add(session_key)
            entry_ips.add(client_ip)
            if sess[2] == 0 or tsec < sess[2]:
                sess[2] = tsec
            sess[4] = tsec

        elif opcode == 5002:
            if status_code not in (200, 201):
                code_key = str(status_code)
                code_cnt[code_key] += 1
                if len(code_map[code_key]) < 500:
                    code_map[code_key].append({
                        'timestamp': epoch_to_str(tsec), 'ip': client_ip,
                        'status': code_key, 'user': f'{client_ip}#{tid}',
                    })
                continue
            sess[1] |= 2  # has_5002
            tids_with_5002.add(session_key)
            entry_ips.add(client_ip)
            if sess[2] == 0 or tsec < sess[2]:
                sess[2] = tsec
            if tsec > sess[3]:
                sess[3] = tsec

            # gap
            if sess[4]:
                gaps_5002.append(tsec - sess[4])
            sess[4] = tsec

        elif opcode == 5004:
            sess[1] |= 4  # has_5004
            tids_with_5004.add(session_key)
            sess[4] = tsec  # 5004 완료 시각 기록

        # 시간대별 트래픽 집계 (분 단위 버킷)
        minute = (tsec // 60) * 60
        if opcode in (5101, 5002):
            ts_req[minute] += 1
            if status_code == 201:
                ts_wait[minute] += 1
        elif opcode == 5004:
            ts_done[minute] += 1

        # 집합 관리
        if opcode in (5101, 5002):
            if status_code == 201:
                wait_user_tids.add(session_key)
            if status_code == 200:
                entry_success_tids.add(session_key)

        # 상태코드 집계 (200/201 이외)
        if status_code not in (200, 201):
            code_key = str(status_code)
            code_cnt[code_key] += 1
            if len(code_map[code_key]) < 500:
                code_map[code_key].append({
                    'timestamp': epoch_to_str(tsec), 'ip': client_ip,
                    'status': code_key, 'user': f'{client_ip}#{tid}',
                })

    if progress_callback:
        progress_callback(line_count)

    # ---- 통계 산출 ----
    over_ttlmax_gaps = [g for g in gaps_5002 if g > TTL_MAX] if rps_enabled else []
    between_ttl_keep_gaps = [g for g in gaps_5002 if g > TTL_MAX and g <= KEEP_ORDER] if (rps_enabled and hold_enabled) else []
    over_keep_gaps = [g for g in gaps_5002 if g > KEEP_ORDER] if (rps_enabled and hold_enabled) else []

    entry_tids = tids_with_5101 | tids_with_5002
    entry_count = len(entry_tids)
    wait_count = len(wait_user_tids)
    complete_count = len(tids_with_5004)

    dropout_tids_201 = wait_user_tids - tids_with_5004
    dropout_count_201 = len(dropout_tids_201)
    dropout_tids_200 = entry_success_tids - tids_with_5004
    dropout_count_200 = len(dropout_tids_200)

    qw_rate = percent(dropout_count_201, wait_count)
    pe_rate = percent(dropout_count_200, len(entry_success_tids))

    code_details = sorted(
        [{'code': code, 'cnt': len(rows), 'rows': rows} for code, rows in code_map.items()],
        key=lambda x: x['cnt'], reverse=True,
    )

    anom_rows = []

    # ---- 단일 순회: 대기시간 + CSV + IP통계 + 역인덱스 ----
    returned_wait_times = []
    dropped_wait_times = []
    top_wait_tids_list = []
    all_durations = []
    quit_wait_rows = []
    post_enter_rows = []
    ip_counts = defaultdict(lambda: [0, 0, 0, 0, 0, 0.0])
    ip_times = {}  # ip -> (min_sec, max_sec)
    ip_to_tids_map = defaultdict(list)

    for sess_key, s in sessions.items():
        _sid, _aid, tid_k = sess_key   # 복합키 언패킹 — tid_k 가 표시용 원래 tid
        ip = s[0]
        flags = s[1]
        st = s[2]
        we = s[3]
        has_5002 = flags & 2
        has_5004 = flags & 4
        has_wait = has_5002 and st and we
        wait_secs = (we - st) if has_wait else 0

        if has_wait:
            (returned_wait_times if has_5004 else dropped_wait_times).append(wait_secs)

        # 세션 전체 처리시간: start_sec → last_req_sec(5004 포함)
        last = s[4]
        duration = (last - st) if (st and last and last > st) else 0
        if duration > 0 and duration <= timeout_sec:
            all_durations.append(duration)
            top_wait_tids_list.append({
                'tid': tid_k, 'ip': ip or '',
                'wait_secs': round(duration, 1),
                'start_time': epoch_to_str(st),
                'timestamp': epoch_to_str(last),
                'server': '',  # views.py에서 서버 라벨로 채워짐
            })

        if sess_key in dropout_tids_201:
            quit_wait_rows.append({
                'timestamp': epoch_to_str(we or st),
                'ip': ip or '', 'tid': tid_k,
                'status': 'WAIT(201)_NO_5004',
            })
        elif sess_key in dropout_tids_200:
            post_enter_rows.append({
                'timestamp': epoch_to_str(we or st),
                'ip': ip or '', 'tid': tid_k,
                'status': 'ENTER(200)_NO_5004',
            })

        if not ip:
            continue
        ip_to_tids_map[ip].append(sess_key)
        c = ip_counts[ip]
        if sess_key in entry_success_tids:
            c[0] += 1
        if sess_key in wait_user_tids:
            c[1] += 1
        if has_5004:
            c[2] += 1
        if sess_key in dropout_tids_201:
            c[3] += 1
        if sess_key in dropout_tids_200:
            c[4] += 1
        if has_wait:
            c[5] += wait_secs

        if st:
            prev = ip_times.get(ip)
            if prev is None:
                ip_times[ip] = (st, st)
            else:
                ip_times[ip] = (min(prev[0], st), max(prev[1], st))

    # ip_times를 문자열로 변환
    ip_times = {ip: (epoch_to_str(mn), epoch_to_str(mx)) for ip, (mn, mx) in ip_times.items()}

    # Top IP
    def top_ip(idx, limit=50):
        items = [(ip, c[idx]) for ip, c in ip_counts.items() if c[idx] > 0]
        items.sort(key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': v} for ip, v in items[:limit]]

    top_issue_ip = top_ip(0)
    top_wait_ip = [{'ip': ip, 'count': round(c[5], 1)} for ip, c in ip_counts.items() if c[5] > 0]
    top_wait_ip.sort(key=lambda x: x['count'], reverse=True)
    top_wait_ip = top_wait_ip[:50]
    top_qw_ip = top_ip(3)
    top_pe_ip = top_ip(4)

    top_wait_tids_list.sort(key=lambda x: x['wait_secs'], reverse=True)
    top_wait_tids = top_wait_tids_list[:5]

    # 시간대별 시리즈
    _all_min = sorted(set(ts_req) | set(ts_wait) | set(ts_done))
    time_series = [
        {'time': epoch_to_str(m), 'req': ts_req.get(m, 0), 'wait': ts_wait.get(m, 0), 'done': ts_done.get(m, 0)}
        for m in _all_min
    ]

    # 처리시간 분포 히스토그램 (5개 균등 구간)
    if all_durations and timeout_sec > 0:
        _bsize = timeout_sec / 5
        _hcnt = [0] * 5
        for _d in all_durations:
            _hcnt[min(int(_d / _bsize), 4)] += 1
        dur_histogram = [
            {'label': f'{int(i * _bsize)}~{int((i + 1) * _bsize)}초', 'count': _hcnt[i]}
            for i in range(5)
        ]
    else:
        dur_histogram = []

    return {
        'range': {
            'startSec': first_ts_sec, 'endSec': last_ts_sec,
            'startISO': to_iso(first_ts_sec), 'endISO': to_iso(last_ts_sec),
        },
        'kpis': {
            'enterIPCnt': len(entry_ips),
            'reqUserCnt': entry_count,
            'waitUserCnt': wait_count,
            'doneUserCnt': complete_count,
            'quitWaitCnt': dropout_count_201,
            'postEnterLeaveCnt': dropout_count_200,
            'qwRate': qw_rate,
            'peRate': pe_rate,
            'entrySuccessCount': len(entry_success_tids),  # merge 시 peRate 재계산용
        },
        'rpsStats': {
            'all': stat(gaps_5002),
            'overMax': stat(over_ttlmax_gaps),
            'holdAct': stat(between_ttl_keep_gaps),
            'holdOver': stat(over_keep_gaps),
        },
        'waitDurStats': {
            'enter': stat(returned_wait_times),
            'quit': stat(dropped_wait_times),
        },
        'durationStats': stat(all_durations),
        'timeSeries': time_series,
        'durHistogram': dur_histogram,
        'timeoutSec': timeout_sec,
        'topWaitTids': top_wait_tids,
        'codeDetails': code_details,
        # ---- 멀티서버 merge용 raw 데이터 (응답에서 _strip_internal로 제거됨) ----
        '_raw': {
            'gaps': gaps_5002,
            'over_ttlmax': over_ttlmax_gaps,
            'between': between_ttl_keep_gaps,
            'over_keep': over_keep_gaps,
            'returned_wait': returned_wait_times,
            'dropped_wait': dropped_wait_times,
            'durations': all_durations,
            'entry_ips': list(entry_ips),
            'top_wait_pool': top_wait_tids_list[:50],  # top 5보다 큰 pool (merge 재순위용)
            'code_cnt': dict(code_cnt),                # 실제 발생 건수 (500개 캡 미적용)
            'ts_req': dict(ts_req),
            'ts_wait': dict(ts_wait),
            'ts_done': dict(ts_done),
        },
        'quitWaitRows': quit_wait_rows,
        'postEnterRows': post_enter_rows,
        'anomRows': anom_rows,
        'totalCodes': sum(code_cnt.values()),
        'lineCount': line_count,
        'topIssueIP': top_issue_ip,
        'topWaitIP': top_wait_ip,
        'topQwIP': top_qw_ip,
        'topPeIP': top_pe_ip,
        # 사용자추적 서버 캐시용
        '_sessions': sessions,
        '_dropout_201': dropout_tids_201,
        '_dropout_200': dropout_tids_200,
        '_ip_counts': dict(ip_counts),
        '_ip_times': ip_times,
        '_ip_to_tids': dict(ip_to_tids_map),
    }
