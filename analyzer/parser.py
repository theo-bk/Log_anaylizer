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
    """epoch seconds → 'YYYY-MM-DD HH:MM:SS' (UTC)."""
    if not sec:
        return ''
    dt = datetime.utcfromtimestamp(sec)
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


# ---- Opcode ----
_OPCODE_RE = re.compile(r'opcode=(\d+)')


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

def compute_range(lines_iter):
    first_ts = None
    last_ts = None
    for raw_line in lines_iter:
        line = raw_line.rstrip('\r\n') if isinstance(raw_line, str) else raw_line.decode('utf-8', errors='replace').rstrip('\r\n')
        dt = parse_timestamp(line)
        if dt is not None:
            sec = int(dt.timestamp())
            if first_ts is None or sec < first_ts:
                first_ts = sec
            if last_ts is None or sec > last_ts:
                last_ts = sec
    return {
        'startSec': first_ts, 'endSec': last_ts,
        'startISO': to_iso(first_ts), 'endISO': to_iso(last_ts),
    }


# ===================== Analyze =====================

def analyze_file(lines_iter, pj='', seg='', seg_all=False,
                 start_sec=None, end_sec=None,
                 ttl_sec=180, keep_sec=15,
                 rps_enabled=False, rps_min=1, rps_max=10,
                 hold_enabled=False, hold_sec=60,
                 progress_callback=None):
    target_proj_seg = f'{pj}.{seg}' if pj and seg and not seg_all else None

    TTL_MIN = max(0, rps_min) if rps_enabled else 1
    TTL_MAX = max(TTL_MIN, rps_max) if rps_enabled else 10
    KEEP_ORDER = max(TTL_MAX, hold_sec) if hold_enabled else 60

    # per-tid session: use list [ip, flags, start_sec, wait_end_sec, last_req_sec]
    # flags: bit 0=has_5101, bit 1=has_5002, bit 2=has_5004
    # Index: 0=ip, 1=flags, 2=start_sec, 3=wait_end_sec, 4=last_req_sec
    sessions = {}

    tids_with_5101 = set()
    tids_with_5002 = set()
    tids_with_5004 = set()
    wait_user_tids = set()
    entry_success_tids = set()
    entry_ips = set()

    gaps_5002 = []
    server_stats = defaultdict(lambda: [0, 0, 0])  # [issue, wait, ret]

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

        # IP (first token)
        client_ip = parts[0]

        # session (list-based for speed)
        sess = sessions.get(tid)
        if sess is None:
            sess = [client_ip, 0, 0, 0, 0]  # ip, flags, start, wait_end, last_req
            sessions[tid] = sess
        else:
            sess[0] = client_ip

        if opcode == 5101:
            sess[1] |= 1  # has_5101
            tids_with_5101.add(tid)
            entry_ips.add(client_ip)
            if sess[2] == 0 or tsec < sess[2]:
                sess[2] = tsec
            sess[4] = tsec

        elif opcode == 5002:
            if status_code not in (200, 201):
                continue
            sess[1] |= 2  # has_5002
            tids_with_5002.add(tid)
            entry_ips.add(client_ip)
            if sess[2] == 0 or tsec < sess[2]:
                sess[2] = tsec
            if tsec > sess[3]:
                sess[3] = tsec

            # gap
            if sess[4]:
                gaps_5002.append(tsec - sess[4])
            sess[4] = tsec

            # sticky/server
            ms = _STICKY_RE.search(raw_line)
            if ms:
                srv = ms.group(1).lower()
                if status_code == 200:
                    server_stats[srv][0] += 1
                else:
                    server_stats[srv][1] += 1

        elif opcode == 5004:
            sess[1] |= 4  # has_5004
            tids_with_5004.add(tid)

        # 집합 관리
        if opcode in (5101, 5002):
            if status_code == 201:
                wait_user_tids.add(tid)
            if status_code == 200:
                entry_success_tids.add(tid)

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

    server_rows = sorted(
        [{'server': srv, 'issue_200': v[0], 'wait_201': v[1], 'return_502': v[2]}
         for srv, v in server_stats.items()],
        key=lambda r: r['issue_200'] + r['wait_201'], reverse=True,
    )

    code_details = sorted(
        [{'code': code, 'cnt': len(rows), 'rows': rows} for code, rows in code_map.items()],
        key=lambda x: x['cnt'], reverse=True,
    )

    anom_rows = []

    # ---- 단일 순회: 대기시간 + CSV + IP통계 + 역인덱스 ----
    returned_wait_times = []
    dropped_wait_times = []
    quit_wait_rows = []
    post_enter_rows = []
    ip_counts = defaultdict(lambda: [0, 0, 0, 0, 0, 0.0])
    ip_times = {}  # ip -> (min_sec, max_sec)
    ip_to_tids_map = defaultdict(list)

    for tid_key, s in sessions.items():
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

        if tid_key in dropout_tids_201:
            quit_wait_rows.append({
                'timestamp': epoch_to_str(we or st),
                'ip': ip or '', 'tid': tid_key,
                'status': 'WAIT(201)_NO_5004',
            })
        elif tid_key in dropout_tids_200:
            post_enter_rows.append({
                'timestamp': epoch_to_str(we or st),
                'ip': ip or '', 'tid': tid_key,
                'status': 'ENTER(200)_NO_5004',
            })

        if not ip:
            continue
        ip_to_tids_map[ip].append(tid_key)
        c = ip_counts[ip]
        if tid_key in entry_success_tids:
            c[0] += 1
        if tid_key in wait_user_tids:
            c[1] += 1
        if has_5004:
            c[2] += 1
        if tid_key in dropout_tids_201:
            c[3] += 1
        if tid_key in dropout_tids_200:
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
        'serverRows': server_rows,
        'codeDetails': code_details,
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
