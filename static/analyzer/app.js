// app.js — Django API를 fetch()/SSE로 호출하는 프론트엔드.
// 소용량: 파일 업로드 방식, 대용량(3GB+): 서버 경로 입력 + SSE 방식.
(function () {
  const $ = (sel) => document.querySelector(sel);

  // ====== 엘리먼트 ======
  const $file       = $('#fileInput');
  const $filePath   = $('#filePath');
  const $fileName   = $('#fileName');
  const $project    = $('#project');
  const $segment    = $('#segment');

  const $dateStart  = $('#dateStart');
  const $timeStart  = $('#timeStart');
  const $dateEnd    = $('#dateEnd');
  const $timeEnd    = $('#timeEnd');

  const $rangeStart = $('#rangeStart');
  const $rangeEnd   = $('#rangeEnd');
  const $fileInfo   = $('#fileInfo');

  const $analyzeBtn = $('#analyzeBtn');
  const $cancelBtn  = $('#cancelBtn');

  const $chkRPS     = $('#chkRPS');
  const $rpsFields  = $('#rpsFields');
  const $rpsMin     = $('#rpsMin');
  const $rpsMax     = $('#rpsMax');

  const $chkHold    = $('#chkHold');
  const $holdFields = $('#holdFields');
  const $holdSec    = $('#holdSec');

  const $progressSection = $('#progressSection');
  const $progressText = $('#progressText');
  const $progressBar  = $('#progressBar');

  // KPI
  const $k_enter_ip  = $('#kpi-enter-ip');
  const $k_req_user  = $('#kpi-req-user');
  const $k_wait_user = $('#kpi-wait-user');
  const $k_done_user = $('#kpi-done-user');
  const $k_qw        = $('#kpi-qw');
  const $k_qw_rate   = $('#kpi-qw-rate');
  const $k_pe        = $('#kpi-pe');
  const $k_pe_rate   = $('#kpi-pe-rate');

  const $codeCards   = $('#codeCards');
  const $serverTable = document.querySelector('#serverTable tbody');

  // 탭/패널
  const $tabAnalyze  = document.querySelector('.tab[data-tab="analyze"]');
  const $tabTrace    = document.querySelector('.tab[data-tab="trace"]');
  const $tabDash     = document.querySelector('.tab[data-tab="dash"]');
  const $panelAnalyze= $('#panel-analyze');
  const $panelTrace  = $('#panel-trace');
  const $panelDash   = $('#panel-dash');

  const CODE_DESC = {
    '300': '다른 위치로 이동(리다이렉트)', '301': '영구 이동', '302': '임시 이동',
    '304': '수정되지 않음', '400': '잘못된 요청', '401': '인증 필요',
    '403': '금지됨', '404': '대상 없음', '408': '요청 시간 초과',
    '409': '충돌', '429': '요청 과다(Too Many Requests)', '500': '서버 내부 오류',
    '502': '이미 종료된 key(반납)', '503': '서비스 이용 불가',
    '504': '게이트웨이 시간 초과', '516': '요청 포맷 오류',
    '993': '권한이 없음', '994': '만료 날짜 경과'
  };

  let lastResult = null;
  let currentSSE = null; // SSE abort용

  // ====== CSV helper ======
  function downloadCSV(filename, rows, headers) {
    if (!rows || !rows.length) { alert('데이터 없음'); return; }
    const cols = headers && headers.length ? headers : Object.keys(rows[0]);
    const esc = (v) => `"${String(v ?? '').replace(/"/g,'""')}"`;
    const csv = [cols.join(','), ...rows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  // ====== 유틸 ======
  const pad2 = (n) => String(n).padStart(2, '0');
  const toLocalParts = (iso) => {
    if (!iso) return { d: '', t: '' };
    const d = new Date(iso);
    if (isNaN(d.getTime())) return { d: '', t: '' };
    return { d: `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`, t: `${pad2(d.getHours())}:${pad2(d.getMinutes())}` };
  };

  const setProgress = (p, extra) => {
    if ($progressSection?.classList.contains('hidden')) $progressSection.classList.remove('hidden');
    const txt = extra ? `${p}% — ${extra}` : `${p}%`;
    if ($progressText) $progressText.textContent = txt;
    if ($progressBar) { $progressBar.value = p; $progressBar.max = 100; }
  };
  const hideProgress = () => {
    if (!$progressSection) return;
    $progressSection.classList.add('hidden');
    if ($progressText) $progressText.textContent = '0%';
    if ($progressBar)  $progressBar.value = 0;
  };

  const setDetectedRange = (d) => {
    const a = toLocalParts(d.startISO);
    const b = toLocalParts(d.endISO);
    if ($dateStart && a.d) $dateStart.value = a.d;
    if ($timeStart && a.t) $timeStart.value = a.t;
    if ($dateEnd && b.d) $dateEnd.value = b.d;
    if ($timeEnd && b.t) $timeEnd.value = b.t;
    if ($rangeStart) $rangeStart.textContent = d.startISO || '-';
    if ($rangeEnd)   $rangeEnd.textContent   = d.endISO   || '-';
    if ($fileInfo && d.fileSizeMB) $fileInfo.textContent = `(${d.fileSizeMB} MB)`;
  };

  const toEpochFromInputs = () => {
    const ds = $dateStart?.value, ts = $timeStart?.value;
    const de = $dateEnd?.value,   te = $timeEnd?.value;
    const s = (ds && ts) ? new Date(`${ds}T${ts}:00`) : null;
    const e = (de && te) ? new Date(`${de}T${te}:00`) : null;
    return {
      startSec: s && !isNaN(s.getTime()) ? Math.floor(s.getTime() / 1000) : undefined,
      endSec:   e && !isNaN(e.getTime()) ? Math.floor(e.getTime() / 1000) : undefined,
    };
  };

  const fmt = (n) => Number.isFinite(n) ? n.toLocaleString('ko-KR') : '0';
  const fmtPct = (n) => Number.isFinite(n) ? `${n.toFixed(2)}%` : '0.00%';
  const fmt2 = (n) => Number.isFinite(n) ? Number(n).toFixed(2) : '0.00';

  // ====== 입력 모드 ======
  function getInputMode() {
    const path = $filePath?.value?.trim();
    if (path) return 'path';
    const f = $file?.files?.[0];
    if (f) return 'upload';
    return null;
  }

  // ====== 경로 입력 → 범위 자동 탐지 ======
  let pathDebounce = null;
  $filePath?.addEventListener('input', () => {
    clearTimeout(pathDebounce);
    pathDebounce = setTimeout(async () => {
      const path = $filePath.value.trim();
      if (!path) return;
      try {
        const resp = await fetch(`/api/range_path/?path=${encodeURIComponent(path)}`);
        const data = await resp.json();
        if (data.error) { if ($fileInfo) $fileInfo.textContent = data.error; return; }
        setDetectedRange(data);
      } catch (e) {
        if ($fileInfo) $fileInfo.textContent = '경로 확인 실패';
      }
    }, 500);
  });

  // 파일 업로드 → 범위 (소용량)
  $file?.addEventListener('change', async () => {
    const f = $file.files?.[0];
    if (!f) return;
    if ($fileName) $fileName.textContent = `${f.name} (${(f.size / 1024 / 1024).toFixed(1)} MB)`;
    setProgress(10);
    const fd = new FormData();
    fd.append('file', f);
    try {
      const resp = await fetch('/api/range/', { method: 'POST', body: fd });
      const data = await resp.json();
      setDetectedRange(data);
      hideProgress();
    } catch (err) {
      alert('범위 탐지 실패: ' + err.message);
      hideProgress();
    }
  });

  // ====== 탭 ======
  function showTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${name}"]`)?.classList.add('active');
    [$panelAnalyze, $panelTrace, $panelDash].forEach(p => p?.classList.add('hidden'));
    document.getElementById(`panel-${name}`)?.classList.remove('hidden');
  }
  function bindTabsOnce() {
    document.querySelectorAll('.tab').forEach(tab => {
      if (tab.dataset.bound === '1') return;
      tab.dataset.bound = '1';
      tab.addEventListener('click', () => { if (!tab.classList.contains('disabled')) showTab(tab.dataset.tab); });
    });
  }
  function enableResultTabs() {
    [$tabTrace, $tabDash].forEach(t => {
      if (!t) return;
      t.classList.remove('disabled');
      t.style.pointerEvents = 'auto'; t.style.opacity = '1'; t.style.cursor = 'pointer';
      t.removeAttribute('title');
    });
  }

  // ====== 옵션 토글 ======
  function toggleRPSFields() {
    const on = !!$chkRPS?.checked;
    $rpsFields?.classList.toggle('show', on);
    [$rpsMin, $rpsMax].filter(Boolean).forEach(el => el.disabled = !on);
  }
  function toggleHoldFields() {
    const on = !!$chkHold?.checked;
    if ($holdFields) $holdFields.classList.toggle('show', on);
    if ($holdSec) $holdSec.disabled = !on;
  }
  $chkRPS?.addEventListener('change', toggleRPSFields);
  $chkHold?.addEventListener('change', toggleHoldFields);
  toggleRPSFields(); toggleHoldFields();

  // ====== 분석 공통 파라미터 ======
  function getQueryParams() {
    const { startSec, endSec } = toEpochFromInputs();
    const p = new URLSearchParams();
    p.set('pj', $project?.value?.trim() || '');
    p.set('seg', $segment?.value?.trim() || '');
    p.set('segAll', $segment?.value?.trim() ? 'false' : 'true');
    if (startSec !== undefined) p.set('startSec', startSec);
    if (endSec !== undefined)   p.set('endSec', endSec);
    p.set('rpsEnabled', $chkRPS?.checked ? 'true' : 'false');
    p.set('rpsMin', $rpsMin?.value || '1');
    p.set('rpsMax', $rpsMax?.value || '10');
    p.set('holdEnabled', $chkHold?.checked ? 'true' : 'false');
    p.set('holdSec', $holdSec?.value || '60');
    return p;
  }

  // ====== 서버 경로 분석 (동기 JSON) ======
  async function analyzeByPath(filePath) {
    const params = getQueryParams();
    params.set('path', filePath);

    setProgress(50, '서버에서 분석 중... (대용량 파일은 30초 이상 걸릴 수 있습니다)');
    $analyzeBtn.disabled = true;
    $cancelBtn.disabled = false;

    const url = `/api/analyze_path/?${params.toString()}`;
    const ctrl = new AbortController();
    currentSSE = ctrl;

    try {
      const resp = await fetch(url, { signal: ctrl.signal });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const json = await resp.json();
      const data = json.data;
      const extra = `${(data.lineCount||0).toLocaleString()} 줄 / ${data.elapsed||0}초 / ${data.fileSizeMB||0} MB`;
      setProgress(100, `완료 — ${extra}`);
      handleResult(data);
    } catch (err) {
      if (err.name === 'AbortError') {
        setProgress(0, '취소됨');
      } else {
        alert('분석 오류: ' + err.message);
        hideProgress();
      }
    } finally {
      $analyzeBtn.disabled = false;
      $cancelBtn.disabled = true;
      currentSSE = null;
    }
  }

  // ====== 업로드 분석 (소용량) ======
  async function analyzeByUpload(file) {
    const params = getQueryParams();
    const fd = new FormData();
    fd.append('file', file);
    for (const [k, v] of params.entries()) fd.append(k, v);

    setProgress(10, '업로드 중...');
    $analyzeBtn.disabled = true;

    try {
      const resp = await fetch('/api/analyze/', { method: 'POST', body: fd });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      handleResult(json.data);
    } catch (err) {
      alert('분석 오류: ' + err.message);
      hideProgress();
    } finally {
      $analyzeBtn.disabled = false;
    }
  }

  // ====== 결과 처리 ======
  function handleResult(data) {
    lastResult = data;
    setProgress(100, `완료 — ${(data.lineCount||0).toLocaleString()} 줄 처리됨`);
    if (data.range) setDetectedRange(data.range);
    renderKPIs(data.kpis);
    renderCodes(data.codeDetails || [], Number(data.totalCodes || 0));
    renderServers(data.serverRows || []);
    renderDetailStats(data);
    bindCSVButtons(data);
    renderDashboard(data);
    enableResultTabs();
    bindTabsOnce();
  }

  // ====== 분석 버튼 ======
  $analyzeBtn?.addEventListener('click', () => {
    const mode = getInputMode();
    if (mode === 'path') {
      analyzeByPath($filePath.value.trim());
    } else if (mode === 'upload') {
      analyzeByUpload($file.files[0]);
    } else {
      alert('로그 파일을 선택하거나 서버 경로를 입력하세요.');
    }
  });

  $cancelBtn?.addEventListener('click', () => {
    if (currentSSE) { currentSSE.abort(); currentSSE = null; }
    hideProgress();
  });

  // ====== 렌더러 ======
  function renderKPIs(k) {
    if ($k_enter_ip)  $k_enter_ip.textContent  = fmt(k.enterIPCnt);
    if ($k_req_user)  $k_req_user.textContent  = fmt(k.reqUserCnt);
    if ($k_wait_user) $k_wait_user.textContent = fmt(k.waitUserCnt);
    if ($k_done_user) $k_done_user.textContent = fmt(k.doneUserCnt);
    if ($k_qw)        $k_qw.textContent        = fmt(k.quitWaitCnt);
    if ($k_qw_rate)   $k_qw_rate.textContent   = fmtPct(k.qwRate);
    if ($k_pe)        $k_pe.textContent        = fmt(k.postEnterLeaveCnt);
    if ($k_pe_rate)   $k_pe_rate.textContent   = fmtPct(k.peRate);
  }

  function renderCodes(details, totalAll = 0) {
    if (!$codeCards) return;
    $codeCards.innerHTML = '';
    const list = Array.isArray(details) ? details.filter(it => !/^2/.test(String(it.code))) : [];
    if (!list.length) { $codeCards.innerHTML = '<div class="subtle">데이터 없음</div>'; return; }
    const sum = totalAll > 0 ? totalAll : list.reduce((s, x) => s + (Number(x.cnt) || 0), 0);
    list.slice(0, 24).forEach(item => {
      const code = String(item.code), cnt = Number(item.cnt) || 0;
      const rows = Array.isArray(item.rows) ? item.rows : [];
      const pct = sum ? (cnt / sum * 100) : 0;
      const div = document.createElement('div'); div.className = 'codecard';
      const desc = CODE_DESC[code] ? `<div class="desc">${CODE_DESC[code]}</div>` : '';
      div.innerHTML = `<div class="title">Status ${code}</div>${desc}<div class="big">${fmt(cnt)}</div><div class="pct">${pct.toFixed(2)}%</div><button type="button">CSV 다운로드</button>`;
      div.querySelector('button')?.addEventListener('click', () => {
        if (!rows.length) return alert('상세 로그 없음');
        downloadCSV(`status_${code}.csv`, rows, ['timestamp','ip','status','user']);
      });
      $codeCards.appendChild(div);
    });
  }

  function renderServers(rows) {
    if (!$serverTable) return;
    $serverTable.innerHTML = '';
    rows.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${r.server || '-'}</td><td>${fmt(r.issue_200)}</td><td>${fmt(r.wait_201)}</td>`;
      $serverTable.appendChild(tr);
    });
  }

  function renderDetailStats(data) {
    const rs = data.rpsStats || {}, wd = data.waitDurStats || {};
    const all = rs.all || {}, overMax = rs.overMax || {}, holdAct = rs.holdAct || {}, holdOver = rs.holdOver || {};
    const enter = wd.enter || {}, quit = wd.quit || {};
    const el = (id) => document.getElementById(id);
    const s = (o) => `최소=${fmt(o.min||0)} / 최대=${fmt(o.max||0)} / 평균=${fmt2(o.avg||0)}`;
    const sc = (o) => `${fmt(o.count||0)} 건 (${s(o)})`;
    if (el('stat-rps'))       el('stat-rps').textContent = s(all);
    if (el('stat-rps-over'))  el('stat-rps-over').textContent = sc(overMax);
    if (el('stat-hold-act'))  el('stat-hold-act').textContent = sc(holdAct);
    if (el('stat-hold-over')) el('stat-hold-over').textContent = sc(holdOver);
    if (el('stat-wait-enter'))el('stat-wait-enter').textContent = s(enter);
    if (el('stat-wait-quit')) el('stat-wait-quit').textContent = s(quit);
  }

  function bindCSVButtons(data) {
    const bind = (id, rows, filename, headers) => {
      const btn = document.getElementById(id);
      if (btn) btn.onclick = () => {
        if (!rows?.length) return alert('데이터 없음');
        downloadCSV(filename, rows, headers);
      };
    };
    bind('btn-qw-csv', data.quitWaitRows, 'quit_wait_users.csv', ['timestamp','ip','tid','status']);
    bind('btn-pe-csv', data.postEnterRows, 'enter_no_done_users.csv', ['timestamp','ip','tid','status']);
    bind('btn-server-csv', data.serverRows, 'server_sticky_summary.csv', ['server','issue_200','wait_201','return_502']);
    bind('btn-anom-csv', data.anomRows, 'server_mixed_users.csv', ['timestamp','ip','tid','flow','samples']);
    const anomBadge = document.getElementById('anomCnt');
    if (anomBadge) anomBadge.textContent = (data.anomRows?.length || 0).toLocaleString('ko-KR');
  }

  // ====== 대시보드: IP Top 테이블 ======
  function renderDashboard(data) {
    function fillTable(tableId, rows, valLabel) {
      const tbody = document.querySelector(`#${tableId} tbody`);
      if (!tbody) return;
      tbody.innerHTML = '';
      (rows || []).forEach((r, i) => {
        const tr = document.createElement('tr');
        const ipLink = `<a href="#" class="ip-link" data-ip="${r.ip}" style="color:#4f46e5;text-decoration:underline;cursor:pointer">${r.ip}</a>`;
        tr.innerHTML = `<td>${ipLink}</td><td>${typeof r.count === 'number' && r.count % 1 !== 0 ? r.count.toFixed(1) : fmt(r.count)}</td>`;
        tbody.appendChild(tr);
      });
    }
    fillTable('top-issue', data.topIssueIP, '발급 tid 수');
    fillTable('top-wait', data.topWaitIP, '총 대기시간(s)');
    fillTable('top-qw', data.topQwIP, '이탈 tid 수');
    fillTable('top-pe', data.topPeIP, '이탈 tid 수');

    // CSV 버튼
    const csvBind = (id, rows) => {
      const btn = document.getElementById(id);
      if (btn) btn.onclick = () => {
        if (!rows?.length) return alert('데이터 없음');
        downloadCSV(`${id}.csv`, rows, ['ip', 'count']);
      };
    };
    csvBind('csv-issue', data.topIssueIP);
    csvBind('csv-wait', data.topWaitIP);
    csvBind('csv-qw', data.topQwIP);
    csvBind('csv-pe', data.topPeIP);

    // IP 클릭 → 사용자 추적 탭으로 이동
    document.querySelectorAll('#panel-dash .ip-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const ip = link.dataset.ip;
        if ($traceIp) $traceIp.value = ip;
        showTab('trace');
        doTrace(ip);
      });
    });
  }

  // ====== 사용자 추적 ======
  const $traceIp = $('#trace-ip');
  const $traceFrom = $('#trace-from');
  const $traceTo = $('#trace-to');
  const $traceBtn = $('#traceBtn');
  const $traceResult = $('#traceResult');
  const $traceBox = $('#traceBox');
  const $traceHint = $('#traceHint');

  async function doTrace(ip) {
    if (!lastResult) {
      if ($traceHint) $traceHint.textContent = '먼저 로그 분석을 실행하세요.';
      return;
    }
    if ($traceHint) $traceHint.textContent = '검색 중...';
    if ($traceResult) $traceResult.style.display = 'none';

    try {
      let traceUrl = `/api/trace/?ip=${encodeURIComponent(ip)}`;
      const fromVal = $traceFrom?.value;
      const toVal = $traceTo?.value;
      if (fromVal) traceUrl += `&from=${encodeURIComponent(fromVal.replace('T', ' '))}`;
      if (toVal) traceUrl += `&to=${encodeURIComponent(toVal.replace('T', ' '))}`;
      const resp = await fetch(traceUrl);
      const json = await resp.json();
      if (json.error) {
        if ($traceHint) $traceHint.textContent = json.error;
        return;
      }
      const sess = json.data;
      if (!sess) {
        if ($traceHint) $traceHint.textContent = `"${ip}"에 해당하는 세션이 없습니다.`;
        return;
      }
      const filterInfo = sess.filteredCount !== undefined && sess.filteredCount !== sess.tidCount
        ? ` (필터: ${sess.filteredCount}개)` : '';
      if ($traceHint) $traceHint.textContent = `${sess.tidCount}개 세션${filterInfo} / 총 대기 ${sess.totalWaitSec}초 / ${sess.firstSeen} ~ ${sess.lastSeen}`;
      if ($traceResult) $traceResult.style.display = '';
      if (!$traceBox) return;

      const tids = sess.tids || [];
      let html = `<table class="trace-table">
        <thead><tr><th>TID</th><th>상태</th><th>시작</th><th>종료</th><th>대기(초)</th><th>opcode</th></tr></thead><tbody>`;
      tids.forEach(t => {
        const cls = t.status === '완료(5004)' ? '' : (t.status.includes('이탈') ? 'style="color:#b91c1c;font-weight:700"' : '');
        html += `<tr ${cls}><td style="font-family:monospace;font-size:13px">${t.tid}</td><td>${t.status}</td><td>${t.start}</td><td>${t.end}</td><td>${t.waitSec}</td><td>${t.opcode}</td></tr>`;
      });
      html += '</tbody></table>';
      if (sess.truncated) html += `<div class="subtle" style="margin-top:8px">결과가 많아 500개까지만 표시됩니다. 시간대 필터를 사용하세요.</div>`;
      $traceBox.innerHTML = html;
    } catch (err) {
      if ($traceHint) $traceHint.textContent = '검색 오류: ' + err.message;
    }
  }

  $traceBtn?.addEventListener('click', () => {
    const ip = $traceIp?.value?.trim();
    if (!ip) { alert('IP를 입력하세요.'); return; }
    doTrace(ip);
  });

  // Enter key로 검색
  $traceIp?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $traceBtn?.click(); }
  });

  bindTabsOnce();
})();
