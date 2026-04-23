// app.js — 멀티서버 로그 분석 지원 버전
(function () {
  const $ = (sel) => document.querySelector(sel);

  // ====== 고정 엘리먼트 ======
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

  // 대시보드 필터
  const $dashFrom       = $('#dash-from');
  const $dashTo         = $('#dash-to');
  const $dashFilterBtn  = $('#dashFilterBtn');
  const $dashResetBtn   = $('#dashResetBtn');
  const $dashFilterHint = $('#dashFilterHint');

  // 탭/패널
  const $tabTrace    = document.querySelector('.nav-tab[data-tab="trace"]');
  const $tabDash     = document.querySelector('.nav-tab[data-tab="dash"]');
  const $tabTimeline = document.querySelector('.nav-tab[data-tab="timeline"]');
  const $panelAnalyze= $('#panel-analyze');
  const $panelTrace  = $('#panel-trace');
  const $panelDash   = $('#panel-dash');
  const $panelTimeline = $('#panel-timeline');

  const CODE_DESC = {
    '300': 'ServerSide Bypass',   '301': 'ServerSide Block',
    '302': 'ServerSide IP Block', '303': 'ServerSide Express Number',
    '500': 'Uservice 없음',       '501': 'Action 없음',
    '502': '이미 종료된 key',     '503': '다른 서버에서 발급된 키',
    '504': '너무 많은 재발급 횟수','505': 'Key가 존재하지 않음',
    '506': '잘못된 ID 입력',      '507': '잘못된 Key 입력',
    '509': 'ID가 이미 존재함',    '513': '라이센스 수를 넘는 요청',
    '516': 'Current값보다 큰 Key값','517': '잘못된 IP로부터의 요청',
    '900': '인증처리 오류',       '991': 'I/O 에러',
    '992': '이미 실행중',         '993': '권한이 없음',
    '994': '만료 날짜 경과',      '995': '횟수 제한 초과',
    '997': '시스템 중지중',       '999': '시스템 에러',
  };

  let lastResult = null;
  let lastServers = [];   // [{label, data}, ...]
  let currentSSE = null;

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
    if ($fileInfo && d.fileSizeMB != null) $fileInfo.textContent = `(총 ${d.fileSizeMB} MB)`;
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

  // ====== 프로젝트/세그먼트 셀렉트박스 관리 ======
  let serverFieldCache = {};   // idx → {sids: [], aids: []}

  function populateSelects() {
    const $pj  = document.getElementById('project');
    const $seg = document.getElementById('segment');
    if (!$pj || !$seg) return;

    const allSids = new Set();
    const allAids = new Set();
    Object.values(serverFieldCache).forEach(({ sids, aids }) => {
      sids.forEach(s => allSids.add(s));
      aids.forEach(a => allAids.add(a));
    });

    const prevPj  = $pj.value;
    const prevSeg = $seg.value;

    $pj.innerHTML = '<option value="">전체</option>';
    [...allSids].sort().forEach(sid => {
      const opt = document.createElement('option');
      opt.value = sid; opt.textContent = sid;
      $pj.appendChild(opt);
    });
    if ([...$pj.options].some(o => o.value === prevPj)) $pj.value = prevPj;

    $seg.innerHTML = '<option value="">전체</option>';
    [...allAids].sort().forEach(aid => {
      const opt = document.createElement('option');
      opt.value = aid; opt.textContent = aid;
      $seg.appendChild(opt);
    });
    if ([...$seg.options].some(o => o.value === prevSeg)) $seg.value = prevSeg;
  }

  // ====== 서버 목록 관리 ======
  let serverDebounces = {};
  let serverRanges   = {};  // idx → range object

  function updateGlobalRange() {
    const ranges = Object.values(serverRanges).filter(Boolean);
    if (!ranges.length) return;
    const starts = ranges.map(r => r.startISO).filter(Boolean).sort();
    const ends   = ranges.map(r => r.endISO).filter(Boolean).sort();
    if (!starts.length || !ends.length) return;
    const totalMB = ranges.reduce((s, r) => s + (r.fileSizeMB || 0), 0);
    setDetectedRange({ startISO: starts[0], endISO: ends[ends.length - 1], fileSizeMB: totalMB.toFixed(1) });
  }

  function createServerRow(idx) {
    const div = document.createElement('div');
    div.className = 'server-item';
    div.dataset.idx = idx;
    div.innerHTML = `
      <div class="server-header">
        <span class="server-num">서버 ${idx + 1}</span>
        <input class="srv-label server-label-input" type="text" value="서버 ${idx + 1}" placeholder="라벨" />
        <button type="button" class="remove-srv ghost" style="font-size:12px;padding:4px 8px;margin-left:auto">제거</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px">
        <div>
          <label style="font-size:12px;color:#6b7280">파일 경로 (대용량 추천)</label><br/>
          <input class="srv-path" type="text" placeholder="예: /var/log/access.log" style="width:100%;font-size:14px"/>
          <div class="srv-fileinfo subtle" style="font-size:12px"></div>
        </div>
        <div>
          <label style="font-size:12px;color:#6b7280">또는 파일 업로드</label><br/>
          <input class="srv-file" type="file" accept=".txt,.log"/>
          <div class="srv-filename subtle" style="font-size:12px">선택된 파일 없음</div>
        </div>
      </div>`;

    // 경로 입력 → 범위 탐지 + sid/aid 스캔
    const pathEl  = div.querySelector('.srv-path');
    const infoEl  = div.querySelector('.srv-fileinfo');
    pathEl.addEventListener('input', () => {
      clearTimeout(serverDebounces[idx]);
      serverDebounces[idx] = setTimeout(async () => {
        const path = pathEl.value.trim();
        if (!path) {
          serverRanges[idx] = null;
          delete serverFieldCache[idx];
          updateGlobalRange();
          populateSelects();
          return;
        }
        try {
          const resp = await fetch(`/api/range_path/?path=${encodeURIComponent(path)}&logTz=${getLogTz()}`);
          const data = await resp.json();
          if (data.error) { infoEl.textContent = data.error; serverRanges[idx] = null; delete serverFieldCache[idx]; }
          else {
            infoEl.textContent = `(${data.fileSizeMB} MB)`;
            serverRanges[idx] = data;
            serverFieldCache[idx] = { sids: data.sids || [], aids: data.aids || [] };
          }
          updateGlobalRange();
          populateSelects();
        } catch { infoEl.textContent = '경로 확인 실패'; }
      }, 500);
    });

    // 파일 업로드 → 범위 탐지 + sid/aid 스캔
    const fileEl     = div.querySelector('.srv-file');
    const fileNameEl = div.querySelector('.srv-filename');
    fileEl.addEventListener('change', async () => {
      const f = fileEl.files?.[0];
      if (!f) return;
      fileNameEl.textContent = `${f.name} (${(f.size / 1024 / 1024).toFixed(1)} MB)`;
      setProgress(10);
      const fd = new FormData(); fd.append('file', f); fd.append('logTz', getLogTz());
      try {
        const resp = await fetch('/api/range/', { method: 'POST', body: fd });
        const data = await resp.json();
        serverRanges[idx] = { ...data, fileSizeMB: f.size / 1024 / 1024 };
        serverFieldCache[idx] = { sids: data.sids || [], aids: data.aids || [] };
        updateGlobalRange();
        populateSelects();
        hideProgress();
      } catch { hideProgress(); }
    });

    // 제거 버튼
    div.querySelector('.remove-srv').addEventListener('click', () => {
      delete serverRanges[idx];
      delete serverFieldCache[idx];
      div.remove();
      updateGlobalRange();
      populateSelects();
      refreshRemoveButtons();
    });

    return div;
  }

  function refreshRemoveButtons() {
    const items = document.querySelectorAll('#serverList .server-item');
    items.forEach(item => {
      const btn = item.querySelector('.remove-srv');
      if (btn) btn.style.display = items.length > 1 ? '' : 'none';
    });
  }

  function getServerInputs() {
    const servers = [];
    document.querySelectorAll('#serverList .server-item').forEach(item => {
      const label = (item.querySelector('.srv-label')?.value?.trim()) || `서버 ${servers.length + 1}`;
      const path  = item.querySelector('.srv-path')?.value?.trim() || '';
      const file  = item.querySelector('.srv-file')?.files?.[0] || null;
      if (path || file) servers.push({ label, path, file });
    });
    return servers;
  }

  // 초기 서버 1개 생성
  (function initServerList() {
    const list = document.getElementById('serverList');
    if (!list) return;
    list.appendChild(createServerRow(0));
    refreshRemoveButtons();

    document.getElementById('addServerBtn')?.addEventListener('click', () => {
      const items = list.querySelectorAll('.server-item');
      const nextIdx = Math.max(...[...items].map(el => parseInt(el.dataset.idx))) + 1;
      list.appendChild(createServerRow(nextIdx));
      refreshRemoveButtons();
    });
  })();

  // ====== 탭 ======
  function showTab(name) {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.nav-tab[data-tab="${name}"]`)?.classList.add('active');
    [$panelAnalyze, $panelTrace, $panelDash, $panelTimeline].forEach(p => p?.classList.add('hidden'));
    document.getElementById(`panel-${name}`)?.classList.remove('hidden');
    if (name === 'timeline') doTimeline(0);
  }
  function bindTabsOnce() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
      if (tab.dataset.bound === '1') return;
      tab.dataset.bound = '1';
      tab.addEventListener('click', () => { if (!tab.classList.contains('disabled')) showTab(tab.dataset.tab); });
    });
  }
  function enableResultTabs() {
    [$tabTrace, $tabDash, $tabTimeline].forEach(t => {
      if (!t) return;
      t.classList.remove('disabled');
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

  // ====== 로그 타임존 ======
  function getLogTz() {
    return document.querySelector('input[name="logTz"]:checked')?.value || 'KST';
  }

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
    p.set('timeoutSec', document.getElementById('timeoutSec')?.value || '20');
    p.set('logTz', getLogTz());
    return p;
  }

  // ====== 멀티서버 분석 ======
  async function analyzeMulti() {
    const servers = getServerInputs();
    if (!servers.length) { alert('로그 파일을 선택하거나 서버 경로를 입력하세요.'); return; }

    const params = getQueryParams();
    const fd = new FormData();
    fd.append('count', servers.length);
    for (const [k, v] of params.entries()) fd.append(k, v);
    servers.forEach((srv, i) => {
      fd.append(`label_${i}`, srv.label);
      if (srv.file)       fd.append(`file_${i}`, srv.file);
      else if (srv.path)  fd.append(`path_${i}`, srv.path);
    });

    const label = servers.length > 1
      ? `서버 ${servers.length}대 분석 중...`
      : '분석 중... (대용량 파일은 30초 이상 걸릴 수 있습니다)';
    setProgress(50, label);
    $analyzeBtn.disabled = true;
    $cancelBtn.disabled  = false;

    const ctrl = new AbortController();
    currentSSE = ctrl;

    try {
      const resp = await fetch('/api/analyze_multi/', { method: 'POST', body: fd, signal: ctrl.signal });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }
      const json = await resp.json();
      const data = json.data;
      const extra = `${(data.lineCount || 0).toLocaleString()} 줄 / ${data.elapsed || 0}초 / ${data.fileSizeMB || 0} MB`;
      setProgress(100, `완료 — ${extra}`);
      handleResult(data);
    } catch (err) {
      if (err.name === 'AbortError') setProgress(0, '취소됨');
      else { alert('분석 오류: ' + err.message); hideProgress(); }
    } finally {
      $analyzeBtn.disabled = false;
      $cancelBtn.disabled  = true;
      currentSSE = null;
    }
  }

  // ====== 분석 버튼 ======
  $analyzeBtn?.addEventListener('click', analyzeMulti);
  $cancelBtn?.addEventListener('click', () => {
    if (currentSSE) { currentSSE.abort(); currentSSE = null; }
    hideProgress();
  });

  // ====== 분석 시간범위 → 대시보드·타임라인·사용자추적 자동 채우기 ======
  function autoFillTimeFilters() {
    const ds = $dateStart?.value, ts = $timeStart?.value;
    const de = $dateEnd?.value,   te = $timeEnd?.value;
    if (!ds || !ts) return;   // 시간 범위 미설정 시 건너뜀
    const fromVal = `${ds}T${ts}`;
    const toVal   = (de && te) ? `${de}T${te}` : '';
    [$dashFrom, $('#tl-from'), $('#trace-from')].forEach(el => { if (el) el.value = fromVal; });
    if (toVal) [$dashTo, $('#tl-to'), $('#trace-to')].forEach(el => { if (el) el.value = toVal; });
  }

  // ====== 결과 처리 ======
  function handleResult(data) {
    lastResult  = data;
    lastServers = data.servers || [];

    autoFillTimeFilters();                           // ① 분석 시간범위 먼저 복사 (덮어쓰이기 전에)
    if (data.range) setDetectedRange(data.range);   // ② 그 후 파일 전체 범위로 입력 업데이트

    const isMulti = lastServers.length > 1;
    renderResult(data, isMulti);
    bindCSVButtons(data);
    renderDashboard(data);

    // 서버 서브탭
    renderServerSubTabs(lastServers);
    // ④ 멀티서버 KPI 비교 (항상 전체 서버 기준)
    renderMultiServerChart(lastServers);

    enableResultTabs();
    bindTabsOnce();
  }

  function renderResult(data, isMulti) {
    renderKPIs(data.kpis);
    renderCodes(data.codeDetails || [], Number(data.totalCodes || 0));
    renderTopWaitTids(data.topWaitTids || [], isMulti);
    renderDetailStats(data);
  }

  // ====== 서버 서브탭 (공용) ======
  function buildServerSubTabs(containerId, onSelectFn) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    if (!lastServers || lastServers.length <= 1) {
      container.classList.add('hidden');
      return;
    }
    container.classList.remove('hidden');

    const makeTab = (label, onClick) => {
      const btn = document.createElement('button');
      btn.textContent = label;
      btn.className = 'servertab';
      btn.addEventListener('click', () => {
        container.querySelectorAll('.servertab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        onClick();
      });
      return btn;
    };

    const combinedTab = makeTab('통합', () => onSelectFn(lastResult, true));
    combinedTab.classList.add('active');
    container.appendChild(combinedTab);

    lastServers.forEach(srv => {
      container.appendChild(makeTab(srv.label, () => onSelectFn(srv.data, false)));
    });
  }

  function renderServerSubTabs(serverResults) {
    // 로그 분석 탭 서브탭
    buildServerSubTabs('serverSubTabs', (data, isCombined) => {
      renderResult(data, isCombined);
      bindCSVButtons(data);
    });
    // 대시보드 탭 서브탭
    buildServerSubTabs('dashServerSubTabs', (data) => {
      renderDashboard(data);
    });
  }

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

  function renderTopWaitTids(rows, showServer) {
    const table = document.getElementById('topWaitTidTable');
    const tbody = table?.querySelector('tbody');
    if (!tbody) return;

    // 서버 컬럼 헤더/셀 표시 전환
    table?.querySelectorAll('.col-server').forEach(el => {
      el.classList.toggle('hidden', !showServer);
    });

    tbody.innerHTML = '';
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="${showServer ? 6 : 5}" class="subtle">데이터 없음</td></tr>`;
      return;
    }
    rows.forEach(r => {
      const tr = document.createElement('tr');
      const badge = showServer && r.server
        ? `<span class="server-badge">${r.server}</span>` : '';
      const serverCell = showServer
        ? `<td class="col-server">${r.server ? `<span class="server-badge">${r.server}</span>` : '-'}</td>` : '';
      tr.innerHTML = `<td style="font-family:monospace;font-size:13px">${badge}${r.tid}</td><td>${r.ip}</td><td>${r.wait_secs}</td><td>${r.start_time || '-'}</td><td>${r.timestamp}</td>${serverCell}`;
      tbody.appendChild(tr);
    });
  }

  function renderDetailStats(data) {
    const rs = data.rpsStats || {}, wd = data.waitDurStats || {};
    const all = rs.all || {}, overMax = rs.overMax || {}, holdOver = rs.holdOver || {};
    const enter = wd.enter || {}, quit = wd.quit || {};
    const dur = data.durationStats || {};
    const el = (id) => document.getElementById(id);
    const s = (o) => `최소=${fmt(o.min||0)} / 최대=${fmt(o.max||0)} / 평균=${fmt2(o.avg||0)}`;
    const sc = (o) => `${fmt(o.count||0)} 건 (${s(o)})`;
    if (el('stat-rps'))       el('stat-rps').textContent = s(all);
    if (el('stat-rps-over'))  el('stat-rps-over').textContent = sc(overMax);
    if (el('stat-hold-act'))  el('stat-hold-act').textContent = s(dur);
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
    bind('btn-qw-csv', data.quitWaitRows, 'quit_wait_users.csv', ['timestamp','ip','tid','status','server']);
    bind('btn-pe-csv', data.postEnterRows, 'enter_no_done_users.csv', ['timestamp','ip','tid','status','server']);
  }

  // ====== 대시보드: 차트 ======
  const chartInstances = {};

  function destroyChart(id) {
    if (chartInstances[id]) { chartInstances[id].destroy(); delete chartInstances[id]; }
  }

  function makeHorizBarChart(canvasId, rows, color, unit) {
    const el = document.getElementById(canvasId);
    if (!el) return;
    destroyChart(canvasId);

    const top10 = (rows || []).slice(0, 10);
    if (!top10.length) {
      // 빈 상태 텍스트
      el.style.display = 'none';
      const wrap = el.parentElement;
      let empty = wrap.querySelector('.chart-empty');
      if (!empty) {
        empty = document.createElement('div');
        empty.className = 'chart-empty';
        empty.style.cssText = 'display:flex;align-items:center;justify-content:center;height:260px;color:#9ca3af;font-size:13px';
        empty.textContent = '데이터 없음';
        wrap.appendChild(empty);
      }
      return;
    }
    el.style.display = '';
    const empty = el.parentElement?.querySelector('.chart-empty');
    if (empty) empty.remove();

    const labels = top10.map(r => r.ip);
    const values = top10.map(r => typeof r.count === 'number' ? r.count : 0);

    chartInstances[canvasId] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: color,
          borderRadius: 4,
          borderSkipped: false,
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => `${ctx.parsed.x.toLocaleString('ko-KR')}${unit ? ' ' + unit : ''}`
            }
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: '#f3f4f6' },
            ticks: { precision: 0, font: { size: 13 }, color: '#6b7280' }
          },
          y: {
            ticks: { font: { size: 13 }, color: '#1e293b' },
            afterFit: (scale) => { scale.width = Math.max(scale.width, Math.min(130, scale.chart.width * 0.28)); }
          }
        },
        onClick: (evt, elements) => {
          if (!elements.length) return;
          const ip = labels[elements[0].index];
          if ($traceIp) $traceIp.value = ip;
          showTab('trace');
          doTrace(ip);
        },
        onHover: (evt, elements) => {
          el.style.cursor = elements.length ? 'pointer' : 'default';
        }
      }
    });
  }

  function renderCodeDonut(codeDetails) {
    const section = document.getElementById('dash-code-section');
    const el = document.getElementById('chart-codes');
    if (!el) return;
    destroyChart('chart-codes');

    const codes = (codeDetails || []).filter(c => !/^2/.test(String(c.code))).slice(0, 8);
    if (!codes.length) { if (section) section.style.display = 'none'; return; }
    if (section) section.style.display = '';

    const COLORS = ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6','#ec4899','#14b8a6'];

    chartInstances['chart-codes'] = new Chart(el.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: codes.map(c => `${c.code}${CODE_DESC[String(c.code)] ? ' · ' + CODE_DESC[String(c.code)] : ''}`),
        datasets: [{
          data: codes.map(c => c.cnt),
          backgroundColor: COLORS.slice(0, codes.length),
          borderWidth: 2,
          borderColor: '#fff',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { font: { size: 14 }, padding: 16, boxWidth: 16 } },
          tooltip: {
            callbacks: { label: ctx => `${ctx.raw.toLocaleString('ko-KR')}건` }
          }
        }
      }
    });
  }

  // ① 세션 상태 도넛
  function renderSessionStatusDonut(data) {
    const el = document.getElementById('chart-session-status');
    if (!el) return;
    destroyChart('chart-session-status');
    const k = data.kpis || {};
    const done     = k.doneUserCnt || 0;
    const quitWait = k.quitWaitCnt || 0;
    const postEnter= k.postEnterLeaveCnt || 0;
    const ongoing  = Math.max(0, (k.reqUserCnt || 0) - done - quitWait - postEnter);
    if (!done && !quitWait && !postEnter && !ongoing) return;
    chartInstances['chart-session-status'] = new Chart(el.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: ['완료(5004)', '대기중 이탈', '진입후 이탈', '진행중'],
        datasets: [{ data: [done, quitWait, postEnter, ongoing],
          backgroundColor: ['#34d399','#f87171','#fb923c','#94a3b8'],
          borderWidth: 2, borderColor: '#fff' }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'right', labels: { font: { size: 14 }, padding: 12, boxWidth: 16 } },
          tooltip: { callbacks: { label: ctx => `${ctx.label}: ${ctx.raw.toLocaleString('ko-KR')}건` } }
        }
      }
    });
  }

  // ② 진입 요청 결과(Funnel)
  function renderFunnelChart(data) {
    const el = document.getElementById('chart-funnel');
    if (!el) return;
    destroyChart('chart-funnel');
    const k = data.kpis || {};
    const req  = k.reqUserCnt   || 0;
    const wait = k.waitUserCnt  || 0;
    const done = k.doneUserCnt  || 0;
    if (!req) return;
    chartInstances['chart-funnel'] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['진입 요청', '대기 발생', '완료(5004)'],
        datasets: [{
          data: [req, wait, done],
          backgroundColor: ['#818cf8','#fb923c','#34d399'],
          borderRadius: 4, borderSkipped: false,
        }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: ctx => `${ctx.parsed.x.toLocaleString('ko-KR')}건` } }
        },
        scales: {
          x: { beginAtZero: true, max: req * 1.05, grid: { color: '#f3f4f6' },
               ticks: { precision: 0, font: { size: 13 }, color: '#6b7280' } },
          y: { ticks: { font: { size: 14 }, color: '#1e293b' } }
        }
      }
    });
  }

  // ③-b IP별 요청·이탈 비교 grouped bar
  function renderIPCompareChart(data) {
    const el = document.getElementById('chart-ip-compare');
    if (!el) return;
    destroyChart('chart-ip-compare');
    const top10 = (data.topIssueIP || []).slice(0, 10);
    if (!top10.length) { el.parentElement.style.height = '60px'; return; }
    el.parentElement.style.height = '360px';
    const qwMap = Object.fromEntries((data.topQwIP  || []).map(r => [r.ip, r.count]));
    const peMap = Object.fromEntries((data.topPeIP  || []).map(r => [r.ip, r.count]));
    const labels  = top10.map(r => r.ip);
    chartInstances['chart-ip-compare'] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: '요청 수',    data: top10.map(r => r.count),      backgroundColor: '#818cf8', borderRadius: 3, borderSkipped: false },
          { label: '대기이탈 수', data: top10.map(r => qwMap[r.ip]||0), backgroundColor: '#f87171', borderRadius: 3, borderSkipped: false },
          { label: '진입이탈 수', data: top10.map(r => peMap[r.ip]||0), backgroundColor: '#fb923c', borderRadius: 3, borderSkipped: false },
        ]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top', labels: { font: { size: 14 }, padding: 12, boxWidth: 16 } },
          tooltip: { callbacks: { label: ctx => `${ctx.dataset.label}: ${ctx.raw.toLocaleString('ko-KR')}` } }
        },
        scales: {
          x: { beginAtZero: true, grid: { color: '#f3f4f6' }, ticks: { precision: 0, font: { size: 13 }, color: '#6b7280' } },
          y: {
            ticks: { font: { size: 13 }, color: '#1e293b' },
            afterFit: (scale) => { scale.width = Math.max(scale.width, Math.min(130, scale.chart.width * 0.28)); }
          }
        },
        onClick: (evt, elements) => {
          if (!elements.length) return;
          const ip = labels[elements[0].index];
          if ($traceIp) $traceIp.value = ip;
          showTab('trace'); doTrace(ip);
        },
        onHover: (evt, el) => { document.getElementById('chart-ip-compare').style.cursor = el.length ? 'pointer' : 'default'; }
      }
    });
  }

  // ④ 멀티서버 KPI 비교 (handleResult에서 호출)
  function renderMultiServerChart(servers) {
    const section = document.getElementById('chart-multiserver-section');
    const el = document.getElementById('chart-multiserver');
    if (!el || !section) return;
    destroyChart('chart-multiserver');
    if (!servers || servers.length <= 1) { section.style.display = 'none'; return; }
    section.style.display = '';
    const COLORS = ['#818cf8','#fb923c','#34d399','#f87171','#c084fc'];
    const categories = ['요청 사용자', '대기 발생', '완료', '대기이탈', '진입이탈'];
    chartInstances['chart-multiserver'] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: categories,
        datasets: servers.map((srv, i) => ({
          label: srv.label,
          data: [
            srv.data.kpis.reqUserCnt, srv.data.kpis.waitUserCnt,
            srv.data.kpis.doneUserCnt, srv.data.kpis.quitWaitCnt,
            srv.data.kpis.postEnterLeaveCnt,
          ],
          backgroundColor: COLORS[i % COLORS.length],
          borderRadius: 4, borderSkipped: false,
        }))
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top', labels: { font: { size: 14 }, padding: 14, boxWidth: 16 } },
          tooltip: { callbacks: { label: ctx => `${ctx.dataset.label}: ${ctx.raw.toLocaleString('ko-KR')}건` } }
        },
        scales: {
          x: { grid: { color: '#f3f4f6' } },
          y: { beginAtZero: true, ticks: { precision: 0, font: { size: 13 } } }
        }
      }
    });
  }

  // ⑤ 시간대별 트래픽 추이
  function renderTimeSeriesChart(data) {
    const el = document.getElementById('chart-timeseries');
    if (!el) return;
    destroyChart('chart-timeseries');
    const ts = data.timeSeries || [];
    if (!ts.length) {
      el.parentElement.style.height = '60px';
      const ctx = el.getContext('2d');
      ctx.clearRect(0, 0, el.width, el.height);
      return;
    }
    el.parentElement.style.height = '360px';

    // 분 단위 라벨 포맷 (HH:MM, 멀티데이면 MM/DD HH:MM)
    const firstDay = ts[0].time.slice(0, 10);
    const isMultiDay = ts.some(t => t.time.slice(0, 10) !== firstDay);
    const labels = ts.map(t => isMultiDay ? t.time.slice(5, 16) : t.time.slice(11, 16));

    // 완료율(%) 계산 — NF4 공식: complete_succ / chk_enter_succ * 100
    // chk_enter_succ(진입 성공) = req(200+201) - wait(201) = 진입 성공(200)만
    const completionRates = ts.map(t => {
      const enterSucc = t.req - t.wait;
      if (enterSucc <= 0) return 0;
      return Math.min(100, t.done / enterSucc * 100);
    });

    chartInstances['chart-timeseries'] = new Chart(el.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: '요청 수',    data: ts.map(t => t.req),  borderColor: '#818cf8', backgroundColor: 'rgba(129,140,248,.12)', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2, yAxisID: 'y' },
          { label: '대기 발생',  data: ts.map(t => t.wait), borderColor: '#fb923c', backgroundColor: 'rgba(251,146,60,.10)',  fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2, yAxisID: 'y' },
          { label: '완료(5004)', data: ts.map(t => t.done), borderColor: '#34d399', backgroundColor: 'rgba(52,211,153,.10)',  fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2, yAxisID: 'y' },
          { label: '완료율(%)',  data: completionRates, borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,.08)', fill: false, tension: 0.3, pointRadius: 0, borderWidth: 2.5, yAxisID: 'y1', borderDash: [5, 5] },
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { position: 'top', labels: { font: { size: 14 }, padding: 14, boxWidth: 24 } },
          tooltip: {
            callbacks: {
              label: ctx => {
                if (ctx.dataset.label === '완료율(%)') {
                  return `${ctx.dataset.label}: ${ctx.raw.toFixed(1)}%`;
                }
                return `${ctx.dataset.label}: ${ctx.raw.toLocaleString('ko-KR')}`;
              }
            }
          }
        },
        scales: {
          x: { grid: { color: '#f3f4f6' }, ticks: { maxTicksLimit: 12, font: { size: 12 }, color: '#6b7280', maxRotation: 45, minRotation: 0 } },
          y: { beginAtZero: true, grid: { color: '#f3f4f6' }, ticks: { precision: 0, font: { size: 13 } }, position: 'left' },
          y1: { beginAtZero: true, max: 100, grid: { drawOnChartArea: false }, ticks: { precision: 0, font: { size: 13 }, callback: v => `${v}%` }, position: 'right' }
        }
      }
    });
  }

  // ⑥ 처리시간 분포 히스토그램
  function renderDurHistogram(data) {
    const el = document.getElementById('chart-dur-hist');
    if (!el) return;
    destroyChart('chart-dur-hist');
    const hist = data.durHistogram || [];
    if (!hist.length || hist.every(b => b.count === 0)) {
      el.parentElement.style.height = '60px'; return;
    }
    el.parentElement.style.height = '260px';
    const max = Math.max(...hist.map(b => b.count));
    chartInstances['chart-dur-hist'] = new Chart(el.getContext('2d'), {
      type: 'bar',
      data: {
        labels: hist.map(b => b.label),
        datasets: [{
          data: hist.map(b => b.count),
          backgroundColor: hist.map(b => {
            const ratio = max ? b.count / max : 0;
            return ratio > 0.7 ? '#f87171' : ratio > 0.4 ? '#fb923c' : '#818cf8';
          }),
          borderRadius: 6, borderSkipped: false,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: ctx => `${ctx.raw.toLocaleString('ko-KR')}건` } }
        },
        scales: {
          x: { grid: { display: false }, ticks: { font: { size: 13 }, color: '#374151' } },
          y: { beginAtZero: true, grid: { color: '#f3f4f6' }, ticks: { precision: 0, font: { size: 13 } } }
        }
      }
    });
  }

  function renderDashboard(data) {
    // ① ②
    renderSessionStatusDonut(data);
    renderFunnelChart(data);
    // ③ IP Top + 비교
    makeHorizBarChart('chart-issue', data.topIssueIP,  '#818cf8');
    makeHorizBarChart('chart-wait',  data.topWaitIP,   '#fb923c', 's');
    makeHorizBarChart('chart-qw',    data.topQwIP,     '#f87171');
    makeHorizBarChart('chart-pe',    data.topPeIP,     '#c084fc');
    renderIPCompareChart(data);
    // ⑤ ⑥
    renderTimeSeriesChart(data);
    renderDurHistogram(data);
    if (data.codeDetails) renderCodeDonut(data.codeDetails);

    const csvBind = (id, rows) => {
      const btn = document.getElementById(id);
      if (btn) btn.onclick = () => {
        if (!rows?.length) return alert('데이터 없음');
        downloadCSV(`${id}.csv`, rows, ['ip', 'count']);
      };
    };
    csvBind('csv-issue', data.topIssueIP);
    csvBind('csv-wait',  data.topWaitIP);
    csvBind('csv-qw',    data.topQwIP);
    csvBind('csv-pe',    data.topPeIP);
  }

  // ====== 사용자 추적 ======
  const $traceIp     = $('#trace-ip');
  const $traceFrom   = $('#trace-from');
  const $traceTo     = $('#trace-to');
  const $traceBtn    = $('#traceBtn');
  const $traceResult = $('#traceResult');
  const $traceBox    = $('#traceBox');
  const $traceHint   = $('#traceHint');

  // 상태 → 뱃지 스타일
  const STATUS_CFG = {
    '완료(5004)':  { cls: 'status-done',      text: '완료' },
    '대기중이탈':  { cls: 'status-wait-out',   text: '대기이탈' },
    '진입후이탈':  { cls: 'status-enter-out',  text: '진입이탈' },
    '진행중':      { cls: 'status-ongoing',    text: '진행중' },
  };
  // opcode → 진입 유형 설명
  const OPCODE_CFG = {
    '5101':      '즉시진입',
    '5002':      '대기후진입',
    '5101+5002': '대기+즉시',
    '-':         '-',
  };

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
      const toVal   = $traceTo?.value;
      if (fromVal) traceUrl += `&from=${encodeURIComponent(fromVal.replace('T', ' '))}`;
      if (toVal)   traceUrl += `&to=${encodeURIComponent(toVal.replace('T', ' '))}`;

      const resp = await fetch(traceUrl);
      const json = await resp.json();
      if (json.error) { if ($traceHint) $traceHint.textContent = json.error; return; }

      const sess = json.data;
      if (!sess) {
        if ($traceHint) $traceHint.textContent = `"${ip}"에 해당하는 세션이 없습니다.`;
        return;
      }

      // hint 텍스트
      const filterNote = (sess.filteredCount != null && sess.filteredCount !== sess.tidCount)
        ? ` (필터 적용: ${sess.filteredCount}개)` : '';
      if ($traceHint) $traceHint.textContent = '';

      // 요약 카드 업데이트
      const el = (id) => document.getElementById(id);
      if (el('ts-total'))    el('ts-total').textContent    = fmt(sess.tidCount);
      if (el('ts-filtered')) el('ts-filtered').textContent = fmt(sess.filteredCount ?? sess.tidCount) + filterNote;
      if (el('ts-wait'))     el('ts-wait').textContent     = `${sess.totalWaitSec}초`;
      if (el('ts-first'))    el('ts-first').textContent    = sess.firstSeen || '-';
      if (el('ts-last'))     el('ts-last').textContent     = sess.lastSeen  || '-';
      if ($traceResult) $traceResult.style.display = '';

      if (!$traceBox) return;

      // 멀티서버 여부
      const showServer = lastServers.length > 1;
      const tids = sess.tids || [];

      const serverTh = showServer ? '<th>서버</th>' : '';
      let html = `<table class="trace-table">
        <thead><tr>
          <th>TID</th>
          ${serverTh}
          <th>진입 유형</th>
          <th>상태</th>
          <th>키 발급</th>
          <th>대기 종료</th>
          <th>키 반납</th>
          <th>대기(초)</th>
        </tr></thead><tbody>`;

      tids.forEach(t => {
        const sc   = STATUS_CFG[t.status] || { cls: '', text: t.status };
        const entry = OPCODE_CFG[t.opcode] || t.opcode;

        // 대기 종료: 5002가 없으면(즉시진입) "즉시진입" 표시
        const endCell  = t.end  ? t.end  : `<span class="muted">—</span>`;
        // 키 반납: 5004가 없으면 "—" 표시
        const doneCell = t.done ? t.done : `<span class="muted">—</span>`;
        // 대기시간: 0이면 "—"
        const waitCell = t.waitSec ? t.waitSec : `<span class="muted">—</span>`;

        const serverCell = showServer
          ? `<td>${t.server ? `<span class="server-badge">${t.server}</span>` : '<span class="muted">—</span>'}</td>`
          : '';

        html += `<tr>
          <td style="font-family:monospace;font-size:13px">${t.tid}</td>
          ${serverCell}
          <td><span class="entry-type">${entry}</span></td>
          <td><span class="status-badge ${sc.cls}">${sc.text}</span></td>
          <td>${t.start || '<span class="muted">—</span>'}</td>
          <td>${endCell}</td>
          <td>${doneCell}</td>
          <td>${waitCell}</td>
        </tr>`;
      });

      html += '</tbody></table>';
      if (sess.truncated) {
        html += `<div class="subtle" style="margin-top:8px">결과가 많아 500개까지만 표시됩니다. 시간대 필터를 사용하세요.</div>`;
      }
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
  $traceIp?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); $traceBtn?.click(); }
  });

  // ====== 세션 타임라인 ======
  const TL_LIMIT = 500;
  const ENTRY_LABEL = { '5101': '즉시진입', '5002': '대기진입', '5101+5002': '대기+즉시', '-': '-' };
  const TL_STATUS_CLASS = { '완료': 'status-done', '대기이탈': 'status-wait-out', '진입이탈': 'status-enter-out', '진행중': 'status-ongoing' };
  let tlAllRows = [];  // CSV용 현재 페이지 rows
  let tlSort = 'time'; // 'time' | 'dur_asc' | 'dur_desc'

  async function doTimeline(offset = 0) {
    if (!lastResult) return;
    const hint  = document.getElementById('tlHint');
    const tbody = document.getElementById('tlBody');
    if (hint)  hint.textContent = '조회 중...';
    if (tbody) tbody.innerHTML  = `<tr><td colspan="8" style="text-align:center;padding:32px;color:#9ca3af">로딩 중...</td></tr>`;
    const paramsBarLoading = document.getElementById('tlParamsBar');
    if (paramsBarLoading) paramsBarLoading.textContent = '';

    const fromVal = document.getElementById('tl-from')?.value;
    const toVal   = document.getElementById('tl-to')?.value;
    const maxDurSec = document.getElementById('tlMaxDurSec')?.value?.trim();
    let url = `/api/timeline/?offset=${offset}&limit=${TL_LIMIT}&sort=${tlSort}`;
    if (fromVal)   url += `&from=${encodeURIComponent(fromVal.replace('T', ' '))}`;
    if (toVal)     url += `&to=${encodeURIComponent(toVal.replace('T', ' '))}`;
    if (maxDurSec) url += `&maxDurSec=${encodeURIComponent(maxDurSec)}`;

    try {
      const resp = await fetch(url);
      const data = await resp.json();
      if (data.error) { if (hint) hint.textContent = data.error; return; }

      tlAllRows = data.rows;
      const total = data.total;
      const from  = offset + 1;
      const to    = Math.min(offset + data.rows.length, total);
      // 분석 파라미터 표시
      const ap = data.analysisParams || {};
      const paramsBar = document.getElementById('tlParamsBar');
      if (paramsBar) {
        const pjStr  = ap.pj  ? `PJ: ${ap.pj}`   : '전체 PJ';
        const segStr = ap.seg ? `SEG: ${ap.seg}`  : '전체 SEG';
        paramsBar.textContent = `[분석 조건] ${pjStr} / ${segStr} / 처리시간 타임아웃: ${ap.timeoutSec ?? 20}초`;
      }

      if (hint) hint.textContent = `총 ${total.toLocaleString('ko-KR')}건 중 ${from.toLocaleString('ko-KR')}~${to.toLocaleString('ko-KR')}건 표시`;

      // 서버 열 표시 여부
      document.querySelectorAll('#tlTable .col-server').forEach(el =>
        el.classList.toggle('hidden', !data.isMulti));

      if (!data.rows.length) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:32px;color:#9ca3af">해당 시간대 데이터 없음</td></tr>`;
      } else {
        if (tbody) tbody.innerHTML = data.rows.map(r => {
          const traceIp = r.ip5101 || r.ip || '';
          return `
          <tr>
            <td><a href="#" class="tl-ip-link" data-ip="${traceIp}" style="color:#4f46e5;text-decoration:none;font-size:13px">${r.ip5101 || '-'}</a></td>
            <td style="font-size:13px">${r.ip5004 || '-'}</td>
            <td><span class="mono" style="font-size:13px">${r.tid}</span></td>
            <td style="white-space:nowrap;font-size:13px">${r.start || '-'}</td>
            <td style="white-space:nowrap;font-size:13px">${r.done || '-'}</td>
            <td style="text-align:right;font-size:13px;${r.durExceeded ? 'color:#ef4444;font-weight:700' : ''}">${r.durSec != null ? r.durSec : '-'}</td>
            <td><span class="status-badge ${TL_STATUS_CLASS[r.status] || ''}">${r.status}</span></td>
            <td class="col-server ${data.isMulti ? '' : 'hidden'}" style="font-size:13px">${r.server || '-'}</td>
          </tr>`;
        }).join('');

        // IP 클릭 → 사용자 추적
        document.querySelectorAll('#tlBody .tl-ip-link').forEach(a => {
          a.addEventListener('click', e => {
            e.preventDefault();
            const ip = a.dataset.ip;
            if ($traceIp) $traceIp.value = ip;
            showTab('trace');
            doTrace(ip);
          });
        });
      }

      // 페이지네이션
      renderTlPager(total, offset, data.limit);
    } catch (err) {
      if (hint) hint.textContent = '조회 실패: ' + err.message;
    }
  }

  function renderTlPager(total, offset, limit) {
    const pager = document.getElementById('tlPager');
    if (!pager) return;
    pager.innerHTML = '';
    if (total <= limit) return;
    const totalPages  = Math.ceil(total / limit);
    const currentPage = Math.floor(offset / limit);
    const addBtn = (label, targetOffset, disabled) => {
      const btn = document.createElement('button');
      btn.className = 'ghost';
      btn.style.cssText = 'padding:6px 14px;font-size:13px';
      btn.textContent = label;
      btn.disabled = disabled;
      if (!disabled) btn.addEventListener('click', () => doTimeline(targetOffset));
      pager.appendChild(btn);
    };
    addBtn('◀ 이전', (currentPage - 1) * limit, currentPage === 0);
    const info = document.createElement('span');
    info.className = 'subtle';
    info.style.cssText = 'padding:0 8px;align-self:center';
    info.textContent = `${currentPage + 1} / ${totalPages} 페이지`;
    pager.appendChild(info);
    addBtn('다음 ▶', (currentPage + 1) * limit, currentPage >= totalPages - 1);
  }

  function updateTlSortButtons() {
    const btnMap = {
      'tlSortTimeBtn':    'time',
      'tlSortDurAscBtn':  'dur_asc',
      'tlSortDurDescBtn': 'dur_desc',
    };
    Object.entries(btnMap).forEach(([id, val]) => {
      const btn = document.getElementById(id);
      if (!btn) return;
      btn.style.background = tlSort === val ? '#4f46e5' : '';
      btn.style.color      = tlSort === val ? '#fff'    : '';
    });
  }

  document.getElementById('tlFilterBtn')?.addEventListener('click', () => doTimeline(0));
  document.getElementById('tlResetBtn')?.addEventListener('click', () => {
    const f = document.getElementById('tl-from');
    const t = document.getElementById('tl-to');
    const m = document.getElementById('tlMaxDurSec');
    if (f) f.value = ''; if (t) t.value = ''; if (m) m.value = '';
    doTimeline(0);
  });
  document.getElementById('tlSortTimeBtn')?.addEventListener('click', () => {
    tlSort = 'time'; updateTlSortButtons(); doTimeline(0);
  });
  document.getElementById('tlSortDurAscBtn')?.addEventListener('click', () => {
    tlSort = 'dur_asc'; updateTlSortButtons(); doTimeline(0);
  });
  document.getElementById('tlSortDurDescBtn')?.addEventListener('click', () => {
    tlSort = 'dur_desc'; updateTlSortButtons(); doTimeline(0);
  });
  document.getElementById('tlCsvBtn')?.addEventListener('click', () => {
    if (!tlAllRows.length) { alert('데이터 없음'); return; }
    downloadCSV('timeline.csv', tlAllRows,
      ['ip5101','ip5004','tid','start','done','durSec','status','server']);
  });

  // ====== 대시보드 시간 필터 ======
  async function doDashFilter() {
    if (!lastResult) {
      if ($dashFilterHint) $dashFilterHint.textContent = '먼저 로그 분석을 실행하세요.';
      return;
    }
    const fromVal = $dashFrom?.value;
    const toVal   = $dashTo?.value;
    if (!fromVal && !toVal) {
      renderDashboard(lastResult);
      if ($dashFilterHint) $dashFilterHint.textContent = '';
      return;
    }
    if ($dashFilterHint) $dashFilterHint.textContent = '조회 중...';
    try {
      const params = new URLSearchParams();
      if (fromVal) params.set('from', fromVal.replace('T', ' '));
      if (toVal)   params.set('to',   toVal.replace('T', ' '));
      const resp = await fetch(`/api/dashboard_filter/?${params}`);
      const json = await resp.json();
      if (json.error) { if ($dashFilterHint) $dashFilterHint.textContent = json.error; return; }
      renderDashboard(json.data);
      if ($dashFilterHint) $dashFilterHint.textContent = '조회 완료';
    } catch (err) {
      if ($dashFilterHint) $dashFilterHint.textContent = '조회 오류: ' + err.message;
    }
  }

  $dashFilterBtn?.addEventListener('click', doDashFilter);
  $dashResetBtn?.addEventListener('click', () => {
    if ($dashFrom) $dashFrom.value = '';
    if ($dashTo)   $dashTo.value   = '';
    if (lastResult) renderDashboard(lastResult);
    if ($dashFilterHint) $dashFilterHint.textContent = '';
  });

  bindTabsOnce();
})();
