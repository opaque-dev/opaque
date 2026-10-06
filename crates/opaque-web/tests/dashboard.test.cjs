// Browser-independent checks of the shipped dashboard script. Real browser
// verification remains part of the release dogfood run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function dashboard() {
  const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  const source = html.split('<script>')[1].split('</script>')[0].replace(/\ninit\(\);\s*$/, '');
  const context = vm.createContext({document: {querySelector: () => ({content: 'test-only'})}, URL, console});
  vm.runInContext(source, context);
  context.auth.unlocked = true;
  context.authToken = "test-only";
  context.el = (tag, attrs, children) => ({tag, attrs: attrs || {}, children: [].concat(children || []), appendChild(child) {this.children.push(child);}});
  context.txt = value => String(value);
  return context;
}
function text(node) {
  return typeof node === 'string' ? node : (node.children || []).map(text).join(' ');
}

test('audit styling distinguishes uncertain and unobserved work from explicit success', () => {
  const ui = dashboard();
  for (const outcome of ['unknown', 'transport_unknown', 'interrupted']) {
    assert.equal(ui.outcomeClass({kind:'operation.executed', outcome}), 'warn', outcome);
  }
  for (const event of [
    {kind:'request.received'}, {kind:'approval.required'}, {kind:'operation.executed'},
    {kind:'new.event', outcome:'future_unrecognized_result'}, {},
  ]) assert.equal(ui.outcomeClass(event), 'neutral', JSON.stringify(event));
  for (const outcome of ['ok', 'api_accepted']) {
    assert.equal(ui.outcomeClass({kind:'operation.executed', outcome}), 'ok', outcome);
  }
  assert.equal(ui.outcomeClass({outcome:'denied'}), 'denied');
  assert.equal(ui.outcomeClass({outcome:'error'}), 'error');
  assert.notEqual(ui.outcomeIcon('neutral'), ui.outcomeIcon('ok'));
});

test('audit identity uses event identity then sequence including zero then stable content', () => {
  const ui = dashboard();
  const event = {event_id:'receipt-a', sequence_number:4, kind:'request.received'};
  assert.equal(ui.auditEventKey(event), ui.auditEventKey({...event, sequence_number:5}));
  assert.notEqual(ui.auditEventKey(event), ui.auditEventKey({...event, event_id:'receipt-b'}));
  assert.equal(ui.auditEventKey({sequence_number:0, kind:'a'}), ui.auditEventKey({sequence_number:0, kind:'b'}));
  assert.notEqual(ui.auditEventKey({sequence_number:0}), ui.auditEventKey({sequence_number:1}));
  const content = {kind:'request.received', operation:'fixture.operation', outcome:'unknown'};
  assert.equal(ui.auditEventKey(content), ui.auditEventKey(JSON.parse(JSON.stringify(content))));
  assert.notEqual(ui.auditEventKey(content), ui.auditEventKey({...content, outcome:'denied'}));
});

test('audit expansion is an accessible button and follows its event when newer rows arrive', () => {
  const {ui} = auditDashboard();
  ui.document.createDocumentFragment = () => ui.el('fragment');
  ui.jsonToHighlightedDom = event => ui.el('pre', {}, JSON.stringify(event));
  const earlier = {event_id:'earlier', sequence_number:100, kind:'request.received'};
  const selected = {event_id:'selected', sequence_number:101, kind:'operation.executed', outcome:'unknown'};
  ui.state.auditEvents = [selected, earlier];
  let selectedRow = ui.buildAuditEventRow(selected, 0).children[0];
  assert.equal(selectedRow.tag, 'button');
  assert.equal(String(selectedRow.attrs['aria-expanded']), 'false');
  assert.equal(selectedRow.attrs['data-event-key'], ui.auditEventKey(selected));
  selectedRow.attrs.onClick();
  assert.equal(ui.state.expandedEvent, ui.auditEventKey(selected));

  const newest = {event_id:'newest', sequence_number:102, kind:'request.received'};
  ui.prependAuditEvent(newest);
  assert.equal(ui.state.auditEvents[1].event_id, 'selected');
  const newestFragment = ui.buildAuditEventRow(newest, 0);
  const selectedFragment = ui.buildAuditEventRow(selected, 1);
  assert.equal(String(newestFragment.children[0].attrs['aria-expanded']), 'false');
  selectedRow = selectedFragment.children[0];
  assert.equal(String(selectedRow.attrs['aria-expanded']), 'true');
  assert.equal(selectedFragment.children.length, 2, 'selected event retains its evidence detail');
  assert.equal(newestFragment.children.length, 1, 'new row must not inherit expanded evidence');
  assert.match(text(selectedFragment.children[1]), /selected/);
  selectedRow.attrs.onClick();
  assert.equal(ui.state.expandedEvent, null);
});

function tabDashboard() {
  const ui = dashboard();
  const document = ui.document;
  function node(id, tab) {
    const attrs = new Map(tab ? [['data-tab',tab]] : []);
    const classes = new Set();
    const result = {id, tabIndex:-1, classList:{add:name=>classes.add(name), remove:name=>classes.delete(name),
      contains:name=>classes.has(name), toggle(name, force) {
        const selected = force === undefined ? !classes.has(name) : force;
        if (selected) classes.add(name); else classes.delete(name);
        return selected;
      }},
      getAttribute:name=>attrs.get(name) ?? null, setAttribute:(name,value)=>attrs.set(name,String(value)),
      focus() { document.activeElement = result; }, closest() { return tab ? result : null; },
    };
    return result;
  }
  const names = ['tasks','audit','policy','sessions','operations'];
  const tabs = names.map(name=>node('tab-'+name, name));
  const panels = names.map(name=>node('panel-'+name));
  const refresh = node('operations-refresh');
  const workspace = {id:'workspace-content',scrollTop:480};
  refresh.tabIndex = 0;
  const byId = new Map([...tabs,...panels,refresh,workspace].map(node=>[node.id,node]));
  document.querySelectorAll = selector => selector === '.tab-panel' ? panels
    : selector === '.tab-btn' ? [...tabs,refresh] : selector === '.tab-btn[data-tab]' ? tabs : [];
  document.getElementById = id=>byId.get(id);
  const loaded = [];
  for (const name of names.filter(name=>name !== 'audit')) {
    ui['load'+name[0].toUpperCase()+name.slice(1)] = ()=>loaded.push(name);
  }
  const key = (key, target=document.activeElement) => {
    let prevented = false;
    ui.navigateTabs({key, target, currentTarget:target, preventDefault(){prevented=true;}});
    return prevented;
  };
  return {ui, tabs, panels, refresh, loaded, key, workspace};
}

test('tab selection exposes exactly one active keyboard tab without rewriting the operation refresh control', () => {
  const {ui,tabs,panels,refresh,loaded,workspace} = tabDashboard();
  ui.switchTab('operations');
  assert.equal(workspace.scrollTop, 0, 'a different view begins at its heading');
  assert.equal(ui.state.activeTab, 'operations');
  for (const tab of tabs) {
    const selected = tab.getAttribute('data-tab') === 'operations';
    assert.equal(tab.getAttribute('aria-selected'), String(selected));
    assert.equal(tab.tabIndex, selected ? 0 : -1);
    assert.equal(tab.classList.contains('active'), selected);
  }
  assert.equal(panels.filter(panel=>panel.classList.contains('active')).length, 1);
  assert.ok(panels.find(panel=>panel.id === 'panel-operations').classList.contains('active'));
  assert.equal(refresh.getAttribute('aria-selected'), null);
  assert.equal(refresh.tabIndex, 0);
  assert.deepEqual(loaded, ['operations']);
  workspace.scrollTop = 180;
  ui.switchTab('operations');
  assert.equal(workspace.scrollTop, 180, 'reselecting the same view preserves its position');
});

test('tab keyboard navigation wraps and supports Home and End without treating unrelated keys as navigation', () => {
  const {ui,tabs,key} = tabDashboard();
  ui.switchTab('tasks');
  tabs[0].focus();
  assert.equal(key('ArrowLeft'), true);
  assert.equal(ui.state.activeTab, 'operations');
  assert.equal(ui.document.activeElement, tabs[4]);
  assert.equal(key('ArrowRight'), true);
  assert.equal(ui.state.activeTab, 'tasks');
  assert.equal(ui.document.activeElement, tabs[0]);
  assert.equal(key('End'), true);
  assert.equal(ui.state.activeTab, 'operations');
  assert.equal(key('Home'), true);
  assert.equal(ui.state.activeTab, 'tasks');
  assert.equal(key('Escape'), false);
  assert.equal(ui.state.activeTab, 'tasks');
  assert.equal(ui.document.activeElement, tabs[0]);
  assert.equal(tabs.filter(tab=>tab.tabIndex === 0).length, 1);
});

test('locked tab clicks and keyboard navigation do not activate or load private views', () => {
  const {ui,tabs,loaded,key} = tabDashboard();
  ui.auth.unlocked = false;
  tabs[0].focus();
  ui.switchTab('operations');
  key('End');
  assert.equal(ui.state.activeTab, 'tasks');
  assert.equal(ui.document.activeElement, tabs[0]);
  assert.deepEqual(loaded, []);
});

function task() {
  return {id: 'test-task', state: 'completed', approved_at: 100, approval_mode: 'insecure_test',
    manifest: {actions: [{operation: 'github.dispatch_staging_workflow'}]},
    slots: [{reserved_at: 100, state: 'unknown'}], release_observation: null};
}

test('historical approval provenance is independent of the running backend', () => {
  const ui = dashboard();
  ui.state.approvalBackend = 'native';
  assert.equal(ui.taskApprovalMode(task()), 'INSECURE TEST APPROVAL');
  assert.equal(ui.taskApprovalMode({...task(), approval_mode: null}), 'Approval mode unavailable');
  assert.equal(ui.taskApprovalMode({...task(), approval_mode: 'paired_workstation'}), 'Paired workstation approval');
  ui.state.workstationTestMode = true;
  assert.equal(ui.testApprovalActive(), true);
});

test('a completed dispatch never labels an unchecked workflow successful', () => {
  const ui = dashboard();
  const receipt = task();
  assert.equal(ui.taskStateLabel(receipt), 'Dispatch recorded');
  assert.equal(ui.workflowLabel(receipt.release_observation), 'Not checked');
  const rendered = text(ui.buildWorkflowEvidence(receipt));
  assert.match(rendered, /Not checked/);
  assert.match(rendered, /Checking cannot dispatch or retry/);
  assert.doesNotMatch(rendered, /succeeded|successful/);
});

test('workflow success preserves unknown dispatch wording and explicit correlation', () => {
  const ui = dashboard();
  const receipt = {...task(), release_observation: {state: 'succeeded', code: 'workflow_succeeded', correlation: 'task_title', run_id: 42, run_attempt: 1, checked_at: 200}};
  assert.equal(ui.slotLabel(receipt.slots[0].state, true), 'Unknown — may have dispatched');
  const rendered = text(ui.buildWorkflowEvidence(receipt));
  assert.match(rendered, /Workflow succeeded/);
  assert.match(rendered, /Matched task correlation title/);
  assert.match(rendered, /Attempt 1/);
  assert.match(rendered, /Run 42/);
  assert.equal(receipt.slots[0].state, 'unknown');
  receipt.release_observation.correlation = 'dispatch_response';
  assert.match(text(ui.buildWorkflowEvidence(receipt)), /Run ID from dispatch response/);
});

test('unapproved work has no reconciliation action, failed refresh retains evidence', () => {
  const ui = dashboard();
  const unapproved = {...task(), approved_at: null, slots: [{reserved_at: null}]};
  assert.doesNotMatch(text(ui.buildWorkflowEvidence(unapproved)), /Check workflow/);
  ui.state.reconcileErrors['test-task'] = 'Provider unavailable. Existing evidence is retained; no dispatch was requested.';
  const rendered = text(ui.buildWorkflowEvidence({...task(), release_observation: {state: 'failed', correlation: 'dispatch_response'}}));
  assert.match(rendered, /Workflow failed/);
  assert.match(rendered, /Existing evidence is retained/);
});

test('missing broker audit custody does not create background request retries', async () => {
  const ui = dashboard();
  ui.state.mode = 'live';
  ui.state.auditAvailable = false;
  ui.apiFetch = () => {throw new Error('must not request an unavailable local source');};
  ui.renderAuditList = () => {};
  ui.setStreamStatus = () => {};
  await ui.applyFilters();
  await ui.connectSSE();
  assert.match(ui.state.auditError, /Audit history is unavailable/);
  assert.equal(ui.state.sseRetryTimer, null);
});

function inferenceTask(unknown = false) {
  const actions = [1, 2, 3].map(ordinal => ({operation: 'inference.fixed_completion', ordinal,
    tenant: {tenant_id: 'synthetic-a', broker_id: 'broker-a'}, model_id: 'fixture-model',
    source_id: 'public-fixture', source_snapshot_sha256: 'a'.repeat(64), prompt_sha256: 'b'.repeat(64),
    options: {max_input_tokens: 512, max_output_tokens: 96, deadline_secs: 30}}));
  return {...task(), manifest: {actions}, slots: actions.map((action, i) => ({id: String(i), action,
    reserved_at: unknown && i > 0 ? null : 100,
    state: unknown ? (i === 0 ? 'unknown' : 'rejected') : 'api_accepted',
    outcome: {code: unknown ? 'transport_unknown' : 'api_accepted', inference_receipt: unknown ? null : {
      code: 'completion_observed', input_tokens: 3, reserved_output_tokens: 96,
      observed_output_tokens: 8, output_sha256: 'c'.repeat(64), output_text: '<img src=x onerror=alert(1)>'}}}))};
}

test('inference allowance is charged by reservation and never observed usage', () => {
  const ui = dashboard();
  const receipt = inferenceTask();
  assert.equal(ui.taskStateLabel(receipt), 'Inference receipts recorded');
  const rendered = text(ui.buildInferenceEvidence(receipt));
  assert.match(rendered, /288 \/ 288 output-token allowance reserved/);
  assert.match(rendered, /24 output tokens observed/);
  assert.match(rendered, /does not refund/);
  assert.match(rendered, /Tenant synthetic-a · Broker broker-a/);
  assert.match(rendered, /operator-attested/);
});

test('unknown inference burns only reserved slot and exposes no retry action', () => {
  const ui = dashboard();
  const receipt = inferenceTask(true);
  assert.equal(ui.inferenceSlotLabel(receipt.slots[0]), 'Unknown — allowance consumed');
  assert.match(text(ui.buildInferenceEvidence(receipt)), /96 \/ 288 output-token allowance reserved/);
  assert.doesNotMatch(text(ui.buildTaskDetail(receipt)), /GitHub API|Vault API|Check workflow|may have written/);
});

test('inference output is a text child, not executable HTML', () => {
  const ui = dashboard();
  const detail = ui.buildTaskDetail(inferenceTask());
  const seen = [];
  function visit(node) {if (typeof node === 'object') {seen.push(node); node.children.forEach(visit);}}
  visit(detail);
  assert.ok(seen.some(node => node.tag === 'p' && node.children.includes('<img src=x onerror=alert(1)>')));
  assert.ok(seen.every(node => node.tag !== 'img' && !Object.hasOwn(node.attrs, 'innerHTML')));
  const receiptTable = seen.find(node => node.tag === 'table');
  assert.match(receiptTable.attrs.className, /inference-slots/);
  const cells = seen.filter(node => node.tag === 'td');
  assert.deepEqual(cells.slice(0, 3).map(cell => cell.attrs['data-label']), ['Fixed prompt / pinned source', 'Receipt', 'Evidence']);
});

function auditDashboard(query = '') {
  const ui = dashboard();
  const fields = {'filter-kind': '', 'filter-operation': '', 'filter-outcome': '', 'filter-q': query};
  ui.document.getElementById = id => ({value: fields[id]});
  ui.URLSearchParams = URLSearchParams;
  ui.state.mode = 'live';
  ui.state.auditAvailable = true;
  ui.state.lastAuditSequence = 100;
  const frames = [];
  ui.requestAnimationFrame = callback => frames.push(callback);
  let renders = 0;
  ui.renderAuditList = () => { renders++; };
  const pending = [];
  ui.apiJson = path => new Promise((resolve, reject) => pending.push({path, resolve, reject}));
  return {ui, fields, pending, frames, renders: () => renders};
}
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

test('audit refresh bursts are single-flight and cannot install responses out of order', async () => {
  const {ui, pending} = auditDashboard('deploy');
  const work = ui.applyFilters();
  await nextTurn();
  assert.equal(pending.length, 1);
  for (let i = 0; i < 100; i++) ui.applyFilters();
  assert.equal(pending.length, 1);
  pending[0].resolve({events: [{event_id: 'old', sequence_number: 101}]});
  await nextTurn();
  assert.equal(pending.length, 2);
  pending[1].resolve({events: [{event_id: 'new', sequence_number: 102}]});
  await work;
  assert.equal(ui.state.auditEvents[0].event_id, 'new');
  assert.equal(ui.state.lastAuditSequence, 100, 'snapshot does not advance stream consumption');
});

test('obsolete audit filters cannot install success or failure over the current view', async () => {
  const {ui, fields, pending} = auditDashboard('old');
  const work = ui.applyFilters();
  await nextTurn();
  fields['filter-q'] = 'new';
  ui.applyFilters();
  pending[0].resolve({events: [{event_id: 'obsolete', sequence_number: 101}]});
  await nextTurn();
  assert.equal(ui.state.auditEvents.length, 0);
  assert.match(pending[1].path, /q=new/);
  pending[1].resolve({events: [{event_id: 'current', sequence_number: 102}]});
  await work;
  const failed = ui.applyFilters();
  await nextTurn();
  pending[2].reject(new Error('storage unavailable'));
  await failed;
  assert.equal(ui.state.auditEvents[0].event_id, 'current');
  assert.equal(ui.state.auditError, 'storage unavailable');
});

test('snapshot installation preserves concurrently streamed evidence and batches rendering', async () => {
  const {ui, pending, frames, renders} = auditDashboard();
  const work = ui.applyFilters();
  await nextTurn();
  for (let sequence = 101; sequence <= 200; sequence++) {
    ui.prependAuditEvent({event_id: String(sequence), sequence_number: sequence});
  }
  assert.equal(frames.length, 1);
  assert.equal(renders(), 0);
  pending[0].resolve({events: [{event_id: '100', sequence_number: 100}]});
  await work;
  assert.equal(ui.state.auditEvents[0].sequence_number, 200);
  assert.equal(ui.state.auditEvents.length, 101);
  assert.equal(ui.state.lastAuditSequence, 200);
  assert.equal(frames.length, 1);
  frames.shift()();
  assert.equal(renders(), 1);
});

test('clearing audit invalidates pending snapshots without starting more work', async () => {
  const {ui, pending} = auditDashboard();
  const work = ui.applyFilters();
  await nextTurn();
  ui.applyFilters(); // Also discard a coalesced follow-up when clearing.
  ui.clearAudit();
  pending[0].resolve({events: [{event_id: 'old', sequence_number: 101}]});
  await work;
  assert.equal(ui.state.auditEvents.length, 0);
  assert.equal(pending.length, 1);
});

test('operation inventory distinguishes configured, disabled, fixture and unknown handlers', () => {
  const ui = dashboard();
  const container = ui.el('div');
  ui.document.getElementById = () => container;
  ui.renderOperations(['enabled', 'disabled', 'fixture_only', undefined].map((availability, i) => ({
    name: 'fixture.operation_' + i, provider: 'fixture', safety: 'Safe', mcp_exposed: true,
    default_approval: 'always', availability,
  })));
  const rendered = text(container);
  for (const label of ['Handler enabled', 'Handler disabled', 'Fixture only — no production transport',
    'Availability unavailable', 'defaults do not grant permission', 'Default approval: always']) {
    assert.ok(rendered.includes(label), label);
  }
});

// Run the shipped script with its real initialization, fetch/cancellation paths,
// and DOM mutations. Timers are captured so locked pages cannot silently poll.
function authDashboard(respond) {
  const nodes = new Map();
  const makeNode = (tag = 'div') => ({tag, nodeType:tag === '#document-fragment' ? 11 : 1,
    value:'', hidden:false, disabled:false, style:{}, children:[], focusCalls:[],
    classList:{add(){},remove(){},toggle(){}},
    set textContent(value) { this._text = String(value); this.children = []; },
    get textContent() { return this._text || ''; },
    appendChild(child) {
      if (child.nodeType === 11) { this.children.push(...child.children); child.children = []; }
      else this.children.push(child);
      return child;
    },
    prepend(child) { this.children.unshift(child); },
    setAttribute(name, value) { this[name] = value; },
    getAttribute(name) { return this[name]; },
    querySelectorAll(selector) {
      const matches = [];
      function visit(node) {
        if (typeof node !== 'object' || node === null) return;
        if (selector.startsWith('.') && (node.className || '').split(/\s+/).includes(selector.slice(1))) matches.push(node);
        for (const child of node.children || []) visit(child);
      }
      for (const child of this.children) visit(child);
      return matches;
    },
    addEventListener(){}, focus(options){ this.focused = true; this.focusCalls.push(options); document.activeElement = this; },
  });
  const document = {
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, makeNode()); return nodes.get(id); },
    querySelector(selector) {
      if (selector === '.tab-bar') return this.getElementById('tab-bar');
      if (selector.startsWith('#')) return nodes.get(selector.slice(1)) || null;
      return null;
    },
    querySelectorAll() { return []; },
    createElement: makeNode, createTextNode: value => String(value), createDocumentFragment: () => makeNode('#document-fragment'),
    documentElement:makeNode('html'),
  };
  document.documentElement.setAttribute('data-md-color-scheme', 'slate');
  const events = new Map(), timers = new Map(), frames = new Map(), calls = [];
  let id = 0, viewportWidth = 1024;
  const context = vm.createContext({document, URL, URLSearchParams, console, AbortController, TextDecoder,
    window:{addEventListener(name, fn) { events.set(name, fn); }, matchMedia(query) {
      const maxWidth = /^\(max-width:\s*(\d+)px\)$/.exec(query);
      return {media:query, matches:maxWidth ? viewportWidth <= Number(maxWidth[1]) : false};
    }},
    fetch(path, options) { calls.push({path, options}); return respond(path, options); },
    setTimeout(fn, delay) { timers.set(++id, {fn, delay, type:'timeout'}); return id; },
    setInterval(fn, delay) { timers.set(++id, {fn, delay, type:'interval'}); return id; },
    clearTimeout(id) { timers.delete(id); }, clearInterval(id) { timers.delete(id); },
    requestAnimationFrame(fn) { frames.set(++id, fn); return id; }, cancelAnimationFrame(id) { frames.delete(id); },
    localStorage:{getItem(){throw new Error('credential persistence');},setItem(){throw new Error('credential persistence');}},
    sessionStorage:{getItem(){throw new Error('credential persistence');},setItem(){throw new Error('credential persistence');}},
  });
  const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  vm.runInContext(html.split('<script>')[1].split('</script>')[0], context);
  return {ui:context, nodes, timers, frames, calls, events,
    resize(width) { viewportWidth = width; events.get('resize')({}); },
    async unlock(token = 'synthetic-owner-token') {
      document.getElementById('unlock-token').value = token;
      await context.unlockDashboard({preventDefault(){}});
      await nextTurn();
    },
  };
}
function jsonResponse(body, status = 200) {
  return {ok:status >= 200 && status < 300, status, json:async () => body, headers:{get:() => 'application/json'}};
}
function disconnectedResponse(path) {
  return Promise.resolve(jsonResponse(path === '/api/status'
    ? {mode:'disconnected', daemon_running:false, audit_available:false}
    : {tasks:[]}));
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => {resolve=yes;reject=no;}); return {promise, resolve, reject}; }

test('tab orientation follows the responsive breakpoint without accessing private data', () => {
  const fixture = authDashboard(() => {throw new Error('orientation must not fetch');});
  const tabs = fixture.ui.document.querySelector('.tab-bar');
  assert.equal(tabs.getAttribute('aria-orientation'), 'vertical');
  fixture.resize(820);
  assert.equal(tabs.getAttribute('aria-orientation'), 'horizontal');
  fixture.resize(390);
  assert.equal(tabs.getAttribute('aria-orientation'), 'horizontal');
  fixture.resize(821);
  assert.equal(tabs.getAttribute('aria-orientation'), 'vertical');
  assert.equal(fixture.ui.auth.unlocked, false);
  assert.equal(fixture.calls.length, 0);
  assert.equal(fixture.timers.size, 0);
});

test('session countdown updates existing expiry cells without replacing the focused scrolled table', async () => {
  const fixture = authDashboard(disconnectedResponse);
  await fixture.unlock();
  const ui = fixture.ui;
  let now = 1_800_000_000_000;
  ui.Date = class extends Date { static now() { return now; } };
  ui.state.activeTab = 'sessions';
  ui.state.sessionsData = [
    {session_id:'healthy-to-expiring', label:'Synthetic fixture', expires_at_utc_ms:now + 301_000, ttl_remaining_secs:9999},
    {session_id:'less-than-a-second', expires_at_utc_ms:now + 500, ttl_remaining_secs:9999},
    {session_id:'already-expired', expires_at_utc_ms:now - 1000, ttl_remaining_secs:9999},
  ];
  ui.renderSessions();
  const container = fixture.nodes.get('sessions-content');
  const wrapper = container.children[0];
  const table = wrapper.children[0];
  const cells = container.querySelectorAll('.session-ttl');
  assert.equal(cells.length, 3);
  wrapper.scrollLeft = 123;
  wrapper.focus();
  ui.document.querySelectorAll = selector => selector === '#sessions-content .session-ttl' ? cells : [];
  ui.renderSessions = () => { throw new Error('countdown must preserve the existing table DOM'); };
  ui.startSessionCountdown();
  const timer = fixture.timers.get(ui.state.sessionCountdownTimer);
  assert.equal(timer.delay, 1000);
  timer.fn();
  assert.deepEqual(ui.state.sessionsData.map(session=>session.ttl_remaining_secs), [301,0,0]);
  assert.equal(cells[0].textContent, '5m 1s');
  assert.equal(cells[0].className, 'session-ttl healthy');
  assert.equal(cells[1].textContent, '0s');
  assert.equal(cells[2].textContent, '0s');
  assert.equal(cells[1].className, 'session-ttl expiring');

  now += 2000;
  timer.fn();
  assert.equal(cells[0].textContent, '4m 59s');
  assert.equal(cells[0].className, 'session-ttl expiring');
  assert.deepEqual(ui.state.sessionsData.map(session=>session.ttl_remaining_secs), [299,0,0]);
  assert.equal(container.children[0], wrapper);
  assert.equal(wrapper.children[0], table);
  assert.deepEqual(container.querySelectorAll('.session-ttl'), cells);
  assert.equal(ui.document.activeElement, wrapper);
  assert.equal(wrapper.scrollLeft, 123);
  ui.lockDashboard();
  cells[0].textContent = 'old view';
  timer.fn();
  assert.equal(cells[0].textContent, 'old view', 'a callback from the locked generation stays inert');
});

test('audit rerender retains the focused event without scrolling or moving focus from another control', async () => {
  const fixture = authDashboard(disconnectedResponse);
  await fixture.unlock();
  const selected = {event_id:'selected', sequence_number:100, kind:'request.received'};
  fixture.ui.state.auditEvents = [selected];
  fixture.ui.renderAuditList();
  const list = fixture.nodes.get('audit-list');
  const original = list.querySelectorAll('.audit-event')[0];
  original.focus();

  fixture.ui.prependAuditEvent({event_id:'newer', sequence_number:101, kind:'request.received'});
  for (const frame of fixture.frames.values()) frame();
  fixture.frames.clear();
  const rows = list.querySelectorAll('.audit-event');
  assert.equal(rows.length, 2);
  assert.notEqual(rows[1], original, 'the focused row is a newly rendered DOM node');
  assert.equal(fixture.ui.document.activeElement, rows[1]);
  assert.equal(rows[1].getAttribute('data-event-key'), fixture.ui.auditEventKey(selected));
  assert.equal(rows[1].focusCalls.length, 1);
  assert.equal(rows[1].focusCalls[0].preventScroll, true);
  assert.equal(rows[0].focusCalls.length, 0, 'new evidence does not take focus');

  const filter = fixture.ui.document.getElementById('filter-q');
  filter.focus();
  fixture.ui.renderAuditList();
  assert.equal(fixture.ui.document.activeElement, filter);
  assert.ok(list.querySelectorAll('.audit-event').every(row=>row.focusCalls.length === 0));

  const removed = list.querySelectorAll('.audit-event')[0];
  removed.focus();
  fixture.ui.state.auditEvents = [selected];
  fixture.ui.renderAuditList();
  assert.ok(list.querySelectorAll('.audit-event').every(row=>row.focusCalls.length === 0), 'a removed event does not transfer focus to a different receipt');
  fixture.ui.lockDashboard();
});

test('theme switching stays in memory and does not unlock, fetch, restart timers or modify private state', async () => {
  const fixture = authDashboard(disconnectedResponse);
  const root = fixture.ui.document.documentElement;
  assert.equal(root.getAttribute('data-md-color-scheme'), 'slate');
  fixture.ui.toggleTheme();
  assert.equal(root.getAttribute('data-md-color-scheme'), 'default');
  assert.equal(fixture.ui.auth.unlocked, false);
  assert.equal(fixture.ui.authToken, '');
  assert.equal(fixture.calls.length, 0);
  assert.equal(fixture.timers.size, 0);

  await fixture.unlock();
  const generation = fixture.ui.auth.generation;
  const calls = fixture.calls.length;
  const timers = fixture.timers.size;
  fixture.ui.state.auditEvents = [{event_id:'retained-private-record'}];
  fixture.ui.toggleTheme();
  assert.equal(root.getAttribute('data-md-color-scheme'), 'slate');
  assert.equal(fixture.ui.auth.generation, generation);
  assert.equal(fixture.ui.auth.unlocked, true);
  assert.equal(fixture.ui.authToken, 'synthetic-owner-token');
  assert.equal(fixture.calls.length, calls);
  assert.equal(fixture.timers.size, timers);
  assert.equal(fixture.ui.state.auditEvents[0].event_id, 'retained-private-record');
  fixture.ui.lockDashboard();
  assert.equal(fixture.ui.state.auditEvents.length, 0);
  assert.equal(fixture.ui.authToken, '');
});

test('a new locked page sends no protected requests or timers', async () => {
  const fixture = authDashboard(() => {throw new Error('must stay locked');});
  await nextTurn();
  assert.equal(fixture.calls.length, 0);
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.ui.authToken, '');
  assert.equal(fixture.ui.auth.unlocked, false);
  assert.equal(fixture.nodes.get('dashboard-private').hidden, true);
  await fixture.ui.pollStatus();
  await fixture.ui.loadTasks();
  await fixture.ui.reconcileTask('some-task');
  await fixture.ui.connectSSE();
  assert.equal(fixture.calls.length, 0);
});

test('owner entry initializes once and accepts an authenticated disconnected daemon', async () => {
  const fixture = authDashboard(disconnectedResponse);
  await fixture.unlock();
  assert.equal(fixture.ui.auth.unlocked, true);
  assert.equal(fixture.ui.state.mode, 'disconnected');
  assert.equal(fixture.nodes.get('unlock-token').value, '');
  assert.equal(fixture.nodes.get('dashboard-private').hidden, false);
  assert.deepEqual(fixture.calls.map(call => call.path), ['/api/status', '/api/tasks']);
  assert.equal(fixture.timers.size, 2);
  for (const call of fixture.calls) {
    assert.equal(call.options.headers.Authorization, 'Bearer synthetic-owner-token');
    assert.ok(!call.path.includes('synthetic-owner-token'));
    assert.equal(call.options.cache, 'no-store');
  }
});

test('lock clears private DOM, caches, cursor, credential, timers and pending frames', async () => {
  const fixture = authDashboard(disconnectedResponse);
  await fixture.unlock();
  fixture.ui.state.tasksData = [{id:'private-task'}];
  fixture.ui.state.auditEvents = [{event_id:'private-event'}];
  fixture.ui.state.auditBuffer = [{event_id:'buffered-private'}];
  fixture.ui.state.lastAuditSequence = 88;
  fixture.ui.state.sessionsData = [{id:'private-session'}];
  fixture.ui.scheduleAuditRender();
  for (const id of ['tasks-content','audit-list','policy-rules-list','sessions-content','operations-content','policy-config-path']) fixture.nodes.get(id).textContent = 'private-record';
  fixture.nodes.get('policy-seal-status').style.color = 'private-policy-color';
  fixture.ui.lockDashboard();
  assert.equal(fixture.ui.authToken, '');
  assert.equal(fixture.nodes.get('policy-seal-status').style.color, '');
  assert.equal(fixture.ui.state.tasksData.length, 0);
  assert.equal(fixture.ui.state.auditEvents.length, 0);
  assert.equal(fixture.ui.state.auditBuffer.length, 0);
  assert.equal(fixture.ui.state.sessionsData.length, 0);
  assert.equal(fixture.ui.state.lastAuditSequence, -1);
  assert.equal(fixture.timers.size, 0);
  assert.equal(fixture.frames.size, 0);
  for (const node of fixture.nodes.values()) assert.notEqual(node.textContent, 'private-record');
});

test('401 locks immediately and requires explicit entry of the rotated owner token', async () => {
  let expire = false;
  const fixture = authDashboard(path => expire ? Promise.resolve(jsonResponse({},401)) : disconnectedResponse(path));
  await fixture.unlock();
  expire = true;
  await fixture.ui.pollStatus();
  assert.equal(fixture.ui.auth.unlocked, false);
  assert.equal(fixture.ui.authToken, '');
  assert.equal(fixture.timers.size, 0);
  assert.match(fixture.nodes.get('unlock-message').textContent, /current web.token/);
  await fixture.unlock('wrong-owner-token');
  assert.equal(fixture.ui.auth.unlocked, false);
  expire = false;
  await fixture.unlock('rotated-owner-token');
  assert.equal(fixture.ui.auth.unlocked, true);
  assert.equal(fixture.calls.at(-1).options.headers.Authorization, 'Bearer rotated-owner-token');
});

test('late JSON cannot restore private data after lock or replace a newer unlock', async () => {
  const oldBody = deferred();
  let tasks = 0;
  const fixture = authDashboard(path => {
    if (path === '/api/tasks' && tasks++ === 0) return Promise.resolve({...jsonResponse({}),json:() => oldBody.promise});
    return disconnectedResponse(path);
  });
  await fixture.unlock();
  const oldRequest = fixture.calls.find(call => call.path === '/api/tasks');
  fixture.ui.lockDashboard();
  assert.equal(oldRequest.options.signal.aborted, true);
  await fixture.unlock('new-owner-token');
  oldBody.resolve({tasks:[{id:'stale-private-task'}]});
  await nextTurn();
  assert.equal(fixture.ui.authToken, 'new-owner-token');
  assert.equal(fixture.ui.state.tasksData.length, 0);
  assert.equal(fixture.ui.state.tasksLoaded, true);
  assert.equal(fixture.ui.auth.requests.size, 0);
});

test('locking while unlock JSON is pending cannot reopen the dashboard', async () => {
  const body = deferred();
  const fixture = authDashboard(() => Promise.resolve({...jsonResponse({}),json:() => body.promise}));
  fixture.nodes.get('unlock-token').value = 'pending-owner-token';
  const unlock = fixture.ui.unlockDashboard({preventDefault(){}});
  await nextTurn();
  fixture.ui.lockDashboard();
  body.resolve({mode:'live'});
  await unlock;
  assert.equal(fixture.ui.auth.unlocked, false);
  assert.equal(fixture.ui.authToken, '');
  assert.equal(fixture.calls.length, 1);
  assert.equal(fixture.timers.size, 0);
});

test('late SSE chunks cannot restore audit events or restart reconnect timers', async () => {
  const chunk = deferred();
  let cancelled = 0;
  const fixture = authDashboard(path => Promise.resolve(path === '/api/status'
    ? jsonResponse({mode:'live',daemon_running:true,audit_available:true})
    : path.startsWith('/api/audit?') ? jsonResponse({events:[]})
    : path === '/api/audit/stream' ? {ok:true,status:200,headers:{get:()=>'text/event-stream'},body:{getReader:()=>({read:()=>chunk.promise,cancel:async()=>{cancelled++;}})}}
    : jsonResponse({tasks:[]})));
  await fixture.unlock();
  await nextTurn();
  assert.ok(fixture.calls.some(call => call.path === '/api/audit/stream'));
  fixture.ui.lockDashboard();
  chunk.resolve({done:false,value:new TextEncoder().encode('event: audit\ndata: {"event_id":"late-private","sequence_number":999}\n\n')});
  await nextTurn();
  assert.equal(fixture.ui.state.auditEvents.length, 0);
  assert.equal(fixture.ui.state.lastAuditSequence, -1);
  assert.equal(fixture.timers.size, 0);
  assert.equal(cancelled, 1);
  assert.equal(fixture.ui.auth.requests.size, 0);
});

test('unlock and reconnect never replay an in-flight reconciliation POST', async () => {
  const postBody = deferred();
  const fixture = authDashboard((path,options) => options.method === 'POST'
    ? Promise.resolve({...jsonResponse({}),json:()=>postBody.promise}) : disconnectedResponse(path));
  await fixture.unlock();
  const reconciliation = fixture.ui.reconcileTask('private-task');
  await nextTurn();
  fixture.ui.lockDashboard();
  await fixture.unlock('new-owner-token');
  postBody.resolve({task:{id:'private-task',state:'completed'}});
  await reconciliation;
  assert.equal(fixture.calls.filter(call => call.options.method === 'POST').length, 1);
  assert.equal(fixture.ui.state.reconcilingTask, null);
  assert.equal(fixture.ui.state.tasksData.length, 0);
  assert.equal(Object.keys(fixture.ui.state.reconcileErrors).length, 0);
});

test('the owner token travels only in Authorization headers, never in a request URL, across every call type', async () => {
  const fixture = authDashboard(path => Promise.resolve(
    path === '/api/status' ? jsonResponse({mode:'live', daemon_running:true, audit_available:true})
    : path.startsWith('/api/audit?') ? jsonResponse({events:[]})
    : path === '/api/audit/stream'
      ? {ok:true, status:200, headers:{get:()=>'text/event-stream'},
         body:{getReader:()=>({read:()=>new Promise(()=>{}), cancel:async()=>{}})}}
    : jsonResponse({tasks:[]})));
  // A live daemon drives status polling, the tasks load, the audit snapshot and
  // the audit SSE stream; the explicit reconcile adds the one mutation POST.
  await fixture.unlock('secret-owner-token');
  await nextTurn();
  try { await fixture.ui.reconcileTask('some-task'); } catch (_) {}
  const paths = fixture.calls.map(call => call.path);
  assert.ok(paths.includes('/api/status'), 'status was exercised');
  assert.ok(paths.some(path => path.startsWith('/api/audit?')), 'audit snapshot was exercised');
  assert.ok(paths.includes('/api/audit/stream'), 'audit SSE stream was exercised');
  assert.ok(paths.some(path => path.includes('/reconcile')), 'reconcile POST was exercised');
  for (const call of fixture.calls) {
    assert.ok(!call.path.includes('secret-owner-token'), 'no credential in URL: ' + call.path);
    assert.equal(call.options.headers.Authorization, 'Bearer secret-owner-token');
    assert.equal(call.options.cache, 'no-store');
  }
  fixture.ui.lockDashboard();
  assert.equal(fixture.ui.authToken, '');
});

test('page lifecycle restoration and separate tabs require explicit unlock', async () => {
  const first = authDashboard(disconnectedResponse);
  const second = authDashboard(disconnectedResponse);
  await first.unlock();
  assert.equal(second.ui.auth.unlocked, false);
  assert.equal(second.calls.length, 0);
  first.events.get('pagehide')({});
  first.events.get('pageshow')({persisted:true});
  assert.equal(first.ui.auth.unlocked, false);
  assert.equal(first.ui.authToken, '');
  assert.equal(first.timers.size, 0);
  const reload = authDashboard(disconnectedResponse);
  assert.equal(reload.ui.auth.unlocked, false);
  assert.equal(reload.calls.length, 0);
});
