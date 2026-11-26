"use strict";

const root = document.querySelector("#ip-monitor-console");
const content = root.querySelector("[data-content]");
const main = root.querySelector("main");
const nav = root.querySelector("[data-navigation]");
const accountActions = root.querySelector("[data-account-actions]");
const dialog = root.querySelector("[data-dialog]");
const notice = root.querySelector("[data-notice]");
const state = { signedIn: false, view: "overview", previous: "overview", targetID: "", roundAt: "", data: null };
const dateOptions = { timeZone: "Asia/Shanghai", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" };
const dateFormat = new Intl.DateTimeFormat("zh-CN", dateOptions);
const roundDateFormat = new Intl.DateTimeFormat("zh-CN", { ...dateOptions, year: "numeric" });
const historySize = 12;
const mainViews = ["overview", "targets", "nodes", "events"];
let routeView = { panel: "connectivity", probe: "", direction: "out", family: 4, changeKey: "", focusChange: false, data: null, error: "" };
let rowDrag = null;
let reorderPending = false;

const mailEvents = [
  ["probe_status", "探针状态"], ["tcp_status", "TCPing 状态"],
  ["icmp_status", "ICMP 状态"], ["route_change", "路由变化"]
];

const verdicts = {
  pending: ["quiet", "等待首轮"],
  ok: ["ok", "可达"],
  icmp_no_reply: ["warn", "ICMP 未响应"],
  refused: ["warn", "端口拒绝"],
  insufficient: ["quiet", "证据不足"],
  multi_region_unreachable: ["bad", "大陆与境外 TCP 均超时"],
  suspected_port_block: ["bad", "疑似 TCP 阻断"],
  tcp_icmp_timeout: ["bad", "TCP 与 ICMP 均超时"]
};
const probeLabels = {
  ok: ["ok", "可达"], timeout: ["bad", "超时"], refused: ["warn", "拒绝"],
  reset: ["warn", "连接重置"], unreachable: ["bad", "不可达"],
  unavailable: ["quiet", "不可用"], error: ["quiet", "探测错误"]
};
const nodeLabels = { pending: ["quiet", "待注册"], online: ["ok", "在线"], offline: ["quiet", "离线"] };

function escape(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}
function time(value, format = dateFormat) {
  const date = new Date(value ?? "");
  return Number.isFinite(date.valueOf()) ? format.format(date) : "—";
}
function address(target) {
  return (target.ip.includes(":") ? "[" + target.ip + "]" : target.ip) + ":" + target.port;
}
function badge(pair) {
  return '<span class="badge ' + pair[0] + '">' + escape(pair[1]) + "</span>";
}
function action(label, name, id, primary = false, small = false) {
  return '<button type="button" class="' + (small ? "text-action" : "action") + (primary ? " primary" : "") +
    '" data-action="' + name + '"' + (id ? ' data-id="' + escape(id) + '"' : "") + ">" + escape(label) + "</button>";
}
function heading(title, caption, buttons = "") {
  return '<header class="page-heading"><div><h1>' + escape(title) + '</h1><p class="subtle">' +
    escape(caption) + "</p></div><div class=\"node-actions\">" + buttons + "</div></header>";
}
function cell(label, value) {
  return '<td><span class="mobile-label" aria-hidden="true">' + escape(label) + "</span>" + value + "</td>";
}
function table(label, headers, rows, extra = "") {
  return '<section class="surface table-wide ' + extra + '" aria-label="' + escape(label) + '">' +
    (rows.length ? "<table><thead><tr>" + headers.map(label => '<th scope="col">' + escape(label) + "</th>").join("") +
      "</tr></thead><tbody>" + rows.join("") + "</tbody></table>" :
      '<p class="empty">暂无' + escape(label) + "</p>") + "</section>";
}
function reorderGrip(item) {
  return '<button type="button" class="reorder-grip" data-reorder="' + escape(item.id) +
    '" aria-label="' + escape("调整 " + item.name + " 的顺序") + '" title="拖动排序，也可按上下方向键">' +
    '<span class="grip-dots" aria-hidden="true"></span></button>';
}
function targetLink(target) {
  return action(target.name, "detail", target.id, false, true) +
    '<code class="target-address">' + escape(address(target)) + "</code>";
}
function intervalMinutes() {
  return state.data.probe_interval_seconds / 60;
}
function isFresh(observation) {
  const freshnessMillis = state.data.probe_interval_seconds * 3000;
  const observedAt = new Date(observation?.observed_at).valueOf();
  return observedAt >= (state.data.probe_schedule_start ?? 0) * 1000 &&
    Date.now() - observedAt <= freshnessMillis;
}
function counts(target, group, key) {
  const online = new Set(state.data.nodes.filter(node => node.group === group && node.state === "online").map(node => node.id));
  const probes = (target.latest ?? []).filter(item => online.has(item.node_id) && isFresh(item))
    .map(item => item[key]).filter(probe => probe && !["error", "unavailable"].includes(probe.status));
  const good = probes.filter(probe => probe.status === "ok").length;
  const color = probes.length === 0 ? "quiet" : good === probes.length ? "ok" : good === 0 ? "bad" : "warn";
  return '<span class="probe mono ' + color + '">' + (probes.length ? good + "/" + probes.length : "—") + "</span>";
}
function targetTable() {
  const rows = state.data.targets.map(target => {
    const verdict = verdicts[target.verdict] ?? verdicts.insufficient;
    return '<tr data-state="' + verdict[0] + '"><td>' +
      '<div class="reorder-name">' + reorderGrip(target) + '<div>' + targetLink(target) + '</div></div></td>' +
      cell("大陆 TCPing", counts(target, "mainland", "tcp")) + cell("大陆 ICMP", counts(target, "mainland", "icmp")) +
      cell("境外 TCPing", counts(target, "overseas", "tcp")) + cell("境外 ICMP", counts(target, "overseas", "icmp")) +
      cell("当前判定", badge(verdict)) + cell("操作", action("编辑", "edit-target", target.id, false, true)) + "</tr>";
  });
  const headers = ["目标", "大陆 TCPing", "大陆 ICMP", "境外 TCPing", "境外 ICMP", "当前判定", "操作"];
  return table("监测目标", headers, rows, "target-table");
}
function recentRounds(target) {
  return (target.history ?? []).slice(-historySize);
}
function roundStatus(round) {
  if (round.sampled === false) return ["missing", "未收到结果"];
  if (round.status === "insufficient") return ["insufficient", "证据不足"];
  return verdicts[round.status] ?? ["insufficient", "证据不足"];
}
function historyLegend() {
  const items = [["ok", "可达"], ["warn", "需关注"], ["bad", "异常"], ["insufficient", "证据不足"], ["missing", "未收到结果"]];
  return '<ul class="history-legend subtle" aria-label="探测历史图例">' + items.map(([color, label]) =>
    '<li><span class="round-block ' + color + '" aria-hidden="true"></span>' + escape(label) + "</li>").join("") + "</ul>";
}
function roundMarks(rounds, selectedAt) {
  const missing = '<span class="round-block missing" aria-hidden="true"></span>'.repeat(historySize - rounds.length);
  const blocks = rounds.map(round => {
    const [color, status] = roundStatus(round);
    const label = escape(time(round.at, roundDateFormat) + " · " + status);
    return '<button type="button" class="round-block ' + color + '" data-action="round-detail" data-id="' + escape(round.at) +
      '" aria-pressed="' + (round.at === selectedAt) + '" title="' + label + '" aria-label="' + label + '"></button>';
  }).join("");
  return '<div class="history-bars" role="group" aria-label="最近探测轮次">' + missing + blocks + "</div>";
}
function historyAxis(times) {
  if (!times.length) return "";
  const endpoints = times.length === 1 ? times : [times[0], times.at(-1)];
  return '<div class="history-labels mono subtle">' + endpoints.map(at => '<time datetime="' + escape(at) + '">' +
    escape(time(at)) + "</time>").join("") + "</div>";
}
function roundDetails(round) {
  const verdict = verdicts[round.status] ?? verdicts.insufficient;
  const header = '<div class="history-details-head"><time class="mono" datetime="' + escape(round.at) + '">' +
    escape(time(round.at, roundDateFormat)) + "</time>" + badge(verdict) +
    (round.sampled === false ? '<span class="subtle">未收到结果</span>' : "") + "</div>";
  if (!round.counts) return header + '<p class="subtle">该轮的协议明细未保留。</p>';
  const items = [["大陆 TCPing", round.counts.mainland?.tcp], ["大陆 ICMP", round.counts.mainland?.icmp],
    ["境外 TCPing", round.counts.overseas?.tcp], ["境外 ICMP", round.counts.overseas?.icmp]];
  return header + '<p class="subtle">可达节点 / 有效节点</p><dl class="history-counts">' + items.map(([name, count]) =>
    "<div><dt>" + escape(name) + '</dt><dd class="mono">' + (count?.valid ? escape(count.reachable) + "/" + escape(count.valid) : "—") +
    "</dd></div>").join("") + "</dl>";
}
function detailHistory(target) {
  const rounds = recentRounds(target);
  if (!rounds.length) return '<p class="empty">等待首轮探测结束</p>';
  const selected = rounds.find(round => round.at === state.roundAt) ?? rounds.at(-1);
  return '<div class="rounds history-detail">' + historyLegend() + roundMarks(rounds, selected.at) + historyAxis(rounds.map(round => round.at)) +
    '<div class="history-details" data-round-details aria-live="polite" aria-atomic="true">' + roundDetails(selected) + "</div></div>";
}
function selectRound(at) {
  const target = state.data.targets.find(item => item.id === state.targetID);
  const round = target && recentRounds(target).find(item => item.at === at);
  if (!round) return;
  state.roundAt = at;
  rememberPage();
  for (const button of content.querySelectorAll('[data-action="round-detail"]')) {
    button.setAttribute("aria-pressed", String(button.dataset.id === at));
  }
  content.querySelector("[data-round-details]").innerHTML = roundDetails(round);
}
function overview() {
  const online = state.data.nodes.filter(node => node.state === "online").length;
  const active = state.data.events.filter(event => event.state === "active").length;
  function metric(label, value, css = "") {
    return '<div class="metric"><dt>' + label + '</dt><dd class="mono ' + css + '">' + value + "</dd></div>";
  }
  return '<section class="overview-hero"><div class="overview-intro"><h1>跨区 IP 可达性监测</h1><p>大陆与境外节点每 ' +
    escape(intervalMinutes()) + ' 分钟执行 TCPing 和 ICMP。</p></div><div class="hero-actions">' +
    action("添加目标", "target-form", "", true) + action("部署节点", "node-form") +
    '</div></section>' +
    '<dl class="metrics">' + metric("监测目标", state.data.targets.length) + metric("活跃异常", active, "num-alert") +
    metric("在线探针", online + " <small>/ " + state.data.nodes.length + "</small>") + "</dl>" +
    routeOverview(state.data.route_overview);
}
function routeOverview(data) {
  const { enabled_targets = 0, online_runners = 0, deployed_runners = 0, latest_trace_at = 0, changes = [] } = data ?? {};
  const latest = latest_trace_at ? escape(routeTime(latest_trace_at)) + ' <small>北京时间</small>' : "—";
  const summary = '<section class="surface"><div class="section-heading"><h2>路由概况</h2></div>' +
    '<dl class="route-overview-metrics"><div><dt>已启用定时追踪</dt><dd><span class="mono">' + escape(enabled_targets) +
    '</span> <small>/ ' + state.data.targets.length + ' 个目标</small></dd></div><div><dt>在线回程端</dt><dd>' +
    '<span class="mono' + (online_runners ? " ok" : "") + '">' + escape(online_runners) + '</span> <small>台 · 已部署 ' +
    escape(deployed_runners) + ' 台</small></dd></div><div><dt>最近一次追踪</dt><dd class="route-overview-time">' +
    latest + '</dd></div></dl></section>';
  const rows = (changes ?? []).map(change => {
    const key = routeChangeKey(change.target_id, change.probe_id, change.direction, change.family, change.window, change.at);
    const direction = change.direction === "back" ? "回程" : "去程";
    const hops = change.hops?.length ? "第 " + change.hops.join("、") + " 跳" : "—";
    return '<li><button type="button" class="route-feed-row route-feed-entry" data-action="route-overview-change" data-id="' +
      escape(change.target_id) + '" data-change-key="' + escape(key) + '"><span class="mono">' + escape(routeTime(change.at)) +
      '</span><strong>' + escape(change.target_name) + '</strong><span>' + escape(change.probe_name) + '</span><span>' +
      escape(direction + " · IPv" + change.family) + '</span><span>' + escape(hops) + '</span><span class="route-feed-arrow" aria-hidden="true">›</span></button></li>';
  }).join("");
  return summary + '<section class="surface"><div class="section-heading"><h2>最近路由变化</h2><span class="subtle">北京时间</span></div>' +
    (rows ? '<div class="route-feed-row route-feed-columns" aria-hidden="true">' +
      '<span>时间</span><span>目标</span><span>探针</span><span>方向 / IP</span><span>变化跳点</span></div>' +
      '<ol class="route-feed">' + rows + '</ol>' : '<p class="empty">暂无路由变化</p>') + '</section>';
}
function probe(probe, protocol) {
  if (!probe) return badge(["quiet", "待测量"]);
  const pair = probeLabels[probe.status] ?? probeLabels.error;
  let status = pair[1];
  if (protocol === "ICMP" && probe.status === "timeout") status = "无回包";
  const stats = probe.sent ? ' <span class="mono subtle">' + escape(probe.received) + "/" + escape(probe.sent) +
    (probe.received ? " · " + escape(Number(probe.rtt_ms).toFixed(1)) + " ms" : "") + "</span>" : "";
  return '<span title="' + escape(probe.detail) + '">' + badge([pair[0], status]) + stats + "</span>";
}
function egressLines(node) {
  return [4, 6].filter(family => node["egress_ipv" + family]).map(family =>
    '<code class="target-address">出口 IPv' + family + " " + escape(node["egress_ipv" + family]) + "</code>"
  ).join("") || '<span class="target-address">出口 IP 未获取</span>';
}
function routeChoice(label, name, value, selected, caption = "") {
  const meta = caption ? '<span class="route-probe-meta">' + escape(caption) + '</span>' : "";
  return '<button type="button" class="action' + (caption ? " route-probe-choice" : "") + '" aria-pressed="' + selected +
    '" data-action="' + name + '" data-id="' + escape(value) + '">' + meta + escape(label) + '</button>';
}
function routeTime(seconds) {
  return time(seconds ? seconds * 1000 : null);
}
function hopLabels(hops) {
  return hops.map(hop => escape(hop.ip + (hop.asn ? " · " + hop.asn : ""))).join("<br>");
}
function routeChangeKey(target, probe, direction, family, window, at) {
  return JSON.stringify([target, probe, direction, family, window, at]);
}
const routeErrors = {
  "target has no resolved address for this family": "目标未解析到此协议的地址。",
  "NextTrace failed to return route JSON": "NextTrace 执行失败，请检查主机权限及 NextTrace 状态。"
};
function routeHops(result) {
  const entries = result.hops ?? [];
  if (!entries.length) return '<p class="empty">未收到任何跳点响应</p>';
  const rows = [];
  for (let i = 1; i <= Math.max(...entries.map(hop => hop.ttl)); i++) {
    const hops = entries.filter(hop => hop.ttl === i);
    if (!hops.length) {
      rows.push("<tr><td>" + i + "</td>" + cell("IP", '<span class="subtle">无响应</span>') +
        cell("延迟", "—") + cell("地区", "—") + cell("ASN / 线路", "—") + cell("反向解析", "—") + "</tr>");
      continue;
    }
    for (const hop of hops) {
      rows.push("<tr><td>" + i + "</td>" +
        cell("IP", '<code>' + escape(hop.ip) + '</code>') + cell("延迟", Number(hop.rtt_ms).toFixed(2) + " ms") +
        cell("地区", escape(hop.location || "—")) +
        cell("ASN / 线路", escape([hop.asn, hop.network].filter(Boolean).join(" · ") || "—")) +
        cell("反向解析", escape(hop.hostname || "—")) + "</tr>");
    }
  }
  return table("路由跳点", ["跳", "IP", "延迟", "地区（仅供参考）", "ASN / 线路", "反向解析"], rows, "route-table");
}
function routeChanges(data) {
  const nodes = new Map(state.data.nodes.map(node => [node.id, node.name]));
  const changes = data.changes.map(change => {
    const job = change.job;
    return {
      at: change.at,
      selected: routeView.changeKey === routeChangeKey(job.target_id, job.probe_id, job.direction, job.family, job.window, change.at),
      label: job.direction === "back" ? "回程路由变化" : "去程路由变化",
      probe: (nodes.get(job.probe_id) || job.probe_id) + " · IPv" + job.family,
      detail: '<code>' + escape(change.destination_ip) + '</code>' +
        '<dl class="route-changes">' + change.hops.map(hop => "<dt>第 " + hop.ttl + " 跳</dt><dd><code>" +
        hopLabels(hop.before) + "</code><span> → </span><code>" + hopLabels(hop.after) + "</code></dd>").join("") + "</dl>"
    };
  });
  for (const change of data.egress_changes ?? []) {
    if (!nodes.has(change.probe_id)) continue;
    changes.push({
      at: change.at, label: "探针出口 IP 变化", probe: nodes.get(change.probe_id) + " · IPv" + change.family,
      detail: '<code>' + escape(change.before) + ' → ' + escape(change.after) + '</code>'
    });
  }
  changes.sort((a, b) => b.at - a.at);
  return table("变化记录", ["事件", "探针", "变化", "时间（北京时间）"], changes.map(change =>
    (change.selected ? '<tr data-selected-route-change tabindex="-1">' : "<tr>") +
    "<td>" + escape(change.label) + "</td>" + cell("探针", escape(change.probe)) +
    cell("变化", change.detail) + cell("时间", escape(routeTime(change.at))) + "</tr>"), "route-table");
}
function routeInterval(minutes) {
  return minutes >= 60 ? (minutes / 60) + " 小时" : minutes + " 分钟";
}
function manualRouteStatus(run) {
  if (!run) return "";
  const marks = { running: ["warn", "正在追踪"], completed: ["ok", "手动追踪完成"], expired: ["warn", "手动追踪超时"] };
  const mark = marks[run.state];
  if (!mark) return "";
  return '<div class="update-feedback" role="status">' + badge(mark) +
    '<span class="subtle">' + escape(run.done + "/" + run.total) + "</span></div>";
}
function routePanel(target) {
  const data = routeView.data;
  if (!data) {
    return '<p class="empty">' + escape(routeView.error || "正在读取路由追踪…") + "</p>";
  }
  if (routeView.panel === "changes") return routeChanges(data);
  const status = { pending: ["quiet", "未部署"], offline: ["quiet", "离线"], unavailable: ["warn", "NextTrace 不可用"], online: ["ok", "在线"] };
  const startTrace = action("立即追踪", "trace-now", target.id, true);
  const traceControl = data.manual?.state === "running" ? startTrace.replace(' type="button"', ' type="button" disabled') : startTrace;
  const runnerVersion = data.runner_version ? '<code class="target-address">版本 ' +
    agentVersion(data.runner_version, data.latest_probe_version) + "</code>" : "";
  const header = '<section class="surface"><div class="section-heading"><div><h2>定时路由追踪</h2><p class="subtle">' +
    (data.enabled ? "每 " + escape(routeInterval(data.minutes)) : "已关闭") + " · 回程端 " + badge(status[data.runner] ?? status.pending) +
    '</p>' + runnerVersion + updateAvailable(data.runner_update_available) + updateStatus(data.runner_update) +
    manualRouteStatus(data.manual) + '</div><div class="node-actions">' + traceControl +
    action("路由设置", "route-settings", target.id) +
    (data.runner === "pending" ? action("部署回程端", "return-install", target.id) :
      action("更新回程端", "show-return-update", target.id) + action("解绑回程端", "return-remove", target.id, false, true)) +
    "</div></div></section>";
  if (!data.enabled && !data.manual && !data.routes.length) return header;
  const probe = state.data.nodes.find(node => node.id === routeView.probe) ?? state.data.nodes[0];
  if (!probe) return header + '<p class="empty">请先添加探针节点</p>';
  const { direction, family } = routeView;
  const result = data.routes.find(({ job }) => job.probe_id === probe.id && job.direction === direction && job.family === family);
  const back = direction === "back";
  const egress = probe["egress_ipv" + family];
  const from = back ? data["runner_ipv" + family] : egress;
  const literalTarget = family === 4 ? /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target.ip) : target.ip.includes(":");
  const to = back ? egress : (result?.destination_ip || (literalTarget ? target.ip : ""));
  const matchingResult = result && (!back || to === result.job.address) ? result : null;
  const lastChange = matchingResult && data.changes.find(item => item.job.probe_id === probe.id &&
    item.job.generation === matchingResult.job.generation && item.job.direction === direction &&
    item.job.family === family && item.destination_ip === matchingResult.destination_ip);
  const probeList = state.data.nodes.map(node => routeChoice(node.name, "route-probe", node.id, node.id === probe.id,
    [node.location, node.isp].filter(Boolean).join(" · "))).join("");
  const filters = '<div class="route-filters"><div class="node-actions route-probe-options" role="group" aria-label="探针">' + probeList +
    '</div><div class="node-actions" role="group" aria-label="方向和协议">' +
    routeChoice("去程", "route-direction", "out", !back) + routeChoice("回程", "route-direction", "back", back) +
    routeChoice("IPv4", "route-family", 4, family === 4) + routeChoice("IPv6", "route-family", 6, family === 6) + "</div></div>";
  const reached = matchingResult && !matchingResult.error && matchingResult.hops?.some(hop => hop.ip === matchingResult.destination_ip);
  const waiting = back && data.runner !== "online" ? "回程端" + (status[data.runner]?.[1] || "未部署") :
    back && !egress ? "尚未获得探针的公网 IPv" + family + " 出口。" :
    !back && !probe.route_ready ? "此探针的 NextTrace 尚不可用。" : "等待首轮追踪。";
  return header + filters + '<section class="surface"><div class="section-heading"><div><h2>' +
    (back ? "回程" : "去程") + " · IPv" + family + '</h2><p class="subtle"><code>' +
    escape(matchingResult?.job.source_ip || from || "等待出口 IP") + " → " +
    escape(to || (back ? "等待出口 IP" : "等待解析 IP")) + '</code></p></div><div>' +
    (matchingResult ? '<p class="subtle">' + escape(routeTime(matchingResult.job.window)) + " · 北京时间" + (matchingResult.job.manual_id ? " · 手动追踪" : "") + "</p>" : "") +
    (matchingResult && !matchingResult.error ? badge(reached ? ["ok", "已到达目标"] : ["quiet", "未观测到目标回包"]) : "") +
    (lastChange ? action("最近变化 " + routeTime(lastChange.at), "detail-panel", "changes", false, true) : "") +
    "</div></div>" +
    (!matchingResult || matchingResult.error ? '<p class="empty">' +
      escape(matchingResult?.error ? routeErrors[matchingResult.error] || matchingResult.error : waiting) + "</p>" : "") +
    "</section>" + (matchingResult && !matchingResult.error ? routeHops(matchingResult) : "");
}
function detail(target) {
  const panels = [["connectivity", "连通性"], ["routes", "路由追踪"], ["changes", "变化记录"]];
  const panelButtons = '<div class="node-actions route-filters" role="group" aria-label="目标详情">' +
    panels.map(([id, label]) => routeChoice(label, "detail-panel", id, routeView.panel === id)).join("") + "</div>";
  const header = action("返回", "back", "", false, true) +
    heading(target.name, address(target), action("编辑目标", "edit-target", target.id) + action("移除目标", "remove-target", target.id)) +
    panelButtons;
  return header + (routeView.panel === "connectivity" ? connectivity(target) :
    '<div class="detail-grid">' + routePanel(target) + '</div>');
}
function connectivity(target) {
  const hostnameTarget = !target.ip.includes(":") && /[a-z]/i.test(target.ip);
  const rows = state.data.nodes.map(node => {
    const item = (target.latest ?? []).find(item => item.node_id === node.id);
    const resolved = item?.resolved_ip ? '<code class="target-address">解析 IP ' + escape(item.resolved_ip) + "</code>" :
      hostnameTarget && item?.tcp?.status === "error" ? '<span class="target-address">DNS 解析失败</span>' : "";
    return "<tr><td><strong>" + escape(node.name) + "</strong>" + egressLines(node) + resolved + "</td>" +
      cell("运营商", escape(node.isp)) + cell("地区", escape(node.location)) +
      cell("TCPing", probe(item?.tcp, "TCPing")) + cell("ICMP", probe(item?.icmp, "ICMP")) +
      cell("观测时间", '<span class="subtle">' + escape(time(item?.observed_at)) + "</span>") +
      cell("节点连接", badge(nodeLabels[node.state] ?? nodeLabels.pending)) + "</tr>";
  });
  return '<div class="detail-grid"><div>' + badge(verdicts[target.verdict] ?? verdicts.insufficient) +
    "</div>" + table("探测节点", ["探针", "运营商", "地区", "TCPing", "ICMP", "观测时间（北京时间）", "节点连接"], rows, "node-table") +
    '<section class="surface"><div class="section-heading"><h2>最近探测轮次</h2><span class="subtle">北京时间</span></div>' +
    detailHistory(target) + "</section></div>";
}
function nodes() {
  const rows = state.data.nodes.map(node => {
    const capability = node.state === "pending" ? "待自检" :
      (node.icmp_v4 ? "IPv4" : "") + (node.icmp_v4 && node.icmp_v6 ? " / " : "") + (node.icmp_v6 ? "IPv6" : "") || "不可用";
    const deployment = node.state === "pending" ? action("生成注册令牌", "rotate-token", node.id, false, true) :
      state.data.release_configured ? action("更新", "show-node-update", node.id, false, true) : "";
    const controls = action("编辑", "edit-node", node.id, false, true) +
      deployment + action("移除节点", "remove-node", node.id, false, true);
    return '<tr><td><div class="reorder-name">' + reorderGrip(node) +
      '<div><strong>' + escape(node.name) + '</strong><code class="target-address">' + escape(node.id) +
      (node.version ? " · " + agentVersion(node.version, state.data.latest_probe_version) : "") +
      "</code>" + updateAvailable(node.update_available) + updateStatus(node.update) + egressLines(node) + "</div></div></td>" +
      cell("运营商", escape(node.isp)) + cell("地区", escape(node.location)) +
      cell("分组", node.group === "mainland" ? "大陆观测" : "境外观测") +
      cell("连接", badge(nodeLabels[node.state] ?? nodeLabels.pending)) +
      cell("ICMP", escape(capability)) + cell("最近心跳", escape(time(node.last_seen))) +
      '<td><div class="node-actions">' + controls + "</div></td></tr>";
  });
  const caption = "每 " + intervalMinutes() + " 分钟探测 · 默认启用 ICMP";
  return heading("探针节点", caption, action("探测设置", "settings-form") + action("添加节点", "node-form", "", true)) +
    table("探针节点", ["节点", "运营商", "地区", "分组", "连接", "ICMP", "最近心跳", "操作"], rows, "node-table");
}
function events() {
  const rows = state.data.events.map(event => {
    const target = state.data.targets.find(item => item.id === event.target_id);
    const resolved = event.resolved_ip ? '<code class="target-address">判定 IP ' + escape(event.resolved_ip) + "</code>" : "";
    const historical = event.target_address && (!target || event.state === "superseded" || event.target_address !== address(target));
    const label = historical ? escape(event.target_name) + '<code class="target-address">' + escape(event.target_address) + "</code>" :
      target ? targetLink(target) : escape(event.target_name);
    const status = event.state === "active" ? ["bad", "进行中"] :
      event.state === "superseded" ? ["quiet", "地址已更改"] : ["ok", "已恢复"];
    return "<tr><td>" + label + resolved + "</td>" +
      cell("状态", badge(status)) +
      cell("判定", badge(verdicts[event.verdict] ?? verdicts.insufficient)) +
      cell("受影响运营商", escape((event.affected_isp_names ?? event.affected_isps ?? []).join("、") || "—")) +
      cell("开始", escape(time(event.started_at))) + cell("结束", escape(time(event.ended_at))) + "</tr>";
  });
  return heading("异常事件", "北京时间 · 连续三轮触发，连续两轮恢复") +
    table("异常事件", ["目标", "状态", "判定", "受影响运营商", "开始", "结束"], rows, "event-table");
}
function render() {
  nav.hidden = accountActions.hidden = !state.signedIn;
  if (!state.signedIn) {
    if (dialog.open) dialog.close();
    content.innerHTML = '<section class="login"><h1>管理端登录</h1><form data-form="login" class="form-fields">' +
      '<label>管理员密码<input type="password" name="password" autocomplete="current-password" required></label>' +
      '<p class="form-message" role="alert" data-error></p><button type="submit" class="action primary">登录</button></form></section>';
    return;
  }
  main.dataset.page = state.view;
  for (const button of nav.querySelectorAll("[data-view]")) {
    const current = state.view === "detail" ? "targets" : state.view;
    if (button.dataset.view === current) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  if (state.view === "targets") content.innerHTML = heading("监测目标", "可达节点 / 有效节点", action("添加目标", "target-form", "", true)) + targetTable();
  else if (state.view === "nodes") content.innerHTML = nodes();
  else if (state.view === "events") content.innerHTML = events();
  else if (state.view === "detail") {
    const target = state.data.targets.find(target => target.id === state.targetID);
    const active = document.activeElement;
    const focusedAt = active?.dataset?.action === "round-detail" ? active.dataset.id : "";
    const routeAction = ["route-probe", "route-direction", "route-family", "detail-panel"].includes(active?.dataset?.action) ? active.dataset.action : "";
    content.innerHTML = target ? detail(target) : heading("目标已移除", "", action("返回总览", "back"));
    if (routeAction) {
      [...content.querySelectorAll("[data-action]")].find(button => button.dataset.action === routeAction &&
        button.dataset.id === active.dataset.id)?.focus({ preventScroll: true });
    }
    if (focusedAt) {
      const buttons = [...content.querySelectorAll('[data-action="round-detail"]')];
      const focus = buttons.find(button => button.dataset.id === focusedAt) ?? buttons.find(button => button.getAttribute("aria-pressed") === "true");
      focus?.focus({ preventScroll: true });
    }
    if (active?.hasAttribute("data-selected-route-change")) {
      content.querySelector("[data-selected-route-change]")?.focus({ preventScroll: true });
    }
  } else {
    const focusedChange = document.activeElement?.dataset?.changeKey;
    content.innerHTML = overview();
    if (focusedChange) focusOverviewChange(focusedChange, { preventScroll: true });
  }
}
function restorePage() {
  const page = window.history.state?.linkObservatoryPage;
  if (!page) return;
  if (mainViews.includes(page.view)) {
    state.view = page.view;
  } else if (page.view === "detail" && typeof page.targetID === "string" && page.targetID) {
    state.view = "detail";
    state.previous = mainViews.includes(page.previous) ? page.previous : "targets";
    state.targetID = page.targetID;
    state.roundAt = typeof page.roundAt === "string" ? page.roundAt : "";
    if (["connectivity", "routes", "changes"].includes(page.panel)) routeView.panel = page.panel;
    if (typeof page.probe === "string") routeView.probe = page.probe;
    if (page.direction === "back") routeView.direction = "back";
    if (page.family === 6) routeView.family = 6;
    if (typeof page.changeKey === "string") routeView.changeKey = page.changeKey;
  }
}
function rememberPage() {
  const { view, previous, targetID, roundAt } = state;
  const { panel, probe, direction, family, changeKey } = routeView;
  const page = view === "detail" ? { view, previous, targetID, roundAt, panel, probe, direction, family, changeKey } : { view };
  window.history.replaceState({ ...window.history.state, linkObservatoryPage: page }, "");
}
function navigate(view) {
  state.view = view;
  rememberPage();
  render();
  if (view === "nodes" || view === "detail") void refresh();
}
function openTarget(id, panel = "connectivity", changeKey = "") {
  state.previous = state.view;
  state.targetID = id;
  state.roundAt = "";
  routeView = { panel, probe: "", direction: "out", family: 4, changeKey, focusChange: Boolean(changeKey), data: null, error: "" };
  navigate("detail");
}
function focusOverviewChange(key, options) {
  [...content.querySelectorAll("[data-change-key]")].find(button => button.dataset.changeKey === key)?.focus(options);
}
function message(text = "", success = false) {
  notice.textContent = text;
  notice.hidden = !text;
  notice.classList.toggle("status-success", success);
}
function openDialog(title, subtitle, body) {
  dialog.innerHTML = '<header class="dialog-head"><div><h2 id="dialog-title">' + escape(title) +
    '</h2>' + (subtitle ? '<p class="subtle">' + escape(subtitle) + "</p>" : "") + "</div>" + action("关闭", "close") +
    '</header><div class="dialog-body">' + body + "</div>";
  if (!dialog.open) dialog.showModal();
  else dialog.querySelector("button").focus();
}
function settingsDialog() {
  openDialog("探测设置", "",
    '<form data-form="settings"><div class="form-fields">' +
    '<label>探测间隔（分钟）<input type="number" name="minutes" min="1" max="10" step="1" value="' +
    escape(intervalMinutes()) + '" required></label>' +
    '<p class="subtle install-note">TCPing 与 ICMP 每轮同时运行。宿主机权限不足时，ICMP 显示「不可用」。</p>' +
    '</div><p class="form-message" role="alert" data-error></p><div class="dialog-actions">' +
    '<button type="submit" class="action primary">保存设置</button></div></form>');
}
async function mailDialog() {
  const config = await api("mail");
  if (!state.signedIn) return;
  const selected = new Set(config.events ?? []);
  const check = (name, label, checked) => '<label class="check-field"><input type="checkbox" name="' + name +
    '"' + (checked ? " checked" : "") + '><span>' + label + '</span></label>';
  const encryption = config.security || "starttls";
  const mode = (value, label) => '<label><input type="radio" name="security" value="' + value + '"' +
    (encryption === value ? " checked" : "") + '><span>' + label + '</span></label>';
  openDialog("邮件提醒", "通过 SMTP 接收探针在线状态、目标连通性与路由变化通知。",
    '<form data-form="mail"><div class="form-fields">' +
    check("enabled", "启用邮件提醒", config.enabled) +
    '<div class="field-grid"><label>SMTP 主机<input name="host" maxlength="253" placeholder="smtp.example.com" spellcheck="false" value="' + escape(config.host) +
    '"></label><label>SMTP 端口<input type="number" name="port" min="1" max="65535" value="' + escape(config.port || 587) + '" required></label>' +
    '<fieldset class="group-field full-field"><legend>加密方式</legend><div class="group-options">' +
    mode("starttls", "STARTTLS（通常 587）") + mode("tls", "TLS（通常 465）") + '</div></fieldset>' +
    '<label>SMTP 用户名<input name="username" maxlength="254" spellcheck="false" autocomplete="off" value="' + escape(config.username) +
    '"></label><label>SMTP 密码或授权码<input type="password" name="password" maxlength="1024" autocomplete="new-password"' +
    (config.has_password ? ' placeholder="已保存，留空保留"' : '') + '></label>' +
    '<label class="full-field">发件地址<input type="email" name="from" maxlength="254" value="' + escape(config.from) +
    '"></label><label class="full-field">收件地址<input name="recipients" maxlength="2560" placeholder="多个地址用逗号分隔" spellcheck="false" value="' +
    escape((config.recipients ?? []).join(", ")) + '"></label></div>' +
    '<fieldset class="group-field"><legend>通知事件</legend><div class="field-grid mail-events">' +
    mailEvents.map(([key, label]) => check(key, label, selected.has(key))).join("") + '</div></fieldset></div>' +
    '<p class="form-message" role="status" data-error></p><div class="dialog-actions">' +
    '<button type="submit" class="action" value="test">发送测试邮件</button> <button type="submit" class="action primary">保存设置</button></div></form>');
}
async function submitMail(form, testing) {
  const data = new FormData(form);
  const cfg = {
    enabled: data.has("enabled"), host: data.get("host"), port: Number(data.get("port")), security: data.get("security"),
    username: data.get("username"), password: data.get("password"), from: data.get("from"),
    recipients: data.get("recipients").split(/[,，;；\n]+/).map(address => address.trim()).filter(Boolean),
    events: mailEvents.map(([key]) => key).filter(key => data.has(key))
  };
  const feedback = form.querySelector("[data-error]");
  const buttons = form.querySelectorAll('[type="submit"]');
  if ([...buttons].some(button => button.disabled)) return;
  const close = dialog.querySelector("[data-action=close]");
  for (const button of [...buttons, close]) button.disabled = true;
  feedback.textContent = "";
  feedback.classList.remove("status-success");
  try {
    await api(testing ? "mail/test" : "mail", testing ? "POST" : "PUT", cfg);
    if (testing) {
      feedback.textContent = "测试邮件已提交给 SMTP 服务器。";
      feedback.classList.add("status-success");
    } else {
      form.elements.password.value = "";
      dialog.close();
      message("邮件提醒设置已保存。", true);
    }
  } catch (err) {
    if (err.status === 401) showLogin("登录已过期，请重新登录。");
    else feedback.textContent = err.message;
  } finally {
    for (const button of [...buttons, close]) button.disabled = false;
  }
}
function passwordDialog() {
  openDialog("修改管理员密码", "保存后需要重新登录。",
    '<form data-form="password"><div class="form-fields">' +
    '<label>当前密码<input type="password" name="current_password" autocomplete="current-password" aria-describedby="password-error" required></label>' +
    '<label>新密码<input type="password" name="new_password" autocomplete="new-password" aria-describedby="password-rules password-error" required></label>' +
    '<p class="subtle" id="password-rules">新密码需含 12–128 个字符，其中至少一个为非空白字符。</p>' +
    '<label>确认新密码<input type="password" name="confirmation" autocomplete="new-password" aria-describedby="password-error" required></label>' +
    '</div><p class="form-message" id="password-error" role="alert" data-error></p><div class="dialog-actions">' +
    '<button type="submit" class="action primary">保存密码</button></div></form>');
  dialog.querySelector('[name="current_password"]').focus();
}
function formDialog(kind, item) {
  const target = kind === "target";
  const group = item?.group ?? "mainland";
  const title = target ? (item ? "编辑目标" : "添加目标") : (item ? "编辑节点" : "配置节点");
  const subtitle = target ? (item ? "更改地址或端口会开始一份新的探测历史。" : "选择目标上的已知开放端口") :
    (item ? "更新节点资料后，原有注册信息会保留。" : "通过独立二进制进行 TCPing 与 ICMP 探测");
  const submit = target ? "保存目标" : item ? "保存节点" : "生成部署命令";
  const fields = target ?
    '<label class="full-field">名称<input name="name" maxlength="32" value="' + escape(item?.name) + '" required></label>' +
    '<label>IP 地址或域名<input name="ip" placeholder="例如 example.com" maxlength="254" autocapitalize="none" spellcheck="false" value="' + escape(item?.ip) + '" required></label>' +
    '<label>TCP 端口<input type="number" min="1" max="65535" name="port" value="' + escape(item?.port ?? 443) + '" required></label>' :
    '<label>节点名称<input name="name" maxlength="32" value="' + escape(item?.name) + '" required></label>' +
    '<label>运营商<input name="isp" maxlength="24" value="' + escape(item?.isp) + '" required></label>' +
    '<label>地区<input name="location" maxlength="24" value="' + escape(item?.location) + '" required></label>' +
    '<fieldset class="group-field"><legend>分组</legend><div class="group-options">' +
    '<label><input type="radio" name="group" value="mainland"' + (group === "mainland" ? " checked" : "") + '><span>大陆观测</span></label>' +
    '<label><input type="radio" name="group" value="overseas"' + (group === "overseas" ? " checked" : "") + '><span>境外观测</span></label></div></fieldset>';
  openDialog(title, subtitle,
    '<form data-form="' + kind + '" data-id="' + escape(item?.id) + '"><div class="field-grid">' + fields + "</div>" +
    '<p class="form-message" role="alert" data-error></p><div class="dialog-actions"><button type="submit" class="action primary">' +
    submit + "</button></div></form>");
}
function showEnrollment(enrollment) {
  const subtitle = enrollment.node.name + " · 有效期至 " + time(enrollment.expires_at);
  if (state.data?.release_configured) return showInstallDialog(enrollment.node, enrollment.token, subtitle);
  openDialog("安装并注册", subtitle,
    '<p class="form-message">配置管理端 HTTPS 地址后可生成安装命令。</p>' +
    '<label class="token-field">一次性令牌<input class="mono" readonly data-field="token" value="' + escape(enrollment.token) + '"></label>' +
    '<div class="dialog-actions"><span role="status" class="subtle" data-feedback></span>' +
    action("复制令牌", "copy", "token", true) + '</div>');
}
function showInstallDialog(node, token = "", subtitle = node.name, back = false, update = false) {
  const installing = back ? !update : Boolean(token);
  const host = back ? "目标主机" : "探针主机";
  const localScript = back ? "install-return.sh" : "install.sh";
  openDialog(back ? (update ? "更新回程端" : "部署回程端") : (installing ? "安装并注册" : "更新探针"), subtitle,
    '<form data-install-form><div class="form-fields">' +
    '<label class="check-field"><input type="checkbox" name="use_proxy"><span>使用 gh-proxy（GitHub 网络受限）</span></label>' +
    '<label data-proxy-field hidden>自定义 gh-proxy 地址<input type="url" name="gh_proxy" maxlength="512" ' +
    'placeholder="https://gh-proxy.example.com" autocomplete="off" spellcheck="false" disabled required></label>' +
    '<label>' + (installing ? '一键安装命令' : '一键更新命令') +
    '<textarea readonly spellcheck="false" rows="7" class="short-command" data-field="install"></textarea></label>' +
    '<p class="subtle">' + (installing ? "在" + host + "运行。安装后会保留本地 " + localScript + "。" : "在" + host + "上用安装时的账号运行。") + '</p>' +
    '<p class="form-message" role="alert" data-error></p></div><div class="dialog-actions">' +
    '<span role="status" class="subtle" data-feedback></span><button type="submit" class="action">生成命令</button>' +
    action(installing ? "复制安装命令" : "复制更新命令", "copy", "install", true) +
    '</div></form>');
  const form = dialog.querySelector("[data-install-form]");
  const useProxy = form.elements.use_proxy;
  const proxy = form.elements.gh_proxy;
  const proxyPreference = "link-observatory.gh-proxy";
  try { proxy.value = localStorage.getItem(proxyPreference) ?? ""; } catch {}
  const output = form.querySelector("[data-field=install]");
  const errorMessage = form.querySelector("[data-error]");
  const feedback = form.querySelector("[data-feedback]");
  const copyButton = form.querySelector("[data-action=copy]");
  const generate = form.querySelector("[type=submit]");
  let generation = 0;
  function resetCommand() {
    generation++;
    output.value = "";
    errorMessage.textContent = feedback.textContent = "";
    copyButton.disabled = true;
    generate.disabled = false;
  }
  async function generateCommand() {
    resetCommand();
    const current = generation;
    const gh_proxy = useProxy.checked ? proxy.value.trim() : "";
    generate.disabled = true;
    feedback.textContent = "正在生成命令…";
    try {
      const endpoint = back ? routeEndpoint(node.id, "return-command") : "nodes/" + encodeURIComponent(node.id) + "/install-command";
      const result = await api(endpoint, "POST", back ? { gh_proxy } : { token, gh_proxy });
      if (generation !== current || !form.isConnected || !dialog.open) return;
      if (gh_proxy) {
        try { localStorage.setItem(proxyPreference, gh_proxy); } catch {}
      }
      output.value = result.command;
      output.scrollTop = 0;
      copyButton.disabled = false;
    } catch (error) {
      if (generation === current && form.isConnected && dialog.open) errorMessage.textContent = error.message;
    } finally {
      if (generation === current) {
        feedback.textContent = "";
        generate.disabled = false;
      }
    }
  }
  form.addEventListener("submit", event => {
    event.preventDefault();
    void generateCommand();
  });
  useProxy.addEventListener("change", () => {
    form.querySelector("[data-proxy-field]").hidden = proxy.disabled = !useProxy.checked;
    resetCommand();
    if (useProxy.checked) proxy.focus();
    else if (!back) void generateCommand();
  });
  proxy.addEventListener("input", resetCommand);
  if (back) resetCommand();
  else void generateCommand();
}
function agentVersion(version, latest) {
  return version === latest ? '<span title="' + escape(version) + '">latest</span>' : escape(version);
}
function updateAvailable(available) {
  return available ? '<div class="update-feedback">' + badge(["warn", "可更新"]) + "</div>" : "";
}
const updateStates = {
  queued: ["quiet", "等待节点领取"],
  running: ["warn", "更新中"],
  succeeded: ["ok", "更新完成"],
  failed: ["bad", "更新失败"],
  expired: ["warn", "更新超时"]
};
function updateStatus(task, showSuccess = false) {
  if (task?.status === "succeeded" && !showSuccess) return "";
  const appearance = updateStates[task?.status];
  if (!appearance) return "";
  return '<div class="update-feedback">' + badge(appearance) +
    '<span class="subtle">' + escape(task.version) + "</span></div>";
}
function showUpdateDialog(item, back = false) {
  const data = routeView.data;
  const supported = back ? data?.runner_managed_updates : item.managed_updates;
  const installed = back ? data?.runner_version : item.version;
  const task = back ? data?.runner_update : item.update;
  const busy = task?.status === "queued" || task?.status === "running";
  const title = back ? "更新回程端" : "更新探针";
  const help = supported ? "在主机上安装配置的发行版。更新完成后程序会自动重启。" :
    "请先在主机上运行手动更新命令，升级到支持后台更新的版本。";
  const manual = action("手动更新命令", back ? "return-update" : "update-command", item.id);
  openDialog(title, item.name,
    '<form data-form="' + (back ? "queue-return-update" : "queue-node-update") +
    '" data-id="' + escape(item.id) + '"><p>' + help + '</p>' +
    (installed ? '<p class="subtle">当前版本 ' + escape(installed) + '</p>' : '') + updateStatus(task, true) +
    '<p class="form-message" role="alert" data-error></p><div class="dialog-actions">' + manual +
    (supported && !busy ? '<button type="submit" class="action primary">开始更新</button>' : '') + '</div></form>');
}
function routeEndpoint(id, operation = "routes") {
  return "targets/" + encodeURIComponent(id) + "/" + operation;
}
function routeSettingsDialog(target) {
  const data = routeView.data;
  const options = [5, 15, 30, 60, 360, 720, 1440, 2880].map(minutes =>
    '<label><input type="radio" required name="minutes" value="' + minutes + '"' +
    (minutes === data.minutes ? " checked" : "") + '><span>' + routeInterval(minutes) + '</span></label>').join("");
  openDialog("路由设置", target.name,
    '<form data-form="route-settings" data-id="' + escape(target.id) + '"><div class="form-fields">' +
    '<label class="check-field"><input type="checkbox" name="enabled"' + (data.enabled ? " checked" : "") +
    '><span>启用定时路由追踪</span></label><fieldset class="group-field"><legend>追踪间隔</legend>' +
    '<div class="group-options route-interval-options">' + options + '</div></fieldset></div>' +
    '<p class="form-message" role="alert" data-error></p><div class="dialog-actions">' +
    '<button type="submit" class="action primary">保存设置</button></div></form>');
}
function removeReturnDialog(target) {
  openDialog("解绑回程端", target.name,
    '<form data-form="return-remove" data-id="' + escape(target.id) + '">' +
    '<p>解绑会吊销该回程端的凭证。在目标主机上运行本地 install-return.sh uninstall 可卸载回程端。</p>' +
    '<p class="form-message" role="alert" data-error></p><div class="dialog-actions">' +
    action("取消", "close") + '<button type="submit" class="action primary">确认解绑</button></div></form>');
}
async function loadRoutes(id) {
  try {
    const data = await api(routeEndpoint(id));
    if (!state.signedIn || state.view !== "detail" || state.targetID !== id) return;
    routeView.data = data;
    routeView.error = "";
  } catch (error) {
    if (!state.signedIn || state.view !== "detail" || state.targetID !== id) return;
    if (error.status === 401) return showLogin("登录已过期，请重新登录。");
    routeView.error = "无法读取路由：" + error.message;
  }
  if (routeView.panel !== "connectivity") render();
  if (routeView.panel === "changes" && routeView.focusChange && routeView.data) {
    routeView.focusChange = false;
    content.querySelector("[data-selected-route-change]")?.focus();
  }
}
function confirmRequest(kind, item) {
  const node = kind === "node";
  const confirmation = '<form data-form="remove" data-kind="' + kind + '" data-id="' + escape(item.id) + '">' +
    "<p>" + (node ? "移除节点会同时吊销其凭证。请在节点主机上用本地 install.sh 卸载探针。" : "移除目标会停止后续探测。") +
    '</p><p class="form-message" role="alert" data-error></p><div class="dialog-actions">' +
    action("取消", "close") + '<button type="submit" class="action primary">确认移除</button></div></form>';
  openDialog(node ? "移除节点" : "移除目标", item.name, confirmation);
}
async function api(path, method = "GET", payload) {
  const options = { method, credentials: "same-origin", cache: "no-store" };
  if (payload !== undefined) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(payload);
  }
  const response = await fetch("/api/admin/" + path, options);
  const data = response.headers.get("Content-Type")?.includes("json") ? await response.json() : null;
  if (!response.ok) throw Object.assign(new Error(data?.error ?? "请求失败，请重试"), { status: response.status });
  return data;
}
let latestRefresh = 0;
function showLogin(text = "", success = false) {
  latestRefresh++;
  state.signedIn = false;
  state.data = null;
  routeView.data = null;
  routeView.error = "";
  render();
  message(text, success);
  content.querySelector('[name="password"]').focus();
}
async function refresh() {
  const request = ++latestRefresh;
  try {
    const data = await api(state.view === "nodes" ? "state?probe_version=1" : "state");
    if (request !== latestRefresh || rowDrag || reorderPending) return;
    state.data = { ...data, nodes: data.nodes ?? [], targets: data.targets ?? [], events: data.events ?? [] };
    state.signedIn = true;
    message();
    if (state.view === "detail" && !state.data.targets.some(target => target.id === state.targetID)) {
      navigate("targets");
      return;
    }
    render();
    if (state.view === "detail" && routeView.panel !== "connectivity") await loadRoutes(state.targetID);
  } catch (error) {
    if (request !== latestRefresh || rowDrag || reorderPending) return;
    if (error.status === 401) {
      if (state.signedIn || !content.querySelector("[data-form=login]")) showLogin();
    } else {
      if (!state.signedIn && !content.querySelector("[data-form=login]")) render();
      message("无法读取管理端状态：" + error.message);
    }
  }
}
async function changePassword(form) {
  const submit = form.querySelector('[type="submit"]');
  if (submit.disabled) return;
  const feedback = form.querySelector("[data-error]");
  const current = form.elements.current_password;
  const next = form.elements.new_password;
  const confirmation = form.elements.confirmation;
  const error = (text, field) => {
    feedback.textContent = text;
    if (field) {
      field.setAttribute("aria-invalid", "true");
      field.focus();
    }
  };
  feedback.textContent = "";
  for (const field of [current, next, confirmation]) field.removeAttribute("aria-invalid");
  const length = [...next.value].length;
  if (length < 12 || length > 128 || /^\p{White_Space}+$/u.test(next.value)) {
    return error("请输入 12–128 个字符的新密码，至少包含一个非空白字符。", next);
  }
  if (next.value === current.value) return error("请使用与当前密码不同的新密码。", next);
  if (next.value !== confirmation.value) return error("两次输入的新密码不一致。", confirmation);

  const close = dialog.querySelector("[data-action=close]");
  submit.disabled = close.disabled = true;
  try {
    await api("password", "POST", { current_password: current.value, new_password: next.value });
    form.reset();
    showLogin("密码已修改，请用新密码重新登录。", true);
  } catch (requestError) {
    if (requestError.status === 401) {
      form.reset();
      showLogin("登录已过期，请重新登录后修改密码。");
    } else if (requestError.status === 403) {
      current.value = "";
      error("当前密码不正确，请重新输入。", current);
    } else if (requestError.status === 429) {
      error("尝试次数过多，请稍后再试。");
    } else if (requestError.status === 400) {
      error("请检查新密码是否符合要求。", next);
    } else {
      error("无法确认密码修改结果，请稍后重试。");
    }
  } finally {
    submit.disabled = close.disabled = false;
  }
}
dialog.addEventListener("cancel", event => {
  if (dialog.querySelector(':is([data-form="password"],[data-form="mail"]) [type="submit"]')?.disabled) event.preventDefault();
});
dialog.addEventListener("close", () => {
  if (!dialog.open) {
    dialog.querySelector(':is([data-form="password"],[data-form="mail"])')?.reset();
    if (dialog.querySelector("[data-install-form]")) dialog.replaceChildren();
  }
});
async function copy(key) {
  const field = [...dialog.querySelectorAll("[data-field]")].find(field => field.dataset.field === key);
  const status = dialog.querySelector("[data-feedback]");
  if (!field || !status) return;
  try {
    await navigator.clipboard.writeText(field.value);
    status.textContent = "已复制";
  } catch {
    field.focus();
    field.select();
    status.textContent = document.execCommand("copy") ? "已复制" : "已选中，请手动复制";
  }
}
root.addEventListener("click", async event => {
  const button = event.target.closest("button");
  if (!button || button.type === "submit") return;
  const { view, action, id } = button.dataset;
  if (view) return navigate(view);
  if (!action) return;
  const target = state.data?.targets.find(target => target.id === id);
  const node = state.data?.nodes.find(node => node.id === id);
  try {
    if (action === "close") dialog.close();
    else if (action === "logout") {
      await api("logout", "POST");
      showLogin();
    } else if (action === "change-password" && state.signedIn) passwordDialog();
    else if (action === "mail-settings" && state.signedIn) await mailDialog();
    else if (action === "target-form") formDialog("target");
    else if (action === "node-form") formDialog("node");
    else if (action === "edit-target" && target) formDialog("target", target);
    else if (action === "edit-node" && node) formDialog("node", node);
    else if (action === "settings-form") settingsDialog();
    else if (action === "back") {
      navigate(state.previous);
      if (state.view === "overview" && routeView.changeKey) focusOverviewChange(routeView.changeKey);
    } else if (action === "detail" && target) openTarget(id);
    else if (action === "route-overview-change" && target) openTarget(id, "changes", button.dataset.changeKey);
    else if (action === "detail-panel") {
      routeView.panel = id;
      rememberPage();
      render();
      if (id !== "connectivity") await loadRoutes(state.targetID);
    } else if (action === "route-probe" || action === "route-direction" || action === "route-family") {
      const key = action.slice(6);
      routeView[key] = key === "family" ? Number(id) : id;
      rememberPage();
      render();
    } else if (action === "trace-now" && target) {
      button.disabled = true;
      try {
        await api(routeEndpoint(id, "routes/trace"), "POST");
        await loadRoutes(id);
      } finally {
        button.disabled = false;
      }
    } else if (action === "route-settings" && target && routeView.data) routeSettingsDialog(target);
    else if ((action === "return-install" || action === "return-update") && target) {
      showInstallDialog(target, "", target.name, true, action === "return-update");
    } else if (action === "show-return-update" && target) showUpdateDialog(target, true);
    else if (action === "show-node-update" && node) showUpdateDialog(node);
    else if (action === "return-remove" && target) removeReturnDialog(target);
    else if (action === "round-detail" && state.view === "detail") selectRound(id);
    else if (action === "update-command" && node) showInstallDialog(node);
    else if (action === "rotate-token" && node) showEnrollment(await api("nodes/" + encodeURIComponent(id) + "/token", "POST"));
    else if (action === "remove-target" && target) confirmRequest("target", target);
    else if (action === "remove-node" && node) confirmRequest("node", node);
    else if (action === "copy") await copy(id);
  } catch (error) {
    message(error.message);
  }
});
root.addEventListener("submit", async event => {
  const form = event.target;
  const mode = form.dataset.form;
  const id = form.dataset.id;
  if (!mode) return;
  event.preventDefault();
  if (mode === "password") return changePassword(form);
  if (mode === "mail") return submitMail(form, event.submitter?.value === "test");
  const submit = form.querySelector("[type=submit]");
  const feedback = form.querySelector("[data-error]");
  const values = Object.fromEntries(new FormData(form).entries());
  submit.disabled = true;
  feedback.textContent = "";
  try {
    if (mode === "login") {
      await api("login", "POST", values);
      await refresh();
    } else if (mode === "target") {
      values.port = Number(values.port);
      await api(id ? "targets/" + encodeURIComponent(id) : "targets", id ? "PUT" : "POST", values);
      dialog.close();
      await refresh();
    } else if (mode === "queue-node-update" || mode === "queue-return-update") {
      const back = mode === "queue-return-update";
      await api(back ? routeEndpoint(id, "return-update") : "nodes/" + encodeURIComponent(id) + "/update", "POST");
      dialog.close();
      if (back) await loadRoutes(id);
      else await refresh();
      message("更新任务已提交。", true);
    } else if (mode === "route-settings" || mode === "return-remove") {
      if (mode === "route-settings") {
        await api(routeEndpoint(id), "PUT", { enabled: form.elements.enabled.checked, minutes: Number(values.minutes) });
      } else {
        await api(routeEndpoint(id, "return-runner"), "DELETE");
      }
      dialog.close();
      await loadRoutes(id);
    } else if (mode === "settings") {
      await api("settings", "PUT", { probe_interval_seconds: Number(values.minutes) * 60 });
      dialog.close();
      await refresh();
    } else if (mode === "node") {
      if (id) {
        await api("nodes/" + encodeURIComponent(id), "PUT", values);
        dialog.close();
      } else {
        const result = await api("nodes", "POST", values);
        state.view = "nodes";
        rememberPage();
        showEnrollment(result);
      }
      await refresh();
    } else if (mode === "remove") {
      const kind = form.dataset.kind;
      await api((kind === "node" ? "nodes/" : "targets/") + encodeURIComponent(form.dataset.id), "DELETE");
      dialog.close();
      await refresh();
    }
  } catch (error) {
    feedback.textContent = error.message;
  } finally {
    submit.disabled = false;
  }
});
function focusGrip(id) {
  [...content.querySelectorAll("[data-reorder]")].find(button => button.dataset.reorder === id)?.focus({ preventScroll: true });
}
async function persistOrder(list, id, index, keepFocus) {
  if (reorderPending) return;
  const items = [...state.data[list]];
  const oldIndex = items.findIndex(item => item.id === id);
  if (oldIndex < 0 || index < 0 || index >= items.length || index === oldIndex) return;
  const [moved] = items.splice(oldIndex, 1);
  items.splice(index, 0, moved);
  reorderPending = true;
  latestRefresh++;
  try {
    await api(list + "/order", "PUT", { ids: items.map(item => item.id) });
    if (state.signedIn && state.data) {
      state.data[list] = items;
      render();
      if (keepFocus && state.view === list) focusGrip(id);
      message("顺序已保存。", true);
    }
  } catch (error) {
    reorderPending = false;
    await refresh();
    if (state.signedIn) {
      if (keepFocus && state.view === list) focusGrip(id);
      message(error.message);
    }
  } finally {
    reorderPending = false;
  }
}
function markDrop(drag) {
  let index = drag.rows.findIndex(row => {
    const rect = row.getBoundingClientRect();
    return drag.y < (rect.top + rect.bottom) / 2;
  });
  if (index === -1) index = drag.rows.length;
  if (index === drag.index) return;
  drag.marker?.removeAttribute("data-drop");
  drag.marker = drag.rows[index] ?? drag.rows.at(-1);
  drag.marker.dataset.drop = index === drag.rows.length ? "after" : "before";
  drag.index = index;
}
function scrollDrag() {
  if (!rowDrag?.moved) return;
  const y = rowDrag.y;
  const distance = y < 56 ? y - 56 : Math.max(0, y - window.innerHeight + 56);
  if (distance) window.scrollBy(0, Math.max(-24, Math.min(24, distance / 3)));
  markDrop(rowDrag);
  rowDrag.frame = requestAnimationFrame(scrollDrag);
}
content.addEventListener("pointerdown", event => {
  const grip = event.target.closest("[data-reorder]");
  if (!grip || !event.isPrimary || event.button !== 0 || rowDrag || reorderPending) return;
  const row = grip.closest("tr");
  const rows = [...row.parentElement.rows].filter(item => item !== row);
  if (!rows.length) return;
  rowDrag = {
    pointer: event.pointerId, id: grip.dataset.reorder, list: state.view, row, rows,
    startY: event.clientY, y: event.clientY, index: -1, moved: false
  };
  content.setPointerCapture(event.pointerId);
});
content.addEventListener("pointermove", event => {
  if (rowDrag?.pointer !== event.pointerId) return;
  rowDrag.y = event.clientY;
  if (rowDrag.moved || Math.abs(rowDrag.y - rowDrag.startY) < 4) return;
  rowDrag.moved = true;
  rowDrag.row.dataset.dragging = "";
  scrollDrag();
});
function finishDrag(event) {
  const drag = rowDrag;
  if (drag?.pointer !== event.pointerId) return;
  rowDrag = null;
  if (drag.moved) {
    cancelAnimationFrame(drag.frame);
    drag.row.removeAttribute("data-dragging");
    if (event.type === "pointerup") {
      drag.y = event.clientY;
      markDrop(drag);
      if (state.view === drag.list) void persistOrder(drag.list, drag.id, drag.index, false);
    }
    drag.marker?.removeAttribute("data-drop");
  }
  if (content.hasPointerCapture(event.pointerId)) content.releasePointerCapture(event.pointerId);
}
for (const type of ["pointerup", "pointercancel", "lostpointercapture"]) content.addEventListener(type, finishDrag);
content.addEventListener("keydown", event => {
  const grip = event.target.closest("[data-reorder]");
  if (!grip || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
  event.preventDefault();
  const list = state.view;
  const index = state.data[list].findIndex(item => item.id === grip.dataset.reorder);
  void persistOrder(list, grip.dataset.reorder, index + (event.key === "ArrowUp" ? -1 : 1), true);
});
restorePage();
void refresh();
window.setInterval(() => {
  if (state.signedIn && !document.hidden && !dialog.open && !rowDrag && !reorderPending) void refresh();
}, 20000);
