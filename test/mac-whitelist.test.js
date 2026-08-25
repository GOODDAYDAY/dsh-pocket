// MAC 白名单（局域网免密 + 名单外回退 PIN）：settings 持久化 + 代理层判定

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request as httpRequest } from 'node:http';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';

import { createPocketProxy } from '../lib/proxy.mjs';

// ---------- settings ----------

async function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), 'dshp-macwl-'));
  const prev = process.env.DSH_HOME;
  process.env.DSH_HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prev === undefined) delete process.env.DSH_HOME;
    else process.env.DSH_HOME = prev;
    rmSync(home, { recursive: true, force: true });
  }
}

test('MAC 白名单默认关闭、列表为空', () => withHome(async () => {
  const { macWhitelistEnabled, macWhitelist } = await import('../lib/settings.mjs');
  assert.equal(macWhitelistEnabled(), false, '默认关闭（不改变现状）');
  assert.deepEqual(macWhitelist(), [], '默认空名单');
}));

test('开关与列表持久化到 settings.json；MAC/备注归一化', () => withHome(async () => {
  const { macWhitelistEnabled, setMacWhitelistEnabled, macWhitelist, setMacWhitelist, settingsPath } = await import('../lib/settings.mjs');
  assert.equal(setMacWhitelistEnabled(true), true, '开启');
  assert.equal(macWhitelistEnabled(), true, '立即生效');
  setMacWhitelist([{ mac: 'AA-BB-CC-DD-EE-FF', note: '客厅电视' }, { mac: '11:22:33:44:55:66' }]);
  assert.deepEqual(macWhitelist(), [
    { mac: 'aa:bb:cc:dd:ee:ff', note: '客厅电视' },
    { mac: '11:22:33:44:55:66', note: '' },
  ], '归一化后返回');
  const raw = JSON.parse(readFileSync(settingsPath(), 'utf8'));
  assert.equal(raw.lanMacWhitelistEnabled, true, '开关已持久化');
  assert.deepEqual(raw.lanMacWhitelist, [
    { mac: 'aa:bb:cc:dd:ee:ff', note: '客厅电视' },
    { mac: '11:22:33:44:55:66', note: '' },
  ], '列表已持久化');
}));

test('非法 MAC 拒绝、空列表清除名单、可关闭', () => withHome(async () => {
  const { macWhitelist, setMacWhitelist, setMacWhitelistEnabled, macWhitelistEnabled } = await import('../lib/settings.mjs');
  assert.throws(() => setMacWhitelist([{ mac: 'aa:bb:cc' }]), /MAC/, '非法 MAC 抛错');
  assert.throws(() => setMacWhitelist('aa:bb:cc:dd:ee:ff'), /数组/, '非数组拒绝');
  setMacWhitelist([{ mac: 'aa:bb:cc:dd:ee:ff' }]);
  assert.equal(macWhitelist().length, 1);
  setMacWhitelist([]);
  assert.deepEqual(macWhitelist(), [], '空数组清除名单');
  setMacWhitelistEnabled(false);
  assert.equal(macWhitelistEnabled(), false, '可关闭');
}));

test('备注：trim、超长截断、同 MAC 去重（后者覆盖前者）', () => withHome(async () => {
  const { macWhitelist, setMacWhitelist } = await import('../lib/settings.mjs');
  setMacWhitelist([
    { mac: 'aa:bb:cc:dd:ee:ff', note: '  客厅电视  ' },
    { mac: 'aa:bb:cc:dd:ee:ff', note: '卧室电视' },
    { mac: '11:22:33:44:55:66', note: 'x'.repeat(80) },
  ]);
  assert.deepEqual(macWhitelist(), [
    { mac: 'aa:bb:cc:dd:ee:ff', note: '卧室电视' },
    { mac: '11:22:33:44:55:66', note: 'x'.repeat(50) },
  ], 'trim + 去重覆盖 + 50 字截断');
}));

// ---------- proxy 层 ----------

function rawRequest(port, { headers, method = 'GET', body, path = '/' }) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** 原始 TCP 发 WS upgrade 请求，返回 'ok'（101）/ 'denied'（401）/ 'timeout'。 */
function wsUpgrade(port, headers) {
  return new Promise((resolve) => {
    const sock = connect(port, '127.0.0.1', () => {
      sock.write('GET /api/events.host HTTP/1.1\r\n' +
        Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') +
        '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n');
    });
    let buf = '';
    const timer = setTimeout(() => { sock.destroy(); resolve('timeout'); }, 2000);
    sock.on('data', (c) => {
      buf += c.toString('latin1');
      if (buf.includes('101') || buf.includes('401')) {
        clearTimeout(timer);
        sock.destroy();
        resolve(buf.includes('101') ? 'ok' : 'denied');
      }
    });
    sock.on('error', () => { clearTimeout(timer); resolve('denied'); });
  });
}

async function proxyWithAuth(extraAuth = {}) {
  const up = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>dsh</body></html>');
  });
  // 假上游也支持 WS 握手（放行路径要转发到上游拿 101）
  up.on('upgrade', (req, socket) => {
    const accept = createHash('sha1')
      .update(String(req.headers['sec-websocket-key'] ?? '') + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
      .digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
    // 模拟真实服务端：收到对端 FIN（半关闭）即关闭连接，否则 close() 永远等不完
    socket.on('end', () => socket.destroy());
  });
  await new Promise((r) => up.listen(0, '127.0.0.1', r));
  const proxy = await createPocketProxy({
    port: 0, host: '127.0.0.1',
    upstream: { host: '127.0.0.1', port: up.address().port },
    auth: { getToken: () => '12345678', isProtected: () => true, ...extraAuth },
  });
  return { proxy, up };
}

const LAN_HOST = { Host: '192.168.1.50:3081', Accept: 'text/html' };
const PUBLIC_HOST = { Host: 'abc.trycloudflare.com', Accept: 'text/html' };

test('白名单命中（LAN + isMacAllowed=true）→ 免 PIN 直连', async () => {
  const { proxy, up } = await proxyWithAuth({ isMacAllowed: () => true });
  try {
    const r = await rawRequest(proxy.port, { headers: LAN_HOST });
    assert.equal(r.status, 200, '免密直连');
    assert.ok(!r.body.includes('访问密码'), '不出现登录页');
  } finally {
    await proxy.close();
    await new Promise((r) => up.close(r));
  }
});

test('白名单未命中（LAN + isMacAllowed=false）→ 回退 PIN 登录页', async () => {
  const { proxy, up } = await proxyWithAuth({ isMacAllowed: () => false });
  try {
    const r = await rawRequest(proxy.port, { headers: LAN_HOST });
    assert.equal(r.status, 200);
    assert.ok(r.body.includes('访问密码'), '回退登录页');
    const api = await rawRequest(proxy.port, { headers: { ...LAN_HOST, Accept: 'application/json' }, path: '/api/hello' });
    assert.equal(api.status, 401, 'API 未认证 401');
  } finally {
    await proxy.close();
    await new Promise((r) => up.close(r));
  }
});

test('公网（trycloudflare）→ 白名单不生效，即使 isMacAllowed=true 也走 PIN', async () => {
  const { proxy, up } = await proxyWithAuth({ isMacAllowed: () => true });
  try {
    const r = await rawRequest(proxy.port, { headers: PUBLIC_HOST });
    assert.ok(r.body.includes('访问密码'), '公网仍要密码');
  } finally {
    await proxy.close();
    await new Promise((r) => up.close(r));
  }
});

test('白名单关闭（isMacAllowed 未提供）→ 局域网照旧走 PIN（现状不变）', async () => {
  const { proxy, up } = await proxyWithAuth({});
  try {
    const r = await rawRequest(proxy.port, { headers: LAN_HOST });
    assert.ok(r.body.includes('访问密码'), '未提供 isMacAllowed 时保持现状');
  } finally {
    await proxy.close();
    await new Promise((r) => up.close(r));
  }
});

test('连接记录：LAN/公网请求都记录（设备发现来源），最近优先', async () => {
  const { proxy, up } = await proxyWithAuth({});
  try {
    await rawRequest(proxy.port, { headers: LAN_HOST });
    await rawRequest(proxy.port, { headers: PUBLIC_HOST });
    const seen = proxy.getSeenClients();
    assert.ok(seen.length >= 1, '记录了连接客户端');
    assert.ok(seen.some((c) => c.ip === '127.0.0.1' && c.via === 'public'), '公网 Host 记为 public（最近一次覆盖）');
    assert.ok(seen.every((c) => c.lastSeen > 0), '带时间戳');
    assert.deepEqual(seen.map((c) => c.lastSeen), [...seen.map((c) => c.lastSeen)].sort((a, b) => b - a), '按最近连接降序');
  } finally {
    await proxy.close();
    await new Promise((r) => up.close(r));
  }
});

// ---------- mergeDevices（lib/index.js 导出） ----------

test('mergeDevices：ARP 有 MAC → lan；公网无 ARP → mac 为 null 保留 via；ARP-only 设备补入', async () => {
  const { mergeDevices } = await import('../lib/index.js');
  const arp = [
    { ip: '192.168.1.10', mac: 'aa:bb:cc:dd:ee:01' },
    { ip: '192.168.1.99', mac: 'aa:bb:cc:dd:ee:99' }, // 只在 ARP 表、无连接记录
  ];
  const seen = [
    { ip: '192.168.1.10', via: 'lan', lastSeen: 3000 },   // ARP 命中 → lan + mac
    { ip: '203.0.113.5', via: 'public', lastSeen: 2000 }, // 公网 → mac null
    { ip: '192.168.1.20', via: 'lan', lastSeen: 1000 },   // LAN 连接但 ARP 未命中（已过期）→ mac null
  ];
  const merged = mergeDevices(arp, seen);
  assert.deepEqual(merged, [
    { ip: '192.168.1.10', mac: 'aa:bb:cc:dd:ee:01', via: 'lan', lastSeen: 3000 },
    { ip: '203.0.113.5', mac: null, via: 'public', lastSeen: 2000 },
    { ip: '192.168.1.20', mac: null, via: 'lan', lastSeen: 1000 },
    { ip: '192.168.1.99', mac: 'aa:bb:cc:dd:ee:99', via: 'lan', lastSeen: null },
  ], '合并结果：ARP 命中补 mac、公网保留 via、ARP-only 设备也列出（lastSeen null）');
});

test('WS：白名单命中放行（101）；未命中回退 401', async () => {
  const ok = await proxyWithAuth({ isMacAllowed: () => true });
  try {
    assert.equal(await wsUpgrade(ok.proxy.port, LAN_HOST), 'ok', '白名单命中 → 握手成功');
  } finally {
    await ok.proxy.close();
    await new Promise((r) => ok.up.close(r));
  }
  const denied = await proxyWithAuth({ isMacAllowed: () => false });
  try {
    assert.equal(await wsUpgrade(denied.proxy.port, LAN_HOST), 'denied', '未命中 → WS 401');
  } finally {
    await denied.proxy.close();
    await new Promise((r) => denied.up.close(r));
  }
});

// 回归：index.js 的 RPC 接线曾漏 import setMacWhitelistEnabled / setMacWhitelist，
// 点「Trusted devices」开关会在调用时抛 ReferenceError（module 加载不报错，单测难发现）。
test('index.js RPC 接线：macWhitelist.setEnabled / macWhitelist.set 走 settings 持久化', () => withHome(async () => {
  const { apply } = await import('../lib/index.js');
  const { POCKET_RPC_CHANNEL, POCKET_ENDPOINTS } = await import('../client/api.js');

  let handler = null;
  const ctx = {
    logger: () => ({ error() {}, info() {}, warn() {} }),
    webServer: { port: 3080 },
    on: () => () => {},
    effect: () => {},
    connection: {
      rpc: {
        handle: (channel, fn, opts) => {
          assert.equal(channel, POCKET_RPC_CHANNEL);
          handler = fn;
          return () => { handler = null; };
        },
      },
    },
  };
  const stubService = {
    startProxy: async () => ({ port: 3081, getSeenClients: () => [] }),
    dispose: async () => {},
    status: async () => ({}),
    startTunnel: async () => 'https://x.trycloudflare.com',
    stopTunnel: () => {},
  };

  apply(ctx, {}, { service: stubService });
  assert.ok(handler, 'RPC handler 已注册');

  const on = await handler(POCKET_ENDPOINTS.macWhitelistSetEnabled, { on: true });
  assert.equal(on.ok, true, '开启白名单开关不抛 ReferenceError');
  assert.equal(on.value.macWhitelistEnabled, true, '开关已开启');

  const set = await handler(POCKET_ENDPOINTS.macWhitelistSet, { entries: [{ mac: 'aa:bb:cc:dd:ee:ff', note: 'x' }] });
  assert.equal(set.ok, true, '设置白名单不抛 ReferenceError');
  assert.deepEqual(set.value.macWhitelist, [{ mac: 'aa:bb:cc:dd:ee:ff', note: 'x' }], '名单已保存');
}));
