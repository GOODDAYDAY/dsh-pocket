// ARP 反查（lib/arp.mjs）：跨平台 arp 输出解析、缓存、白名单判定（局域网 MAC 免密）

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeMac,
  isValidMac,
  parseArpOutput,
  createArpResolver,
  checkMacWhitelist,
} from '../lib/arp.mjs';

test('normalizeMac：`-` 分隔转 `:`，统一小写', () => {
  assert.equal(normalizeMac('AA-BB-CC-DD-EE-FF'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(normalizeMac('aa:bb:cc:dd:ee:ff'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(normalizeMac('  A1:B2:C3:D4:E5:F6  '), 'a1:b2:c3:d4:e5:f6');
});

test('isValidMac：合法（`:`/`-` 分隔）为真，其余为假', () => {
  assert.equal(isValidMac('aa:bb:cc:dd:ee:ff'), true);
  assert.equal(isValidMac('AA-BB-CC-DD-EE-FF'), true);
  assert.equal(isValidMac('aa:bb:cc:dd:ee'), false, '少一组');
  assert.equal(isValidMac('aa:bb:cc:dd:ee:ff:00'), false, '多一组');
  assert.equal(isValidMac('aa:bb:cc:dd:ee:gg'), false, '非法字符');
  assert.equal(isValidMac(''), false);
});

test('parseArpOutput：Windows arp -a 格式（`-` 分隔 + 中文尾部）', () => {
  const text = [
    '接口: 192.168.1.100 --- 0x8',
    '  Internet 地址         物理地址              类型',
    '  192.168.1.5           aa-bb-cc-dd-ee-ff     动态',
    '  192.168.1.6           11-22-33-44-55-66     静态',
  ].join('\r\n');
  const map = parseArpOutput(text);
  assert.equal(map.get('192.168.1.5'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(map.get('192.168.1.6'), '11:22:33:44:55:66');
  assert.equal(map.has('192.168.1.100'), false, '接口行（无 MAC）跳过');
  assert.equal(map.size, 2);
});

test('parseArpOutput：Linux ip neigh 与 arp -a、macOS 格式（`:` 分隔）', () => {
  const ipNeigh = '192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE';
  const arpA = '? (192.168.1.6) at 11:22:33:44:55:66 [ether] on wlan0';
  const macos = '? (192.168.1.7) at ab:cd:ef:12:34:56 on en0 ifscope [ethernet]';
  const map = parseArpOutput([ipNeigh, arpA, macos].join('\n'));
  assert.equal(map.get('192.168.1.5'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(map.get('192.168.1.6'), '11:22:33:44:55:66');
  assert.equal(map.get('192.168.1.7'), 'ab:cd:ef:12:34:56');
});

test('parseArpOutput：大写 MAC 归一化为小写', () => {
  const map = parseArpOutput('192.168.1.9 dev eth0 lladdr AA:BB:CC:DD:EE:FF STALE');
  assert.equal(map.get('192.168.1.9'), 'aa:bb:cc:dd:ee:ff');
});

test('createArpResolver：首次 resolve 查询并缓存，peek 立即命中', async () => {
  let calls = 0;
  const resolver = createArpResolver({
    run: async () => { calls++; return '192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE'; },
    ttlMs: 60_000,
  });
  assert.equal(resolver.peek('192.168.1.5'), null, '查询前无缓存');
  assert.equal(await resolver.resolve('192.168.1.5'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(resolver.peek('192.168.1.5'), 'aa:bb:cc:dd:ee:ff', '查询后缓存命中');
  await resolver.resolve('192.168.1.5');
  assert.equal(calls, 1, 'TTL 内不重复执行命令');
});

test('createArpResolver：表中无该 IP → null；命令失败 → null 不抛', async () => {
  const resolver = createArpResolver({
    run: async () => '192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE',
    ttlMs: 60_000,
  });
  assert.equal(await resolver.resolve('10.0.0.9'), null, '不在表中');
  const failing = createArpResolver({ run: async () => { throw new Error('arp not found'); } });
  assert.equal(await failing.resolve('192.168.1.5'), null, '命令失败不抛');
});

test('createArpResolver：TTL 过期后重新查询', async () => {
  let calls = 0;
  const resolver = createArpResolver({
    run: async () => { calls++; return '192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE'; },
    ttlMs: 5,
  });
  await resolver.resolve('192.168.1.5');
  assert.equal(calls, 1);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(resolver.peek('192.168.1.5'), null, '过期后缓存失效');
  await resolver.resolve('192.168.1.5');
  assert.equal(calls, 2, '过期后重新执行');
});

test('checkMacWhitelist：开关关闭 → 拒绝（不触发查询）', () => {
  let queried = false;
  const allowed = checkMacWhitelist({
    enabled: false,
    macs: ['aa:bb:cc:dd:ee:ff'],
    ip: '192.168.1.5',
    peek: () => { queried = true; return 'aa:bb:cc:dd:ee:ff'; },
    resolve: async () => 'aa:bb:cc:dd:ee:ff',
  });
  assert.equal(allowed, false);
  assert.equal(queried, false, '关闭时不查询');
});

test('checkMacWhitelist：缓存命中且在名单 → 放行；命中但不在名单 → 拒绝', () => {
  const macs = ['aa:bb:cc:dd:ee:ff'];
  assert.equal(checkMacWhitelist({ enabled: true, macs, ip: '192.168.1.5', peek: () => 'aa:bb:cc:dd:ee:ff' }), true);
  assert.equal(checkMacWhitelist({ enabled: true, macs, ip: '192.168.1.5', peek: () => '11:22:33:44:55:66' }), false);
  // 名单内 MAC 大写/`-` 形式也命中（归一化双保险）
  assert.equal(checkMacWhitelist({ enabled: true, macs, ip: '192.168.1.5', peek: () => 'AA-BB-CC-DD-EE-FF' }), true);
});

test('checkMacWhitelist：缓存未命中 → 拒绝（fail-closed）并后台预热', async () => {
  let warmed = false;
  const allowed = checkMacWhitelist({
    enabled: true,
    macs: ['aa:bb:cc:dd:ee:ff'],
    ip: '192.168.1.5',
    peek: () => null,
    resolve: async (ip) => { warmed = true; return 'aa:bb:cc:dd:ee:ff'; },
  });
  assert.equal(allowed, false, '未命中缓存回退（走 PIN）');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(warmed, true, '后台触发 ARP 解析');
});

test('checkMacWhitelist：无 IP（空 socket 地址）→ 拒绝', () => {
  assert.equal(checkMacWhitelist({ enabled: true, macs: ['aa:bb:cc:dd:ee:ff'], ip: '' }), false);
});

test('listAll：返回全部设备并顺带预热缓存；命令失败 → 空数组不抛', async () => {
  const resolver = createArpResolver({
    run: async () => '192.168.1.9 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n192.168.1.2 dev wlan0 lladdr 11:22:33:44:55:66 STALE',
    ttlMs: 60_000,
  });
  const devices = await resolver.listAll();
  assert.deepEqual(devices, [
    { ip: '192.168.1.2', mac: '11:22:33:44:55:66' },
    { ip: '192.168.1.9', mac: 'aa:bb:cc:dd:ee:ff' },
  ], '按 IP 排序');
  assert.equal(resolver.peek('192.168.1.9'), 'aa:bb:cc:dd:ee:ff', '发现后请求路径可直接命中缓存');
  const failing = createArpResolver({ run: async () => { throw new Error('no arp'); } });
  assert.deepEqual(await failing.listAll(), [], '命令失败返回空列表');
});
