// ARP 反查（局域网 MAC 白名单的判定基础，见 lib/index.js 装配）
//
// 约束：HTTP/WS 在 TCP 层只能拿到客户端 IP（二层 MAC 只在局域网帧里存在），
// 要拿 MAC 只能查本机 ARP 表（IP → MAC 映射）。因此：
//   - 仅同一子网（局域网扫码）有效；公网隧道流量来自云端，查不到 → 白名单只作用于 LAN；
//   - 判定 fail-closed：缓存未命中 = 不在白名单（走 PIN），后台触发解析，下次请求命中。
//
// 缓存：ARP 表由系统维护（TCP 建连时内核已解析过 ARP），读一次缓存一小段时间即可；
// 命令执行失败/表里没有该 IP → 返回 null，不抛。

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const IP_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const MAC_RE = /\b([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\b/;

/** 归一化：小写、`-` 分隔转 `:`。 */
export function normalizeMac(raw) {
  return String(raw ?? '').trim().toLowerCase().replace(/-/g, ':');
}

/** 校验 MAC 格式（6 组 2 位 hex，`:` 或 `-` 分隔）。 */
export function isValidMac(raw) {
  return MAC_RE.test(String(raw ?? '').trim()) &&
    normalizeMac(raw).split(':').length === 6;
}

/**
 * 解析 ARP 命令输出 → Map<IP, 归一化 MAC>。
 * 兼容 Windows `arp -a`（`-` 分隔 + 中文/英文尾部）、Linux `ip neigh` / `arp -a`、
 * macOS `arp -a`（`:` 分隔）。逐行取 IP + MAC 配对，表头/接口行（无 MAC）自然跳过。
 */
export function parseArpOutput(text) {
  const map = new Map();
  for (const line of String(text).split(/\r?\n/)) {
    const ip = line.match(IP_RE)?.[1];
    const mac = line.match(MAC_RE)?.[1];
    if (ip && mac) map.set(ip, normalizeMac(mac));
  }
  return map;
}

/** 默认 ARP 查询：Linux 优先 `ip neigh`（精确），失败回退 `arp -a`；其他平台 `arp -a`。 */
async function defaultArpLookup() {
  if (process.platform === 'linux') {
    try {
      const r = await execFileAsync('ip', ['neigh', 'show'], { timeout: 3000 });
      return r.stdout;
    } catch { /* 无 ip 命令 → 回退 arp */ }
  }
  const r = await execFileAsync('arp', ['-a'], { timeout: 3000 });
  return r.stdout;
}

/**
 * 带缓存的 IP → MAC 解析器。
 * - peek(ip)：同步读缓存（请求路径用，不阻塞）；
 * - resolve(ip)：异步查 ARP 表并写缓存（后台预热/测试直调）；
 * - listAll()：异步拉取整张 ARP 表（设备发现用），顺带刷新缓存。
 */
export function createArpResolver({ run = defaultArpLookup, ttlMs = 30_000 } = {}) {
  const cache = new Map(); // ip -> { mac, ts }
  const fresh = (hit) => hit && Date.now() - hit.ts < ttlMs;
  return {
    peek(ip) {
      const hit = cache.get(ip);
      return fresh(hit) ? hit.mac : null;
    },
    async resolve(ip) {
      const hit = cache.get(ip);
      if (fresh(hit)) return hit.mac;
      let mac = null;
      try {
        mac = parseArpOutput(await run()).get(ip) ?? null;
      } catch { mac = null; }
      if (mac) cache.set(ip, { mac, ts: Date.now() });
      else cache.delete(ip);
      return mac;
    },
    async listAll() {
      let table;
      try {
        table = parseArpOutput(await run());
      } catch { table = new Map(); }
      const now = Date.now();
      const devices = [];
      for (const [ip, mac] of table) {
        cache.set(ip, { mac, ts: now }); // 顺带预热缓存，省得请求路径再解析一次
        devices.push({ ip, mac });
      }
      return devices.sort((a, b) => a.ip.localeCompare(b.ip));
    },
  };
}

/**
 * 白名单判定（同步，供代理请求路径调用）：
 * 开关关闭 / 无 IP → 拒绝；缓存命中且 MAC 在名单 → 放行；未命中 → 拒绝并后台预热（fail-closed）。
 */
export function checkMacWhitelist({ enabled = false, macs = [], ip, peek = () => null, resolve = async () => {} }) {
  if (!enabled || !ip) return false;
  const mac = peek(ip);
  if (mac) return macs.includes(normalizeMac(mac));
  resolve(ip).catch(() => {}); // 后台预热，不阻塞请求
  return false;
}
