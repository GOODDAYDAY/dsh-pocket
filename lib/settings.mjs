// dsh-pocket 设置持久化（$DSH_HOME/dsh-pocket/settings.json）
//
// 当前项：
//   - lanAuthEnabled    局域网访问密码开关（issue #24），默认开启
//   - publicPinCustom   公网密码是否用户自定义（issue #33），自定义后不自动轮换
//   - lanPinCustom      局域网密码是否用户自定义（issue #33）
// 默认**开启**（安全优先）：局域网扫码也要输 8 位密码；
// 用户可关闭——关闭后局域网扫码直连（仅同一网络内的设备能访问），公网不受影响（永远要密码）。

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { isValidIpv4 } from './ip.mjs';
import { isValidMac, normalizeMac } from './arp.mjs';

const settingsRel = join('dsh-pocket', 'settings.json');
export function settingsPath() {
  return join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), settingsRel);
}

function readSettings() {
  try {
    const raw = JSON.parse(readFileSync(settingsPath(), 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch { /* 无文件/损坏 → 默认 */ }
  return {};
}

function writeSettings(s) {
  try {
    mkdirSync(dirname(settingsPath()), { recursive: true });
    writeFileSync(settingsPath(), JSON.stringify(s, null, 2), { mode: 0o600 });
  } catch { /* 忽略 */ }
  return s;
}

/** 局域网访问密码开关：默认开启（文件缺失/损坏都视为开启）。 */
export function lanAuthEnabled() {
  return readSettings().lanAuthEnabled !== false;
}

/** 设置局域网访问密码开关，返回新状态（持久化）。 */
export function setLanAuthEnabled(on) {
  const s = readSettings();
  s.lanAuthEnabled = !!on;
  writeSettings(s);
  return s.lanAuthEnabled;
}

/** 局域网地址手动覆盖：默认空字符串 = 自动选择。 */
export function lanIpOverride() {
  return readSettings().lanIpOverride ?? '';
}

/** 设置局域网地址覆盖；空字符串清除覆盖，恢复自动选择。非法 IPv4 抛错。 */
export function setLanIpOverride(value) {
  const ip = String(value ?? '').trim();
  if (ip && !isValidIpv4(ip)) {
    throw new Error('局域网地址必须是 IPv4 地址 | LAN address must be an IPv4 address');
  }
  const s = readSettings();
  if (ip) s.lanIpOverride = ip;
  else delete s.lanIpOverride;
  writeSettings(s);
  return ip;
}

// ---------- 访问密码「自定义」标记（issue #33） ----------
// 用户可把公网/局域网密码设成自己固定的 8 位数字（自定义后不再自动轮换）。
// 标记存 settings.json：publicPinCustom / lanPinCustom。
const PIN_CUSTOM_KEYS = { public: 'publicPinCustom', lan: 'lanPinCustom' };

// ---------- 局域网 MAC 白名单（免密直连名单） ----------
// 默认关闭：不改变现状。开启后局域网内名单设备免 PIN 直连，名单外设备回退现有
// 密码流程（开 PIN 则输 PIN，关 PIN 则直连）；公网隧道不受影响（拿不到 MAC，见 arp.mjs）。
// 存储：lanMacWhitelistEnabled / lanMacWhitelist（[{ mac, note }] 数组，mac 归一化小写 `:` 分隔）。
const MAC_LIST_KEY = 'lanMacWhitelist';
const MAC_ENABLED_KEY = 'lanMacWhitelistEnabled';
const NOTE_MAX = 50; // 备注长度上限

/** 白名单开关：默认关闭。 */
export function macWhitelistEnabled() {
  return readSettings()[MAC_ENABLED_KEY] === true;
}

/** 设置白名单开关，返回新状态（持久化）。 */
export function setMacWhitelistEnabled(on) {
  const s = readSettings();
  s[MAC_ENABLED_KEY] = !!on;
  writeSettings(s);
  return s[MAC_ENABLED_KEY];
}

/**
 * 当前白名单：[{ mac, note }]（过滤非法项，保证 mac 都是合法格式）。
 * 兼容旧纯字符串条目（升级前存的），统一转成对象。
 */
export function macWhitelist() {
  const list = readSettings()[MAC_LIST_KEY];
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const entry of list) {
    if (typeof entry === 'string') {
      if (isValidMac(entry)) out.push({ mac: normalizeMac(entry), note: '' });
      continue;
    }
    if (entry && typeof entry === 'object' && isValidMac(entry.mac)) {
      const note = typeof entry.note === 'string' ? entry.note.trim().slice(0, NOTE_MAX) : '';
      out.push({ mac: normalizeMac(entry.mac), note });
    }
  }
  return out;
}

/**
 * 设置白名单：[{ mac, note }]（接受 `:`/`-` 分隔、任意大小写，mac 归一化存储）。
 * 同 mac 重复自动去重（后者覆盖前者）；空数组/undefined 清除名单；
 * 非数组、mac 非法或 note 非字符串抛错。
 */
export function setMacWhitelist(entries) {
  const list = entries === undefined ? [] : entries;
  if (!Array.isArray(list)) {
    throw new Error('MAC 白名单必须是数组 | MAC whitelist must be an array');
  }
  const byMac = new Map();
  for (const entry of list) {
    const mac = typeof entry === 'string' ? normalizeMac(entry) : normalizeMac(entry?.mac);
    if (!isValidMac(mac)) {
      throw new Error(`非法 MAC 地址：${mac}（格式 AA:BB:CC:DD:EE:FF）| invalid MAC: ${mac}`);
    }
    const note = typeof entry?.note === 'string' ? entry.note.trim().slice(0, NOTE_MAX) : '';
    byMac.set(mac, { mac, note });
  }
  const normalized = [...byMac.values()];
  const s = readSettings();
  if (normalized.length) s[MAC_LIST_KEY] = normalized;
  else delete s[MAC_LIST_KEY];
  writeSettings(s);
  return normalized;
}

/** 该 PIN（public | lan）是否用户自定义过（自定义后不自动轮换）。 */
export function pinCustom(which) {
  const key = PIN_CUSTOM_KEYS[which];
  if (!key) return false;
  return readSettings()[key] === true;
}

/** 设置自定义标记，返回新状态。 */
export function setPinCustom(which, on) {
  const key = PIN_CUSTOM_KEYS[which];
  if (!key) return false;
  const s = readSettings();
  s[key] = !!on;
  writeSettings(s);
  return !!on;
}
