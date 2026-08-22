#!/usr/bin/env python3
"""
FreeProxyHub — 免费代理聚合采集器 v2.0
从 VPN Gate 和 GitHub 开源项目采集代理数据，输出 JSON 和订阅文件
限制数据量，防止 OOM
"""

import csv
import json
import os
import re
import time
import urllib.request
import urllib.error
import base64
import io
import sys
import urllib.parse
from datetime import datetime, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 每个来源最大采集数（防止OOM）
MAX_PER_SOURCE = {
    "vpngate": 500,
    "gfpcom_http": 800,
    "gfpcom_socks5": 800,
    "gfpcom_socks4": 500,
    "gfpcom_vless": 500,
    "gfpcom_vmess": 300,
    "gfpcom_trojan": 300,
    "gfpcom_ss": 300,
    "monosans": 500,
    "roosterkid": 300,
    "hookzof": 200,
}

def fetch_url(url, timeout=15):
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FreeProxyHub/1.0",
                "Accept": "text/plain, text/csv, */*"
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt == 0:
                time.sleep(1)
            else:
                print(f"  ⚠ 失败: {e}")
    return None

def safe_text(s):
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(s))

def write_json(filename, data):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  ✅ 已写入 {filename}")

def write_text(filename, text):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"  ✅ 已写入 {filename}")

# ── 1. VPN Gate ────────────────────────────────────

def collect_vpngate():
    """从 VPN Gate 获取 VPN 服务器列表"""
    print("\n🌐 [VPN Gate] 正在采集...")
    # 尝试多个镜像
    urls = [
        "https://www.vpngate.net/api/iphone/",
        "http://219.255.212.214:27095/api/iphone/",
    ]
    raw = None
    for url in urls:
        raw = fetch_url(url)
        if raw:
            print(f"  ✅ 连接成功: {url}")
            break

    if not raw:
        print("  ⚠ VPN Gate 所有镜像均不可达，跳过")
        return []

    lines = raw.strip().split("\n")
    csv_lines = [l for l in lines if not l.startswith("#") and l.strip() and l != "*"]
    if len(csv_lines) < 2:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(csv_lines)))
    proxies = []
    max_count = MAX_PER_SOURCE["vpngate"]
    for row in reader:
        if len(proxies) >= max_count:
            break
        try:
            ip = safe_text(row.get("IP", "")).strip()
            if not ip or ip == "-":
                continue
            ping_str = safe_text(row.get("Ping", "999")).strip()
            ping = int(re.sub(r'[^0-9]', '', ping_str)) if re.sub(r'[^0-9]', '', ping_str) else 999
            if ping > 500:  # 过滤高延迟
                continue

            proxies.append({
                "ip": ip,
                "hostname": safe_text(row.get("HostName", "")).strip(),
                "port": 443,
                "country": safe_text(row.get("CountryLong", "")).strip(),
                "country_code": safe_text(row.get("CountryShort", "")).strip(),
                "protocol": "openvpn",
                "type": "VPN",
                "source": "vpngate",
                "ping": ping,
                "speed": int(re.sub(r'[^0-9.]', '', safe_text(row.get("Speed", "0")).strip()) or 0),
                "score": int(re.sub(r'[^0-9]', '', safe_text(row.get("Score", "0")).strip()) or 0),
                "sessions": int(re.sub(r'[^0-9]', '', safe_text(row.get("Sessions", "0")).strip()) or 0),
                "anti_censorship": "medium"
            })
        except:
            continue

    print(f"  ✅ VPN Gate: {len(proxies)} 条")
    return proxies

# ── 2. GitHub 代理 ─────────────────────────────────

GITHUB_SOURCES = [
    {"name": "gfpcom_http", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt", "protocol": "http"},
    {"name": "gfpcom_socks5", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks5.txt", "protocol": "socks5"},
    {"name": "gfpcom_socks4", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks4.txt", "protocol": "socks4"},
    {"name": "gfpcom_vless", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt", "protocol": "vless"},
    {"name": "gfpcom_vmess", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt", "protocol": "vmess"},
    {"name": "gfpcom_trojan", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt", "protocol": "trojan"},
    {"name": "gfpcom_ss", "url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt", "protocol": "ss"},
    {"name": "monosans_http", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "protocol": "http"},
    {"name": "monosans_socks5", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "protocol": "socks5"},
    {"name": "monosans_socks4", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "protocol": "socks4"},
    {"name": "roosterkid_v2ray", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt", "protocol": "v2ray"},
    {"name": "roosterkid_socks5", "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "protocol": "socks5"},
]

def parse_proxy_uri(uri):
    uri = uri.strip()
    if not uri or uri.startswith("#") or uri.startswith("//"):
        return None

    # vmess://
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="replace")
            data = json.loads(decoded)
            ip = data.get("add", "")
            if not ip or ip == "0.0.0.0":
                return None
            return {
                "ip": ip,
                "port": int(data.get("port", 0)),
                "protocol": "vmess",
                "user_id": data.get("id", ""),
                "network": data.get("net", "tcp"),
                "tls": data.get("tls") == "tls",
                "host": data.get("host", ""),
                "path": data.get("path", ""),
                "remarks": data.get("ps", ""),
                "type": "Proxy",
                "anti_censorship": "strong" if data.get("tls") == "tls" else "medium"
            }
        except:
            return None

    # vless:// trojan:// ss://
    for scheme in ["vless://", "trojan://", "ss://"]:
        if uri.startswith(scheme):
            try:
                rest = uri[len(scheme):]
                user_info = ""
                host_port = rest
                remarks = ""
                if "#" in rest:
                    host_port, remarks = rest.rsplit("#", 1)
                    remarks = urllib.parse.unquote(remarks)
                params_str = ""
                if "?" in host_port:
                    host_port, params_str = host_port.split("?", 1)
                if "@" in host_port:
                    user_info, host_port = host_port.split("@", 1)

                if ":" in host_port:
                    host, port_str = host_port.rsplit(":", 1)
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    host = host_port
                    port = 443

                if not host or host == "0.0.0.0":
                    return None

                params = {}
                if params_str:
                    for kv in params_str.split("&"):
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            params[k] = urllib.parse.unquote(v)

                protocol = scheme.replace("://", "")
                security = params.get("security", "none")
                is_reality = security == "reality"

                anti = "extreme" if is_reality else ("strong" if security == "tls" else "medium")

                return {
                    "ip": host,
                    "port": port,
                    "protocol": protocol,
                    "user_id": user_info,
                    "network": params.get("type", params.get("net", "tcp")),
                    "tls": security in ("tls", "reality"),
                    "reality": is_reality,
                    "host": params.get("host", params.get("sni", "")),
                    "path": params.get("path", ""),
                    "fp": params.get("fp", ""),
                    "pbk": params.get("pbk", ""),
                    "sid": params.get("sid", ""),
                    "remarks": remarks,
                    "type": "Proxy",
                    "anti_censorship": anti
                }
            except:
                return None
    return None

def plain_to_proxy(line, protocol):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    line = re.sub(r'^(http://|https://|socks4://|socks5://|socks://)', '', line)
    line = line.rstrip('/')

    # user:pass@ip:port
    if "@" in line:
        auth_part, addr_part = line.rsplit("@", 1)
        if ":" in addr_part:
            ip, port_str = addr_part.rsplit(":", 1)
            if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                return {"ip": ip, "port": int(port_str), "protocol": protocol, "type": "Proxy", "anti_censorship": "medium"}
    else:
        if ":" in line:
            parts = line.rsplit(":", 1)
            if parts[1].isdigit() and 1 <= int(parts[1]) <= 65535:
                ip = parts[0]
                # IPv6
                if ip.startswith("["):
                    ip = ip.strip("[]")
                # 简单过滤明显无效IP
                if ip and not ip.startswith("0.") and ip != "0.0.0.0":
                    return {"ip": ip, "port": int(parts[1]), "protocol": protocol, "type": "Proxy", "anti_censorship": "medium"}
    return None

def collect_github():
    print("\n📦 [GitHub] 正在采集代理列表...")
    all_proxies = []
    total = len(GITHUB_SOURCES)
    success = 0

    for idx, src in enumerate(GITHUB_SOURCES):
        max_n = MAX_PER_SOURCE.get(src["name"], 500)
        print(f"  [{idx+1}/{total}] {src['name']} (上限{max_n})...", end=" ")
        raw = fetch_url(src["url"])
        if not raw:
            print("❌")
            continue

        lines = raw.split("\n")
        count = 0
        for line in lines:
            if count >= max_n:
                break
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            proxy = None
            if src["protocol"] in ("vless", "vmess", "trojan", "ss", "v2ray"):
                proxy = parse_proxy_uri(line)
            else:
                proxy = plain_to_proxy(line, src["protocol"])

            if proxy:
                proxy["source"] = src["name"].split("_")[0]  # 统一来源名
                all_proxies.append(proxy)
                count += 1

        print(f"✅ {count} 条")
        success += 1

    print(f"  ✅ GitHub: {len(all_proxies)} 条 (来自 {success}/{total} 个源)")
    return all_proxies

# ── 3. 去重 ────────────────────────────────────────

def deduplicate(proxies):
    seen = set()
    unique = []
    for p in proxies:
        key = f"{p.get('ip','')}:{p.get('port',0)}:{p.get('protocol','')}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    print(f"  🔄 去重: {len(proxies)} → {len(unique)}")
    return unique

# ── 4. 订阅生成 ────────────────────────────────────

def generate_subscriptions(proxies):
    print("\n📄 [订阅] 生成订阅文件...")

    # 精选节点：优先取 Reality、Trojan、VMess(TLS) 等抗干扰强的
    premium = [p for p in proxies if p.get("anti_censorship") in ("extreme", "strong")]
    standard = [p for p in proxies if p.get("anti_censorship") == "medium"]

    # 按来源排序，确保多样性
    proxies_sorted = premium + standard[:2000]
    # 去重后的精选
    seen = set()
    final = []
    for p in proxies_sorted:
        key = f"{p['ip']}:{p['port']}:{p.get('protocol','')}"
        if key not in seen:
            seen.add(key)
            final.append(p)

    print(f"  📊 订阅用节点: {len(final)} (抗干扰强: {len(premium)}, 普通: {min(len(standard),2000)})")

    # ---- Clash YAML ----
    clash_items = []
    for p in final[:300]:
        proto = p.get("protocol", "")
        name = p.get("remarks", "") or f"{p['ip']}:{p['port']}"
        name = re.sub(r'[^\w\u4e00-\u9fff\-\.\(\)\[\]@]', '_', name)[:30]

        if proto == "http":
            clash_items.append(f'  - {{name: "{name}", type: http, server: {p["ip"]}, port: {p["port"]}}}')
        elif proto == "socks5":
            clash_items.append(f'  - {{name: "{name}", type: socks5, server: {p["ip"]}, port: {p["port"]}, udp: true}}')
        elif proto == "socks4":
            clash_items.append(f'  - {{name: "{name}", type: socks5, server: {p["ip"]}, port: {p["port"]}, udp: false}}')
        elif proto == "vmess":
            net = p.get("network", "tcp")
            tls = "true" if p.get("tls") else "false"
            clash_items.append(f'  - {{name: "{name}", type: vmess, server: {p["ip"]}, port: {p["port"]}, uuid: "{p.get("user_id","")}", alterId: 0, cipher: auto, tls: {tls}, network: "{net}"}}')
        elif proto == "vless":
            tls = "true" if p.get("tls") else "false"
            net = p.get("network", "tcp")
            if p.get("reality"):
                clash_items.append(f'  - {{name: "{name}", type: vless, server: {p["ip"]}, port: {p["port"]}, uuid: "{p.get("user_id","")}", flow: "xtls-rprx-vision", tls: true, servername: "{p.get("host",p["ip"])}", network: "{net}"}}')
            else:
                clash_items.append(f'  - {{name: "{name}", type: vless, server: {p["ip"]}, port: {p["port"]}, uuid: "{p.get("user_id","")}", tls: {tls}, network: "{net}"}}')
        elif proto == "trojan":
            clash_items.append(f'  - {{name: "{name}", type: trojan, server: {p["ip"]}, port: {p["port"]}, password: "{p.get("user_id","")}", udp: true, sni: "{p.get("host",p["ip"])}"}}')
        elif proto == "ss":
            cipher = p.get("method", "aes-256-gcm")
            pw = p.get("password", p.get("user_id", ""))
            clash_items.append(f'  - {{name: "{name}", type: ss, server: {p["ip"]}, port: {p["port"]}, cipher: "{cipher}", password: "{pw}"}}')

    clash_yaml = f"""# FreeProxyHub 订阅
# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# 节点数: {len(clash_items)}
# 注意: 免费节点可能不稳定，请自行验证

port: 7890
socks-port: 7891
mode: rule
log-level: warning
allow-lan: false

proxies:
{chr(10).join(clash_items)}

proxy-groups:
  - name: "🚀 自动选择"
    type: url-test
    proxies:
      - "♻️ 自动选择"
      - "🎯 手动选择"
    url: "http://www.gstatic.com/generate_204"
    interval: 300
  - name: "♻️ 自动选择"
    type: fallback
    proxies:
      - "🎯 手动选择"
    url: "http://www.gstatic.com/generate_204"
    interval: 300
  - name: "🎯 手动选择"
    type: select
    proxies: ["DIRECT"]

rules:
  - MATCH,🚀 自动选择
"""
    # 添加代理名称到选择组
    clash_yaml = clash_yaml.replace(
        'proxies: ["DIRECT"]',
        'proxies:\n' + "".join(f'      - "{n}"\n' for n in re.findall(r'name: "(.+?)"', clash_yaml[:5000])[:10])
    )
    write_text("clash.yaml", clash_yaml)

    # ---- Base64 订阅 (v2rayNG) ----
    b64_lines = []
    for p in final[:200]:
        proto = p.get("protocol", "")
        if proto == "vmess":
            v = {"v":"2","ps":p.get("remarks","") or f"{p['ip']}:{p['port']}","add":p["ip"],"port":p["port"],
                 "id":p.get("user_id",""),"aid":0,"net":p.get("network","tcp"),"type":"none",
                 "host":p.get("host",""),"path":p.get("path",""),"tls":"tls" if p.get("tls") else ""}
            b64_lines.append(f"vmess://{base64.b64encode(json.dumps(v).encode()).decode()}")
        elif proto == "vless":
            params = f"?type={p.get('network','tcp')}"
            if p.get("tls"): params += "&security=tls"
            if p.get("reality"): params += "&security=reality&flow=xtls-rprx-vision"
            if p.get("host"): params += f"&sni={p['host']}"
            if p.get("pbk"): params += f"&pbk={p['pbk']}"
            if p.get("fp"): params += f"&fp={p['fp']}"
            rem = base64.b64encode((p.get("remarks","") or f"{p['ip']}:{p['port']}").encode()).decode()
            b64_lines.append(f"vless://{p.get('user_id','')}@{p['ip']}:{p['port']}{params}#{rem}")
        elif proto == "trojan":
            rem = base64.b64encode((p.get("remarks","") or f"{p['ip']}:{p['port']}").encode()).decode()
            sni = p.get("host", p["ip"])
            b64_lines.append(f"trojan://{p.get('user_id','')}@{p['ip']}:{p['port']}?sni={sni}#{rem}")
        elif proto == "ss":
            method = p.get("method", p.get("cipher", "aes-256-gcm"))
            pw = p.get("password", p.get("user_id", ""))
            rem = base64.b64encode((p.get("remarks","") or f"{p['ip']}:{p['port']}").encode()).decode()
            ui = base64.b64encode(f"{method}:{pw}".encode()).decode()
            b64_lines.append(f"ss://{ui}@{p['ip']}:{p['port']}#{rem}")

    if b64_lines:
        b64_content = "\n".join(b64_lines)
        write_text("subscribe.txt", b64_content)
        sub_b64 = base64.b64encode(b64_content.encode()).decode()
        write_text("subscribe_base64.txt", sub_b64)

    # ---- 纯文本 ----
    txt_lines = []
    for p in final[:300]:
        if p.get("protocol") in ("http", "https"):
            txt_lines.append(f"{p['protocol']}://{p['ip']}:{p['port']}")
        elif p.get("protocol") in ("socks5", "socks4"):
            txt_lines.append(f"{p['protocol']}://{p['ip']}:{p['port']}")
    if txt_lines:
        write_text("proxies.txt", "\n".join(txt_lines))

    print(f"  ✅ 订阅: Clash={len(clash_items)}, Base64={len(b64_lines)}, Plain={len(txt_lines)}")
    return {"clash": len(clash_items), "base64": len(b64_lines), "plain": len(txt_lines)}

# ── 5. 统计 ────────────────────────────────────────

def generate_stats(proxies):
    stats = {
        "total": len(proxies),
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "protocols": {},
        "sources": {},
        "anti_censorship": {"medium": 0, "strong": 0, "extreme": 0}
    }
    for p in proxies:
        proto = p.get("protocol", "unknown")
        stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
        src = p.get("source", "unknown")
        stats["sources"][src] = stats["sources"].get(src, 0) + 1
        ac = p.get("anti_censorship", "medium")
        if ac in stats["anti_censorship"]:
            stats["anti_censorship"][ac] += 1

    stats["protocols"] = dict(sorted(stats["protocols"].items(), key=lambda x: -x[1]))
    stats["sources"] = dict(sorted(stats["sources"].items(), key=lambda x: -x[1]))
    write_json("stats.json", stats)
    return stats

# ── 主流程 ──────────────────────────────────────────

def main():
    print("=" * 50)
    print("  FreeProxyHub 采集器 v2.0")
    print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)

    all_proxies = []
    all_proxies.extend(collect_vpngate())
    all_proxies.extend(collect_github())

    print(f"\n📊 总计: {len(all_proxies)} 条")
    unique = deduplicate(all_proxies)
    write_json("proxies.json", unique)

    stats = generate_stats(unique)
    print(f"\n📈 统计:")
    print(f"  总代理数: {stats['total']}")
    print(f"  协议: {', '.join(f'{k}={v}' for k,v in stats['protocols'].items())}")
    print(f"  来源: {', '.join(f'{k}={v}' for k,v in stats['sources'].items())}")
    print(f"  抗干扰: {', '.join(f'{k}={v}' for k,v in stats['anti_censorship'].items())}")

    sub_stats = generate_subscriptions(unique)

    meta = {
        "version": "2.0",
        "updated_at": stats["updated_at"],
        "total_proxies": stats["total"],
        "subscriptions": sub_stats
    }
    write_json("meta.json", meta)

    print(f"\n✅ 完成! 数据保存在 {OUTPUT_DIR}/")
    return 0

if __name__ == "__main__":
    sys.exit(main())