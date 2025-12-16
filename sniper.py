#!/usr/bin/env python3
import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# -----------------------------
# Helpers: process execution
# -----------------------------
TOOL_HELP_CACHE = {}

def run_cmd(cmd, *, input_text=None, timeout=None, check=True):
    p = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            f"Command failed ({p.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}"
        )
    return p.stdout, p.stderr, p.returncode

def tool_help(tool):
    if tool in TOOL_HELP_CACHE:
        return TOOL_HELP_CACHE[tool]
    for flag in ("-h", "--help"):
        try:
            out, err, _ = run_cmd([tool, flag], check=False)
            TOOL_HELP_CACHE[tool] = (out or "") + (err or "")
            return TOOL_HELP_CACHE[tool]
        except Exception:
            continue
    return ""

def has_flag(tool, flag):
    h = tool_help(tool)
    # match whole flag tokens only, avoid substring hits (e.g., "-j" vs "-json")
    return re.search(rf"(?:^|[\s,]){re.escape(flag)}(?:[\s,=]|$)", h) is not None

def first_supported_flag(tool, candidates):
    for f in candidates:
        if has_flag(tool, f):
            return f
    return None

def require_flag(tool, candidates, reason):
    f = first_supported_flag(tool, candidates)
    if not f:
        raise SystemExit(
            f"{tool} must support one of {', '.join(candidates)} for {reason}. "
            "Please update to a recent ProjectDiscovery release."
        )
    return f

def require_tools(tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        raise SystemExit(f"Missing tools in PATH: {', '.join(missing)}")

# -----------------------------
# URL normalization + bucketing
# -----------------------------
TRACKING_PARAMS_RE = re.compile(r"^(utm_|gclid$|fbclid$|yclid$|msclkid$|igshid$)", re.I)

def normalize_url(u: str) -> str | None:
    u = (u or "").strip()
    if not u:
        return None

    # If URL has no scheme, assume http (useful for host inputs)
    if "://" not in u:
        u = "http://" + u

    try:
        sp = urlsplit(u)
    except Exception:
        return None

    scheme = (sp.scheme or "http").lower()

    host = (sp.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None

    port = sp.port
    # Remove default ports
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"

    # Basic path normalization
    path = sp.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    # Optional: drop trailing slash except root
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    # Normalize query: drop tracking params, sort keys
    q = []
    for k, v in parse_qsl(sp.query, keep_blank_values=True):
        k = k.strip()
        if not k:
            continue
        if TRACKING_PARAMS_RE.match(k):
            continue
        q.append((k, v))
    q.sort(key=lambda kv: (kv[0], kv[1]))
    query = urlencode(q, doseq=True)

    return urlunsplit((scheme, netloc, path, query, ""))  # drop fragment

def bucket_key(u_norm: str) -> tuple[str, list[str]]:
    sp = urlsplit(u_norm)
    host = sp.hostname or ""
    path = sp.path or "/"
    params = sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
    key = f"{host}{path}?" + ",".join(params)
    return key, params

# -----------------------------
# Wildcard detection
# -----------------------------
def rand_label(n=12):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

def parse_dnsx_ips(obj: dict) -> set[str]:
    ips = set()
    for k in ("a", "aaaa", "A", "AAAA"):
        v = obj.get(k)
        if isinstance(v, list):
            ips |= {str(x) for x in v if x}
        elif isinstance(v, str) and v:
            ips.add(v)
    # Some versions may put ip in other keys; keep conservative.
    return ips

def parse_httpx_fp(obj: dict) -> tuple:
    # A lightweight fingerprint for wildcard comparison
    return (
        obj.get("status_code"),
        obj.get("content_length"),
        (obj.get("title") or "").strip(),
        obj.get("hash"),
        obj.get("webserver") or obj.get("server"),
    )

def dnsx_single(dnsx, host, extra_flags):
    # Use -u/-target if supported, else temp file with -l
    if has_flag(dnsx, "-u") or has_flag(dnsx, "-target"):
        cmd = [dnsx] + extra_flags + ["-u", host]
        out, _, _ = run_cmd(cmd, check=False)
        lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        if not lines:
            return None
        return json.loads(lines[0])
    else:
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf.write(host + "\n")
            tf.flush()
            cmd = [dnsx] + extra_flags + ["-l", tf.name]
            out, _, _ = run_cmd(cmd, check=False)
        os.unlink(tf.name)
        lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        if not lines:
            return None
        return json.loads(lines[0])

def httpx_single(httpx, host, extra_flags):
    # httpx supports -u/-target per docs
    cmd = [httpx] + extra_flags + ["-u", host]
    out, _, _ = run_cmd(cmd, check=False)
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    if not lines:
        return None
    return json.loads(lines[0])

def build_wildcard_map(domains, dnsx, httpx, out_dir, verify_http=True):
    wildcard = {}  # root -> {"test_host":..., "ips": [...], "http_fp": (...)}

    dnsx_flags = []
    # Prefer JSONL output to stdout for parsing
    dnsx_json_flag = require_flag(dnsx, ["-json", "-j", "-jsonl"], "JSON output parsing")
    dnsx_flags.append(dnsx_json_flag)
    # Ask for A/AAAA where supported
    if has_flag(dnsx, "-a"):
        dnsx_flags += ["-a"]
    if has_flag(dnsx, "-aaaa"):
        dnsx_flags += ["-aaaa"]
    if has_flag(dnsx, "-silent"):
        dnsx_flags += ["-silent"]

    httpx_flags = []
    httpx_json_flag = require_flag(httpx, ["-json", "-j"], "JSON output parsing")
    httpx_flags.append(httpx_json_flag)
    # Minimal but strong probes for fingerprinting
    for f in ("-sc", "-cl", "-title", "-hash", "-silent"):
        if has_flag(httpx, f):
            if f == "-hash":
                # choose md5 for stability (supported per docs)
                httpx_flags += ["-hash", "md5"]
            else:
                httpx_flags += [f]

    for root in domains:
        test_host = f"{rand_label()}.{root}"
        dj = dnsx_single(dnsx, test_host, dnsx_flags)
        if not dj:
            continue
        ips = parse_dnsx_ips(dj)
        if not ips:
            continue

        entry = {"test_host": test_host, "ips": sorted(ips), "dnsx": dj}
        if verify_http:
            hj = httpx_single(httpx, test_host, httpx_flags)
            if hj:
                entry["httpx"] = hj
                entry["http_fp"] = parse_httpx_fp(hj)
        wildcard[root] = entry

    with open(os.path.join(out_dir, "wildcards.json"), "w", encoding="utf-8") as f:
        json.dump(wildcard, f, indent=2)

    return wildcard

def root_match(host, roots):
    host = host.lower().rstrip(".")
    best = None
    for r in roots:
        r = r.lower().rstrip(".")
        if host == r or host.endswith("." + r):
            if best is None or len(r) > len(best):
                best = r
    return best

# -----------------------------
# Main pipeline
# -----------------------------
def read_lines(p):
    if not os.path.exists(p):
        return []
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip()]

def write_lines(p, items):
    with open(p, "w", encoding="utf-8") as f:
        for x in items:
            f.write(x + "\n")

def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
    return out

def main():
    ap = argparse.ArgumentParser(description="OSINT/Recon Orchestrator (subfinder+dnsx+httpx+gau+waybackurls+katana)")
    ap.add_argument("-dL", "--domains", required=True, help="File containing root domains (one per line)")
    ap.add_argument("-o", "--out", default="out", help="Output directory")
    ap.add_argument("--providers", default="wayback,otx,commoncrawl", help="gau providers list")
    ap.add_argument("--skip-ext", default="png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,mp3,webm,pdf",
                    help="Extensions to skip in gau (-b)")
    ap.add_argument("--katana-depth", type=int, default=3)
    ap.add_argument("--katana-concurrency", type=int, default=10)
    ap.add_argument("--wildcard-verify-http", action="store_true",
                    help="If set, compare wildcard HTTP fingerprint before filtering (slower, fewer false positives)")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # Tools
    tools = ["subfinder", "dnsx", "httpx", "katana", "gau", "waybackurls"]
    require_tools(tools)

    domains = read_lines(args.domains)
    if not domains:
        raise SystemExit("No domains found in domain list file.")

    # 1) Subfinder
    sub_out = os.path.join(args.out, "subfinder.txt")
    sub_cmd = ["subfinder"]
    if has_flag("subfinder", "-dL"):
        sub_cmd += ["-dL", args.domains]
    else:
        # fallback: iterate domains (older/odd builds)
        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
            tf.write("\n".join(domains) + "\n")
            tf.flush()
            sub_cmd += ["-dL", tf.name]
        os.unlink(tf.name)

    if has_flag("subfinder", "-all"):
        sub_cmd += ["-all"]
    if has_flag("subfinder", "-silent"):
        sub_cmd += ["-silent"]
    sub_cmd += ["-o", sub_out]
    print("[*] Running:", " ".join(sub_cmd))
    run_cmd(sub_cmd)

    subs = sorted(set(read_lines(sub_out)))
    write_lines(sub_out, subs)
    print(f"[i] subfinder unique subdomains: {len(subs)}")

    # 2) Wildcard map (random test per root)
    print("[*] Building wildcard map (random-host test per root domain)...")
    wildcard = build_wildcard_map(domains, "dnsx", "httpx", args.out, verify_http=args.wildcard_verify_http)
    print(f"[i] Wildcard signatures collected: {len(wildcard)} / {len(domains)} roots")

    # 3) DNSX enrichment
    dnsx_out = os.path.join(args.out, "dnsx.jsonl")
    dns_cmd = ["dnsx"]
    if has_flag("dnsx", "-l") or has_flag("dnsx", "-list"):
        dns_cmd += ["-l", sub_out]
    else:
        raise SystemExit("dnsx does not appear to support -l/-list (unexpected).")

    dnsx_json_flag = require_flag("dnsx", ["-json", "-j", "-jsonl"], "JSON output parsing")
    for f in ("-a", "-aaaa", "-cname", "-ns"):
        if has_flag("dnsx", f):
            dns_cmd += [f]
    dns_cmd += [dnsx_json_flag]
    dns_cmd += ["-o", dnsx_out]
    if has_flag("dnsx", "-silent"):
        dns_cmd += ["-silent"]

    print("[*] Running:", " ".join(dns_cmd))
    run_cmd(dns_cmd)

    dns_rows = read_jsonl(dnsx_out)
    print(f"[i] dnsx JSON rows: {len(dns_rows)}")
    if len(dns_rows) == 0:
        print("[!] dnsx produced zero JSON rows. Check resolvers/connectivity or ensure dnsx supports the chosen JSON flag.")

    # 4) Wildcard filtering based on A/AAAA set (+ optional HTTP fingerprint)
    print("[*] Filtering wildcard DNS responses...")
    keep_hosts = []
    wildcard_hits = set()

    # Prepare httpx single flags for fingerprint compare
    httpx_fp_flags = []
    httpx_fp_json = require_flag("httpx", ["-json", "-j"], "HTTP fingerprint parsing")
    httpx_fp_flags.append(httpx_fp_json)
    for f in ("-sc", "-cl", "-title", "-hash", "-silent"):
        if has_flag("httpx", f):
            if f == "-hash":
                httpx_fp_flags += ["-hash", "md5"]
            else:
                httpx_fp_flags += [f]

    for row in dns_rows:
        host = (row.get("host") or row.get("input") or "").strip().lower().rstrip(".")
        if not host:
            continue
        root = root_match(host, domains)
        if not root or root not in wildcard:
            keep_hosts.append(host)
            continue

        ips = parse_dnsx_ips(row)
        wips = set(wildcard[root].get("ips", []))

        # Heuristic: if resolved IP set equals wildcard IP set (or is subset), consider wildcard-suspect
        suspect = bool(ips) and bool(wips) and ips.issubset(wips)

        if suspect and args.wildcard_verify_http and "http_fp" in wildcard[root]:
            hj = httpx_single("httpx", host, httpx_fp_flags)
            if hj:
                if parse_httpx_fp(hj) == tuple(wildcard[root]["http_fp"]):
                    wildcard_hits.add(host)
                    continue  # filtered out
                else:
                    keep_hosts.append(host)
                    continue
            # if cannot probe, keep by default (safer)
            keep_hosts.append(host)
            continue

        if suspect and not args.wildcard_verify_http:
            wildcard_hits.add(host)
            continue

        keep_hosts.append(host)

    keep_hosts = sorted(set(keep_hosts))
    keep_hosts_path = os.path.join(args.out, "hosts_filtered.txt")
    write_lines(keep_hosts_path, keep_hosts)
    print(f"[i] wildcard filtering -> kept: {len(keep_hosts)}, filtered: {len(wildcard_hits)}")

    with open(os.path.join(args.out, "wildcard_filtered_hosts.txt"), "w", encoding="utf-8") as f:
        for h in sorted(wildcard_hits):
            f.write(h + "\n")

    # 5) HTTPX enrichment
    httpx_out = os.path.join(args.out, "httpx.jsonl")
    hx_cmd = ["httpx", "-l", keep_hosts_path]

    # probes/enrichment (only add if supported)
    httpx_json_flag = require_flag("httpx", ["-json", "-j"], "JSON output parsing")
    hx_cmd.append(httpx_json_flag)

    want_flags = [
        "-sc", "-cl", "-title", "-td", "-server", "-ip", "-cname", "-asn", "-cdn",
        "-hash", "-silent"
    ]
    for f in want_flags:
        if has_flag("httpx", f):
            if f == "-hash":
                hx_cmd += ["-hash", "md5"]
            else:
                hx_cmd += [f]

    hx_cmd += ["-o", httpx_out]

    print("[*] Running:", " ".join(hx_cmd))
    run_cmd(hx_cmd)

    httpx_rows = read_jsonl(httpx_out)
    print(f"[i] httpx JSON rows: {len(httpx_rows)}")

    # Build live URL list for katana input
    live_urls = []
    for r in httpx_rows:
        u = r.get("url") or r.get("final_url") or r.get("input")
        nu = normalize_url(u) if u else None
        if nu:
            live_urls.append(nu)

    live_urls = sorted(set(live_urls))
    live_urls_path = os.path.join(args.out, "live_urls.txt")
    write_lines(live_urls_path, live_urls)
    print(f"[i] live URLs for katana: {len(live_urls)}")

    # 6) Archive URLs: gau + waybackurls
    print("[*] Collecting archive URLs (gau + waybackurls)...")
    archive_raw = os.path.join(args.out, "archive_urls_raw.txt")
    raw_urls = []

    # gau
    gau_cmd = ["gau"]
    # providers
    if args.providers:
        gau_cmd += ["-providers", args.providers]
    # include subdomains
    if True:
        gau_cmd += ["-subs"]
    # skip extensions
    if args.skip_ext:
        gau_cmd += ["-b", args.skip_ext]

    # pass domains via stdin
    gau_in = "\n".join(domains) + "\n"
    out, _, _ = run_cmd(gau_cmd, input_text=gau_in, check=False)
    raw_urls += [ln.strip() for ln in out.splitlines() if ln.strip()]

    # waybackurls
    out, _, _ = run_cmd(["waybackurls"], input_text=gau_in, check=False)
    raw_urls += [ln.strip() for ln in out.splitlines() if ln.strip()]

    # write raw
    with open(archive_raw, "w", encoding="utf-8") as f:
        for u in raw_urls:
            f.write(u + "\n")
    print(f"[i] archive URLs collected (gau+wayback): {len(raw_urls)}")

    # 7) Normalize + bucket archive URLs
    print("[*] Normalizing + bucketing archive URLs...")
    archive_norm_path = os.path.join(args.out, "archive_urls_normalized.txt")
    buckets_path = os.path.join(args.out, "archive_buckets.jsonl")

    norm_urls = []
    for u in raw_urls:
        nu = normalize_url(u)
        if nu:
            norm_urls.append(nu)
    norm_urls = sorted(set(norm_urls))
    write_lines(archive_norm_path, norm_urls)
    print(f"[i] normalized archive URLs: {len(norm_urls)}")

    bucket_map = {}  # bucket -> {"count": int, "params": [...], "samples": [...]}
    for nu in norm_urls:
        bkey, params = bucket_key(nu)
        entry = bucket_map.setdefault(bkey, {"count": 0, "params": params, "samples": []})
        entry["count"] += 1
        if len(entry["samples"]) < 5:
            entry["samples"].append(nu)

    with open(buckets_path, "w", encoding="utf-8") as f:
        for bkey, v in sorted(bucket_map.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
            f.write(json.dumps({"bucket": bkey, **v}, ensure_ascii=False) + "\n")
    print(f"[i] archive buckets: {len(bucket_map)}")

    # 8) Katana crawl (use -list if available, fallback if not)
    katana_out = os.path.join(args.out, "katana.jsonl")
    print("[*] Crawling with katana...")
    k_cmd = ["katana"]
    run_katana = True

    if has_flag("katana", "-list"):
        k_cmd += ["-list", live_urls_path]
    else:
        # Fallback: if -list not available, feed via stdin (best-effort)
        # Many builds support -u/-target, but not always for bulk; so we do stdin piping if needed.
        if has_flag("katana", "-u"):
            # Some builds accept multiple -u occurrences; do minimal fallback with first N
            for u in live_urls[:50]:
                k_cmd += ["-u", u]
        else:
            raise SystemExit("katana does not support -list or -u; cannot proceed.")

    katana_json_flag = first_supported_flag("katana", ["-jsonl", "-json"])
    if katana_json_flag:
        k_cmd.append(katana_json_flag)
    else:
        print("[!] Katana missing JSON output flag (-jsonl/-json); skipping katana step.")
        run_katana = False

    if run_katana and has_flag("katana", "-o"):
        k_cmd += ["-o", katana_out]

    # optional knobs (only if supported)
    if run_katana and has_flag("katana", "-depth"):
        k_cmd += ["-depth", str(args.katana_depth)]
    if run_katana and has_flag("katana", "-concurrency"):
        k_cmd += ["-concurrency", str(args.katana_concurrency)]
    # js crawl flag can be -jc or -js-crawl depending on build; add what exists
    if run_katana and has_flag("katana", "-jc"):
        k_cmd += ["-jc"]
    elif run_katana and has_flag("katana", "-js-crawl"):
        k_cmd += ["-js-crawl"]

    if run_katana and has_flag("katana", "-silent"):
        k_cmd += ["-silent"]

    if run_katana:
        print("[*] Running:", " ".join(k_cmd))
        # If no -list, no stdin support guaranteed; but we only do stdin for gau/wayback
        run_cmd(k_cmd, check=False)
        katana_rows = read_jsonl(katana_out)
    else:
        katana_rows = []
    print(f"[i] katana JSON rows: {len(katana_rows)}")

    # 9) Build indexes for final merge
    dns_by_host = {}
    for r in dns_rows:
        h = (r.get("host") or r.get("input") or "").strip().lower().rstrip(".")
        if h:
            dns_by_host[h] = r

    http_by_url = {}
    http_by_host = {}
    for r in httpx_rows:
        u = r.get("url") or r.get("final_url") or r.get("input")
        nu = normalize_url(u) if u else None
        if nu:
            http_by_url[nu] = r
            h = (urlsplit(nu).hostname or "").lower().rstrip(".")
            if h and h not in http_by_host:
                http_by_host[h] = r

    kat_by_url = {}
    for r in katana_rows:
        u = r.get("url") or r.get("endpoint") or r.get("input")
        nu = normalize_url(u) if u else None
        if not nu:
            continue
        kat_by_url.setdefault(nu, []).append(r)

    # Universe of URLs
    url_universe = set()
    url_universe |= set(live_urls)
    url_universe |= set(norm_urls)
    url_universe |= set(kat_by_url.keys())

    # 10) final.jsonl merge
    final_path = os.path.join(args.out, "final.jsonl")
    print(f"[*] Writing merged dataset: {final_path}")
    with open(final_path, "w", encoding="utf-8") as f:
        for u in sorted(url_universe):
            sp = urlsplit(u)
            host = (sp.hostname or "").lower().rstrip(".")
            bkey, params = bucket_key(u)

            sources = []
            if u in http_by_url or u in live_urls:
                sources.append("httpx")
            if u in kat_by_url:
                sources.append("katana")
            if u in norm_urls:
                sources.append("archive")

            rec = {
                "url": u,
                "host": host,
                "bucket": bkey,
                "param_names": params,
                "sources": sources,
                "dnsx": dns_by_host.get(host),
                "httpx": http_by_url.get(u) or http_by_host.get(host),
                "katana": kat_by_url.get(u, []),
                "wildcard_filtered_host": host in wildcard_hits,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print("[+] Done.")
    print(f"    Outputs in: {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()
