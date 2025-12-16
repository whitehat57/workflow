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
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# -------------------------
# Utilities
# -------------------------

def which_or_die(bin_name: str) -> str:
    p = shutil.which(bin_name)
    if not p:
        raise SystemExit(f"[!] Missing dependency: {bin_name} (not found in PATH)")
    return p

def run_cmd(cmd: List[str], *, stdin_bytes: Optional[bytes] = None,
            stdout_path: Optional[Path] = None, cwd: Optional[Path] = None,
            env: Optional[Dict[str, str]] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Runs a command. If stdout_path is provided, stdout is written to file (and also captured minimally).
    Returns (returncode, stdout_text, stderr_text).
    """
    stdout_target = subprocess.PIPE
    if stdout_path:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(stdout_path, "wb")
        stdout_target = f
    else:
        f = None

    try:
        p = subprocess.run(
            cmd,
            input=stdin_bytes,
            stdout=stdout_target,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env,
            timeout=timeout,
        )
        out = ""
        if stdout_path:
            out = ""  # already written to file
        else:
            out = (p.stdout or b"").decode("utf-8", errors="replace")
        err = (p.stderr or b"").decode("utf-8", errors="replace")
        return p.returncode, out, err
    finally:
        if f:
            f.close()

def help_text(tool: str) -> str:
    # Prefer "-h" for ProjectDiscovery tools (as per docs), fallback to "--help"
    rc, out, err = run_cmd([tool, "-h"])
    text = out + "\n" + err
    if rc != 0 and not text.strip():
        rc, out, err = run_cmd([tool, "--help"])
        text = out + "\n" + err
    return text

def version_text(tool: str) -> str:
    # Many PD tools support "-version" (seen in usage pages); fallback to "--version"
    for args in (["-version"], ["--version"], ["version"]):
        rc, out, err = run_cmd([tool] + args)
        text = (out + "\n" + err).strip()
        if text:
            return text.splitlines()[0][:200]
    return "unknown"

def supports_flag(tool_help: str, flag: str) -> bool:
    # conservative: match whole token-like occurrences
    return re.search(rf"(^|\s){re.escape(flag)}(\s|,|$)", tool_help) is not None

def read_lines(p: Path) -> List[str]:
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]

def write_lines(p: Path, lines: Iterable[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln.rstrip() + "\n")

def iter_jsonl(path: Path) -> Iterable[dict]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # keep pipeline resilient
                continue

# -------------------------
# URL normalization + bucketing
# -------------------------

TRACKING_PREFIXES = ("utm_",)
TRACKING_KEYS = {
    "gclid", "fbclid", "msclkid", "yclid", "igshid",
    "mc_cid", "mc_eid", "ref", "ref_src", "spm"
}

def normalize_url(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw:
        return None

    # Wayback outputs often already have scheme; keep only http/https
    try:
        parts = urlsplit(raw)
    except Exception:
        return None

    if parts.scheme not in ("http", "https"):
        return None

    scheme = parts.scheme.lower()
    netloc = parts.netloc.strip()

    # Lowercase hostname portion
    if "@" in netloc:
        # avoid credentials in URLs for safety/consistency
        return None

    host = netloc
    port = ""
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)

    host = host.lower().strip(".")
    if not host:
        return None

    # Drop default ports
    if port:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            port = ""
    netloc_norm = host if not port else f"{host}:{port}"

    # Normalize path
    path = parts.path or "/"
    # collapse multiple slashes (but keep a leading slash)
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path

    # Normalize query: remove tracking params, sort
    qsl = parse_qsl(parts.query, keep_blank_values=True)
    cleaned = []
    for k, v in qsl:
        kk = (k or "").strip()
        if not kk:
            continue
        kl = kk.lower()
        if kl in TRACKING_KEYS:
            continue
        if any(kl.startswith(pfx) for pfx in TRACKING_PREFIXES):
            continue
        cleaned.append((kk, v))

    cleaned.sort(key=lambda kv: (kv[0].lower(), kv[1]))

    query = urlencode(cleaned, doseq=True)

    # Drop fragments always
    frag = ""

    return urlunsplit((scheme, netloc_norm, path, query, frag))

def bucket_key(norm_url: str) -> str:
    parts = urlsplit(norm_url)
    host = parts.netloc.lower()
    path = parts.path or "/"
    qsl = parse_qsl(parts.query, keep_blank_values=True)
    keys = sorted({k for k, _ in qsl if k})
    ksig = ",".join(keys)
    return f"{host}{path}?{ksig}" if ksig else f"{host}{path}"

# -------------------------
# Wildcard detection (DNS-only heuristic)
# -------------------------

def rand_label(n: int = 14) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

@dataclass
class WildcardSignature:
    a: Set[str]
    aaaa: Set[str]
    cname: Set[str]

def extract_dns_sig(dnsx_obj: dict) -> WildcardSignature:
    a = set()
    aaaa = set()
    cname = set()

    # dnsx json fields can vary; try common keys
    for k in ("a", "A"):
        if k in dnsx_obj and isinstance(dnsx_obj[k], list):
            a.update([str(x).strip() for x in dnsx_obj[k] if str(x).strip()])
        elif k in dnsx_obj and isinstance(dnsx_obj[k], str):
            a.add(dnsx_obj[k].strip())

    for k in ("aaaa", "AAAA"):
        if k in dnsx_obj and isinstance(dnsx_obj[k], list):
            aaaa.update([str(x).strip() for x in dnsx_obj[k] if str(x).strip()])
        elif k in dnsx_obj and isinstance(dnsx_obj[k], str):
            aaaa.add(dnsx_obj[k].strip())

    for k in ("cname", "CNAME"):
        if k in dnsx_obj and isinstance(dnsx_obj[k], list):
            cname.update([str(x).strip().lower() for x in dnsx_obj[k] if str(x).strip()])
        elif k in dnsx_obj and isinstance(dnsx_obj[k], str):
            cname.add(dnsx_obj[k].strip().lower())

    return WildcardSignature(a=a, aaaa=aaaa, cname=cname)

def dns_sig_equals(s1: WildcardSignature, s2: WildcardSignature) -> bool:
    return s1.a == s2.a and s1.aaaa == s2.aaaa and s1.cname == s2.cname

# -------------------------
# Tool runners
# -------------------------

def run_subfinder(domain: str, outdir: Path, threads: int = 40) -> Path:
    out_subs = outdir / "subdomains.txt"
    cmd = ["subfinder", "-d", domain, "-silent", "-o", str(out_subs)]
    # threads flag name in subfinder is "-t" (verify via capability detection if needed)
    # keep optional for safety
    h = help_text("subfinder")
    if supports_flag(h, "-t"):
        cmd += ["-t", str(threads)]
    rc, _, err = run_cmd(cmd)
    if rc != 0:
        raise SystemExit(f"[!] subfinder failed: {err.strip()[:400]}")
    return out_subs

def run_dnsx(subdomains_file: Path, outdir: Path, resolvers: Optional[Path], threads: int = 200) -> Path:
    out_jsonl = outdir / "dnsx.jsonl"
    cmd = ["dnsx", "-l", str(subdomains_file), "-a", "-aaaa", "-cname", "-ns", "-json", "-o", str(out_jsonl), "-silent"]
    if resolvers:
        cmd += ["-r", str(resolvers)]
    h = help_text("dnsx")
    if supports_flag(h, "-t"):
        cmd += ["-t", str(threads)]
    rc, _, err = run_cmd(cmd)
    if rc != 0:
        raise SystemExit(f"[!] dnsx failed: {err.strip()[:400]}")
    return out_jsonl

def detect_wildcard(domain: str, outdir: Path, resolvers: Optional[Path], tests: int = 3) -> Optional[WildcardSignature]:
    """
    Random host tests:
    - If >=2 tests resolve to identical (A/AAAA/CNAME) signatures, treat as wildcard signature.
    """
    sigs: List[WildcardSignature] = []
    tmp = outdir / "wildcard_tests"
    tmp.mkdir(parents=True, exist_ok=True)

    for i in range(tests):
        host = f"{rand_label()}.{domain}"
        f_in = tmp / f"wild_{i}.txt"
        write_lines(f_in, [host])

        f_out = tmp / f"wild_{i}.jsonl"
        cmd = ["dnsx", "-l", str(f_in), "-a", "-aaaa", "-cname", "-json", "-o", str(f_out), "-silent"]
        if resolvers:
            cmd += ["-r", str(resolvers)]
        rc, _, _ = run_cmd(cmd)
        if rc != 0:
            continue

        objs = list(iter_jsonl(f_out))
        if not objs:
            continue

        sig = extract_dns_sig(objs[0])
        if sig.a or sig.aaaa or sig.cname:
            sigs.append(sig)

    if len(sigs) < 2:
        return None

    # find majority identical signature
    for i in range(len(sigs)):
        same = sum(1 for j in range(len(sigs)) if dns_sig_equals(sigs[i], sigs[j]))
        if same >= 2:
            return sigs[i]

    return None

def filter_wildcard_hosts(dnsx_jsonl: Path, wildcard_sig: WildcardSignature, outdir: Path) -> Tuple[Path, Path]:
    """
    Returns (kept_hosts.txt, wildcard_hosts.txt).
    """
    kept = []
    wild = []

    for obj in iter_jsonl(dnsx_jsonl):
        host = obj.get("host") or obj.get("hostname") or obj.get("input")
        if not host:
            continue
        sig = extract_dns_sig(obj)
        if dns_sig_equals(sig, wildcard_sig):
            wild.append(host)
        else:
            kept.append(host)

    kept_file = outdir / "hosts.filtered.txt"
    wild_file = outdir / "hosts.wildcard.txt"
    write_lines(kept_file, sorted(set(kept)))
    write_lines(wild_file, sorted(set(wild)))
    return kept_file, wild_file

def run_httpx(hosts_file: Path):
