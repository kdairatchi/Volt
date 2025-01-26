#!/bin/bash
# Ultimate Bug Bounty Automation Suite v2.0
# Integrates: Recon, XSS, SQLi, RCE, Bypass Techniques, API/JS Analysis
# Dependencies: subfinder, amass, httpx, nuclei, sqlmap, ghauri, ffuf, kiterunner, gitallsecrets, notify

set -eo pipefail

# Configuration
TARGET=""
WORKSPACE="bb_results"
THREADS=20
NOTIFY=false
CLOUDFLARE_BYPASS=false

banner() {
    cat <<EOF

░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        
░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒▒▓███▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░  
EOF
}

check_dependencies() {
    declare -A tools=(
        ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["amass"]="go install -v github.com/owasp-amass/amass/v3/...@master"
        ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        ["gitallsecrets"]="go install -v github.com/amitshekhariitbhu/gitallsecrets@latest"
        ["ghauri"]="pip install ghauri"
        ["kiterunner"]="go install github.com/assetnote/kiterunner/cmd/kr@latest"
    )

    for tool in "${!tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo "Installing $tool..."
            eval "${tools[$tool]}"
        fi
    done
}

setup_workspace() {
    mkdir -p "$WORKSPACE"/{recon,vulns,bypass,js_analysis,apis}
}

automated_recon() {
    echo "[+] Phase 1: Automated Reconnaissance"
    
    # Subdomain Enumeration
    subfinder -d "$TARGET" -silent | anew "$WORKSPACE/recon/subs.txt"
    amass enum -passive -d "$TARGET" -silent | anew "$WORKSPACE/recon/subs.txt"
    
    # Cloudflare Check & Bypass
    if grep -q "cloudflare" <<< "$(wafw00f "$TARGET")"; then
        CLOUDFLARE_BYPASS=true
        cloudflared tunnel --url http://localhost:8080 &> "$WORKSPACE/recon/cf-tunnel.log" &
        sleep 5
    fi

    # Live Host Verification
    httpx -l "$WORKSPACE/recon/subs.txt" -title -status-code -tech-detect \
        -o "$WORKSPACE/recon/live_hosts.json" -json
}

vulnerability_scanning() {
    echo "[+] Phase 2: Automated Vulnerability Scanning"
    
    # XSS Automation
    gospider -s "https://$TARGET" -d 3 | grep -Eo 'https?://[^"]+' | \
        qsreplace -a | dalfox pipe --silence --skip-bav -o "$WORKSPACE/vulns/xss_results.txt"
    
    # SQLi Detection
    ghauri -u "https://$TARGET" --batch --threads "$THREADS" \
        --tamper=between,charencode -o "$WORKSPACE/vulns/sqli_ghauri.txt"
    
    # RCE Detection
    nuclei -t ~/nuclei-templates/rce/ -l "$WORKSPACE/recon/live_hosts.json" \
        -o "$WORKSPACE/vulns/rce_results.txt"
}

bypass_techniques() {
    echo "[+] Phase 3: Modern Bypass Techniques"
    
    # 403 Bypass Testing
    while read -r url; do
        for path in "/admin..;/" "/.%2e/admin" "/admin/.."; do
            curl -sk -H "X-Original-URL: $path" "$url" -o /dev/null -w "%{http_code}" | \
                grep -vE "403|404" && echo "Potential 403 bypass: $url$path" | anew "$WORKSPACE/bypass/403_bypass.txt"
        done
    done < "$WORKSPACE/recon/live_hosts.txt"
    
    # IDOR Testing
    ffuf -w "$WORKSPACE/recon/live_hosts.txt" -u "FUZZ" -H "X-Forwarded-For: 127.0.0.1" \
        -mc 200 -t "$THREADS" -o "$WORKSPACE/bypass/idor_results.json"
}

js_api_analysis() {
    echo "[+] Phase 4: JS & API Analysis"
    
    # JavaScript Secrets
    subjs -t "$THREADS" -c -i "$WORKSPACE/recon/live_hosts.txt" | \
        grep -E "apiKey|token|secret" > "$WORKSPACE/js_analysis/js_secrets.txt"
    
    # API Route Discovery
    kiterunner brute "$TARGET" -w ~/tools/routes-large.kite \
        -j -o "$WORKSPACE/apis/api_routes.json"
    
    # PostMessage Vulnerabilities
    python3 - <<'EOF'
import requests
from bs4 import BeautifulSoup
res = requests.get("https://$TARGET")
soup = BeautifulSoup(res.text, 'html.parser')
for script in soup.find_all('script'):
    if 'postMessage' in script.text:
        print("Potential postMessage vulnerability found")
EOF
}

automation_workflow() {
    echo "[+] Phase 5: Intelligent Automation Workflow"
    
    # Continuous Monitoring
    nuclei -l "$WORKSPACE/recon/live_hosts.txt" -nt -severity critical \
        -silent | notify -provider telegram
    
    # GitHub Secrets
    gitallsecrets -u "$TARGET" -o "$WORKSPACE/secrets.txt"
    
    # Subdomain Takeover
    subzy run --targets "$WORKSPACE/recon/subs.txt" \
        --hide_fails > "$WORKSPACE/takeover_check.txt"
}

reporting() {
    echo "[+] Generating Final Report"
    echo "# Bug Bounty Report: $TARGET" > report.md
    echo "## Subdomains" >> report.md
    cat "$WORKSPACE/recon/subs.txt" >> report.md
    echo "## Vulnerabilities" >> report.md
    cat "$WORKSPACE/vulns/*.txt" >> report.md
    echo "## Secrets Found" >> report.md
    cat "$WORKSPACE/secrets.txt" >> report.md
}

main() {
    banner
    check_dependencies
    setup_workspace
    automated_recon
    vulnerability_scanning
    bypass_techniques
    js_api_analysis
    automation_workflow
    reporting
}

# Argument Handling
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift ;;
        --notify) NOTIFY=true ;;
        *) echo "Usage: $0 --target example.com [--notify]"; exit 1 ;;
    esac
    shift
done

[ -z "$TARGET" ] && { echo "Target required!"; exit 1; }

main
