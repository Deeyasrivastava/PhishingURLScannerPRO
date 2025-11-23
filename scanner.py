# scanner.py
import re
import csv
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "bank", "account",
    "password", "free", "gift", "offer", "prize", "bonus", "confirm",
    "auth", "signin", "reset"
]

COMMON_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bitly.com", "tiny.cc"
}

COMMON_TLDS = [".com", ".in", ".net", ".org", ".edu", ".gov", ".co", ".io"]


def is_ip_address(host):
    return re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) is not None


def is_shortened(host):
    # check host or host with path that looks like a shortener
    host_lower = host.lower()
    for s in COMMON_SHORTENERS:
        if host_lower.endswith(s) or host_lower == s:
            return True
    return False


def punycode_present(host):
    return "xn--" in host.lower()


def subdomain_depth(host):
    # remove port if present
    host_only = host.split(":")[0]
    parts = host_only.split(".")
    # treat IP as depth 0
    if is_ip_address(host_only):
        return 0
    return max(0, len(parts) - 2)  # subdomains beyond domain + tld


def has_suspicious_query(url):
    parsed = urlparse(url)
    qs = parsed.query
    if not qs:
        return False
    # suspicious if very long query or contains keywords
    if len(qs) > 80:
        return True
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in qs.lower():
            return True
    return False


def port_is_unusual(parsed):
    if ":" not in parsed.netloc:
        return False
    try:
        port = int(parsed.netloc.split(":")[1])
    except:
        return False
    return port not in (80, 443)


def score_url(url):
    """
    Returns: dict with fields:
    - score (int)
    - label (str)
    - reasons (list)
    - url_normalized (str)
    """
    original = url.strip()
    if not original:
        return None

    # allow URLs without scheme
    if "://" not in original:
        normalized = "http://" + original
    else:
        normalized = original

    parsed = urlparse(normalized)
    host = parsed.netloc.lower() if parsed.netloc else ""
    path = parsed.path or ""
    score = 0
    reasons = []

    # Rule: missing host or obviously malformed
    if not host:
        reasons.append("Malformed URL or missing host")
        score += 2
        label = "HIGH RISK"
        return {"score": score, "label": label, "reasons": reasons, "url_normalized": normalized}

    # Rule: long URL
    if len(normalized) > 100:
        score += 2
        reasons.append("Very long URL (>100 chars)")
    elif len(normalized) > 75:
        score += 1
        reasons.append("Long URL (>75 chars)")

    # Rule: many digits
    digit_count = sum(c.isdigit() for c in normalized)
    if digit_count > 10:
        score += 2
        reasons.append("Contains many digits")
    elif digit_count > 4:
        score += 1
        reasons.append("Contains several digits")

    # Raw IP
    if is_ip_address(host.split(":")[0]):
        score += 3
        reasons.append("Uses IP address instead of domain (raw IP)")

    # @ symbol presence
    if "@" in normalized:
        score += 2
        reasons.append("Contains '@' in URL (can obfuscate real host)")

    # suspicious keywords in URL
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in normalized.lower():
            score += 1
            reasons.append(f"Suspicious keyword: {kw}")
            break

    # hyphen-heavy domain
    if host.count("-") >= 2:
        score += 1
        reasons.append("Domain has many hyphens")

    # punycode / IDN
    if punycode_present(host):
        score += 1
        reasons.append("Punycode / IDN present (xn--)")

    # subdomain depth
    depth = subdomain_depth(host)
    if depth >= 3:
        score += 2
        reasons.append(f"Many subdomains (depth={depth})")
    elif depth >= 1:
        # small penalty for having suspicious subdomain
        if depth >= 2:
            score += 1
            reasons.append(f"Multiple subdomains (depth={depth})")

    # TLD check
    if not any(host.endswith(tld) for tld in COMMON_TLDS):
        score += 1
        reasons.append("Uncommon or suspicious TLD")

    # HTTP vs HTTPS
    if parsed.scheme.lower() == "http":
        score += 1
        reasons.append("Uses HTTP (not HTTPS)")
    elif parsed.scheme.lower() == "https":
        # small negative (good) — we won't reduce the score, but note it
        reasons.append("Uses HTTPS")

    # shortener
    host_only = host.split(":")[0]
    if is_shortened(host_only):
        score += 2
        reasons.append("URL shortener detected (harder to inspect destination)")

    # query string suspiciousness
    if has_suspicious_query(normalized):
        score += 1
        reasons.append("Suspicious or long query string present")

    # unusual port
    if port_is_unusual(parsed):
        score += 1
        reasons.append("Uses a non-standard port")

    # Final label
    if score >= 6:
        label = "HIGH RISK"
    elif score >= 3:
        label = "MEDIUM RISK"
    else:
        label = "LOW RISK"

    return {"score": score, "label": label, "reasons": reasons, "url_normalized": normalized}


def analyze_single_interactive():
    url = input("Enter URL: ").strip()
    result = score_url(url)
    if not result:
        print("Empty input or invalid URL.\n")
        return
    print("\n---- RESULT ----")
    print("URL:", result["url_normalized"])
    print("Risk:", result["label"], f"(score={result['score']})")
    print("Reasons:")
    for r in result["reasons"]:
        print(" -", r)
    print("----------------\n")


def analyze_file_interactive(export_csv=False):
    filename = input("Enter filename (like urls.txt): ").strip()
    try:
        with open(filename, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("File not found!\n")
        return

    results = []
    counts = {"LOW RISK": 0, "MEDIUM RISK": 0, "HIGH RISK": 0}

    for url in urls:
        r = score_url(url)
        if r is None:
            continue
        results.append({"input": url, **r})
        counts[r["label"]] += 1

        # print summary for each
        print("\nURL:", r["url_normalized"])
        print("Risk:", r["label"], f"(score={r['score']})")
        for reason in r["reasons"]:
            print(" -", reason)
        print("-----------------------")

    # summary
    print("\n=== SUMMARY ===")
    print(f"Total URLs scanned: {len(results)}")
    print("Low risk:", counts["LOW RISK"])
    print("Medium risk:", counts["MEDIUM RISK"])
    print("High risk:", counts["HIGH RISK"])
    print("================\n")

    # optionally export CSV
    if export_csv:
        csv_name = "results.csv"
        try:
            with open(csv_name, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["input_url", "normalized_url", "score", "label", "reasons"])
                for r in results:
                    writer.writerow([r["input"], r["url_normalized"], r["score"], r["label"], "; ".join(r["reasons"])])
            print(f"Results exported to {csv_name}\n")
        except Exception as e:
            print("Failed to write CSV:", e)


def main():
    while True:
        print("\n===== ENHANCED URL PHISHING DETECTION TOOL =====")
        print("1. Analyze single URL")
        print("2. Analyze URLs from file (display results)")
        print("3. Analyze URLs from file and export results to results.csv")
        print("4. Exit")

        choice = input("Choose option (1/2/3/4): ").strip()
        if choice == "1":
            analyze_single_interactive()
        elif choice == "2":
            analyze_file_interactive(export_csv=False)
        elif choice == "3":
            analyze_file_interactive(export_csv=True)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice! Try again.")


if __name__ == "__main__":
    main()
