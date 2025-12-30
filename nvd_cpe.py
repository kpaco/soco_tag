import requests
from datetime import datetime
import sys

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def fetch_cves_by_cpe(cpe_name, output_file="cves.csv", min_score=None):
    params = {"cpeName": cpe_name, "resultsPerPage": 200}
    response = requests.get(NVD_CVE_API, params=params)
    response.raise_for_status()
    data = response.json()

    cve_list = []
    seen = set()

    for item in data.get("vulnerabilities", []):
        cve_id = item["cve"]["id"]
        metrics = item["cve"].get("metrics", {})

        for version_key in ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30"]:
            if version_key in metrics:
                for metric in metrics[version_key]:
                    if metric.get("source") != "nvd@nist.gov":
                        continue  # skip any non-NVD BaseScore
                    score = metric["cvssData"]["baseScore"]
                    severity = metric["cvssData"]["baseSeverity"]
                    cvss_version = metric["cvssData"]["version"]

                    if min_score is None or (score is not None and score >= min_score):
                        unique_key = (cve_id, cvss_version)
                        if unique_key not in seen:
                            seen.add(unique_key)
                            cve_list.append({
                                "cve_id": cve_id,
                                "score": score,
                                "severity": severity,
                                "cvss_version": cvss_version,
                                "cpe": cpe_name
                            })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        f.write(f"=== CVE Results for {cpe_name} ===\n")
        f.write(f"Generated at: {datetime.now()}\n\n")
        if not cve_list:
            f.write("No CVEs found with CVSS v3.x score >= 7.\n")
        else:
            for cve in cve_list:
                f.write(f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}\t\t|\t\tNVD - {cve['cve_id']}\t\t|\t\t{cve['score']} {cve['severity']}\t\tCVSS_v{cve['cvss_version']}\n")
    print(f"Combined cvss results saved to {output_file}")

def find_cpe(vendor, product, version):
    """Query NVD CPE API to find most probable CPE for vendor/product/version"""
    params = {"keywordSearch": f"{vendor} {product} {version}", "resultsPerPage": 20}
    response = requests.get(NVD_CPE_API, params=params)
    response.raise_for_status()
    data = response.json()

    cpes = [item["cpe"]["cpeName"] for item in data.get("products", [])]
    if not cpes:
        print(f"No CPEs found for {vendor}:{product}:{version}")
        sys.exit(1)

    # heuristic: prefer exact version match if exists
    for cpe in cpes:
        if version in cpe:
            print(f"Selected CPE: {cpe}")
            return cpe

    # fallback: first CPE from the list
    print(f"No exact version match. Taking first candidate: {cpes[0]}")
    return cpes[0]


def main():
    if len(sys.argv) == 2:
        # mode 1: direct cpe string
        cpe_name = sys.argv[1]
    elif len(sys.argv) == 4:
        # mode 2: vendor, product, version
        vendor, product, version = sys.argv[1:4]
        cpe_name = find_cpe(vendor, product, version)
    else:
        print("\nScript usage:\n\n"
              " 1 argument: the exact full CPE-string         -->   python nvd_cpe.py cpe:2.3:a:microsoft:.net_framework:4.6:*:*:*:*:*:*:* \n"
              " or\n"
              " 3 arguemnts: for <vendor> <product> <version> -->   python nvd_cpe.py microsoft .net_framework 4.6")
        sys.exit(1)

    fetch_cves_by_cpe(cpe_name, output_file="cve_result.txt", min_score=7.0)


if __name__ == "__main__":
    main()