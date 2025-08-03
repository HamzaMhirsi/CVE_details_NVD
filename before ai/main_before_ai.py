import urllib.request
import json

Tool_name = "1Password"
platform = "macos"

# pull data  
# get data based on platform {you can change here your keyword based on the platform you want to investogate}
def fetch_cve_data(Tool_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={Tool_name}"
    response = urllib.request.urlopen(url)
    return json.load(response)

# function to pull cvss score baseed on metric version
def get_cvss_score(vulnerability):
    metrics = vulnerability["cve"].get("metrics", {})
    if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
        return metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    else:
        return None

# function to look for macos match in criteria
def check_affects_platform(vulnerability, platform):
    configurations = vulnerability["cve"].get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe_match in cpe_matches:
                criteria = cpe_match.get("criteria", "")
                if platform in criteria.lower():
                    return True
    return False

# function to pull all together cveid and score
def filter_cves_for_platform(data, platform):
    vulnerabilities = data["vulnerabilities"]
    filtered_cves = []
    for vulnerability in vulnerabilities:
        cve_id = vulnerability["cve"]["id"]

        # Check if this CVE affects the specified platform
        if not check_affects_platform(vulnerability, platform):
            continue
        
        # Get the CVSS score
        score = get_cvss_score(vulnerability)
        
        # Only include CVEs with valid scores
        if score is not None:
            filtered_cves.append((cve_id, score))
    
    return filtered_cves

# main function
def main():
    # Fetch data from NVD API
    data = fetch_cve_data(Tool_name)
    
    # Filter for macOS CVEs
    filtered_cves = filter_cves_for_platform(data, platform)
    
    # Print results
    print("\nApplication Name,CVE ID,CVSS Score")
    for cve_id, score in filtered_cves:
        print(f"{Tool_name},{cve_id},{score}")
    
    print("Challenge complete!")


if __name__ == "__main__":
    main()
