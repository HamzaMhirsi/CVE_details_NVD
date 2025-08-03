import urllib.request
import json
import csv
import sys
import argparse


NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def check_affects_platform(vulnerability, platform):
    """Check if a CVE affects a specific platform by looking in configurations."""
    configurations = vulnerability["cve"].get("configurations", [])
    
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe_match in cpe_matches:
                criteria = cpe_match.get("criteria", "")
                if platform.lower() in criteria.lower():
                    return True
    return False


def fetch_cves(keyword="1Password"):
    """Fetch CVEs from NVD API for a given keyword."""
    url = f"{NVD_API_BASE_URL}?keywordSearch={keyword}"
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"Failed to fetch CVEs: HTTP {response.status}")
        return json.load(response)


def parse_cves(data, app_name="1Password", platform_filter=None):
    """Parse CVE data and extract relevant information."""
    cve_entries = []
    for item in data.get("vulnerabilities", []):
        cve_id = item["cve"]["id"]
        
        # Apply platform filter if specified
        if platform_filter and not check_affects_platform(item, platform_filter):
            continue
        
        metrics = item["cve"].get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"]["baseScore"]
                break
        if score is not None:
            cve_entries.append((app_name, cve_id, score))
    return cve_entries


def output_csv(entries):
    writer = csv.writer(sys.stdout)
    writer.writerow(["Application Name", "CVE ID", "CVSS Score"])
    for row in entries:
        writer.writerow(row)


def run_challenge():
    """Run the original 1Password challenge with macOS filtering."""
    print("Running 1Password CVE Challenge (macOS only)...", file=sys.stderr)
    data = fetch_cves("1Password")
    entries = parse_cves(data, "1Password", platform_filter="macos")
    output_csv(entries)


def run_custom_search():
    """Run custom product and platform search."""
    print("\n=== Custom CVE Search ===")
    
    # Get product name
    product = input("Enter product name (e.g., Chrome, Firefox, Docker): ").strip()
    if not product:
        print("Product name cannot be empty!")
        return
    
    # Get platform (optional)
    platform = input("Enter platform (optional - e.g., macOS, Linux, Windows): ").strip()
    
    # Build search keyword
    if platform:
        search_keyword = f"{product} {platform}"
        display_name = f"{product} ({platform})"
    else:
        search_keyword = product
        display_name = product
    
    print(f"\nSearching for CVEs related to '{search_keyword}'...", file=sys.stderr)
    
    try:
        data = fetch_cves(search_keyword)
        # Apply platform filter if platform was specified
        platform_filter = platform.lower() if platform else None
        entries = parse_cves(data, display_name, platform_filter=platform_filter)
        
        if entries:
            print(f"\nFound {len(entries)} CVEs for {display_name}:\n")
            output_csv(entries)
        else:
            print(f"No CVEs found for '{search_keyword}'.")
    except Exception as e:
        print(f"Error fetching CVEs: {e}", file=sys.stderr)


def main():
    """Main function with interactive mode selection."""
    parser = argparse.ArgumentParser(description="CVE Fetcher Tool")
    parser.add_argument("--challenge", action="store_true", 
                       help="Run the 1Password challenge directly")
    parser.add_argument("--custom", action="store_true",
                       help="Run custom product/platform search")
    
    args = parser.parse_args()
    
    # If command line arguments are provided, use them
    if args.challenge:
        run_challenge()
        return
    elif args.custom:
        run_custom_search()
        return
    
    # Interactive mode
    print("\n=== CVE Fetcher Tool ===")
    print("Choose an option:")
    print("1. Run 1Password Challenge (original)")
    print("2. Custom Product/Platform Search")
    print("3. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == "1":
                run_challenge()
                break
            elif choice == "2":
                run_custom_search()
                break
            elif choice == "3":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except EOFError:
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()
