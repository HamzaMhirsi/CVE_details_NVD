from main_before_ai import check_affects_platform, get_cvss_score, filter_cves_for_platform

print("Testing CVE filtering functions...")

# Test data that looks like real NVD data
test_data = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2025-gigs1",
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 7.5}}
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:1password:1password:*:*:*:*:*:macos:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-gigs2",
                "metrics": {
                    "cvssMetricV30": [
                        {"cvssData": {"baseScore": 5.6}}
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:1password:1password:*:*:*:*:*:windows:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2025-gigs3",
                "metrics": {},  # No metrics - should be skipped
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:a:1password:1password:*:*:*:*:*:macos:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    ]
}

# Test individual functions
print("Testing individual functions")
vulnerabilities = test_data["vulnerabilities"]

# Test CVE 1
vulnerability1 = vulnerabilities[0]
cve_id1 = vulnerability1["cve"]["id"]
affects_macos1 = check_affects_platform(vulnerability1, "macos")
score1 = get_cvss_score(vulnerability1)
print(f"CVE 1 ({cve_id1}): affects macOS = {affects_macos1}")
print(f"CVE 1 ({cve_id1}): CVSS score = {score1}")
print()

# Test CVE 2
vulnerability2 = vulnerabilities[1]
cve_id2 = vulnerability2["cve"]["id"]
affects_macos2 = check_affects_platform(vulnerability2, "macos")
score2 = get_cvss_score(vulnerability2)
print(f"CVE 2 ({cve_id2}): affects macOS = {affects_macos2}")
print(f"CVE 2 ({cve_id2}): CVSS score = {score2}")
print()

# Test CVE 3
vulnerability3 = vulnerabilities[2]
cve_id3 = vulnerability3["cve"]["id"]
affects_macos3 = check_affects_platform(vulnerability3, "macos")
score3 = get_cvss_score(vulnerability3)
print(f"CVE 3 ({cve_id3}): affects macOS = {affects_macos3}")
print(f"CVE 3 ({cve_id3}): CVSS score = {score3}")
print()

# Test the main filtering function
print("Testing main filtering function")
filtered_cves = filter_cves_for_platform(test_data, "macos")

print(f"Filtered CVEs: {filtered_cves}")
print()

# Test results
print("=== TEST RESULTS ===")
print(f"Expected: 1 CVE (CVE-2025-gigs1 with score 7.5)")
print(f"Found: {len(filtered_cves)} CVE(s)")

if len(filtered_cves) == 1 and filtered_cves[0] == ("CVE-2025-gigs1", 7.5):
    print("TEST PASSED! The filtering logic works correctly.")
else:
    print("TEST FAILED! Expected different results.")

print("Test complete!")
