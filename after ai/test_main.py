import unittest
from main import parse_cves, check_affects_platform


class TestParseCVEs(unittest.TestCase):
    def test_parse_cves_without_platform_filter(self):
        """Test parse_cves without platform filtering (original functionality)."""
        fake_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 7.5}}
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2023-0002",
                        "metrics": {
                            "cvssMetricV30": [
                                {"cvssData": {"baseScore": 5.6}}
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2023-0003",
                        "metrics": {}  # Should be skipped
                    }
                }
            ]
        }

        expected = [
            ("1Password", "CVE-2023-0001", 7.5),
            ("1Password", "CVE-2023-0002", 5.6),
        ]
        self.assertEqual(parse_cves(fake_data), expected)
    
    def test_check_affects_platform(self):
        """Test the platform checking functionality."""
        # Test CVE that affects macOS
        macos_vulnerability = {
            "cve": {
                "id": "CVE-2023-0001",
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
        
        # Test CVE that affects Windows
        windows_vulnerability = {
            "cve": {
                "id": "CVE-2023-0002",
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
        }
        
        self.assertTrue(check_affects_platform(macos_vulnerability, "macos"))
        self.assertFalse(check_affects_platform(macos_vulnerability, "windows"))
        self.assertTrue(check_affects_platform(windows_vulnerability, "windows"))
        self.assertFalse(check_affects_platform(windows_vulnerability, "macos"))
    
    def test_parse_cves_with_macos_filter(self):
        """Test parse_cves with macOS platform filtering."""
        fake_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
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
                        "id": "CVE-2023-0002",
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
                        "id": "CVE-2023-0003",
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 8.1}}
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
                }
            ]
        }

        # Without platform filter - should return all CVEs with scores
        expected_all = [
            ("1Password", "CVE-2023-0001", 7.5),
            ("1Password", "CVE-2023-0002", 5.6),
            ("1Password", "CVE-2023-0003", 8.1),
        ]
        self.assertEqual(parse_cves(fake_data), expected_all)
        
        # With macOS filter - should only return macOS CVEs
        expected_macos = [
            ("1Password", "CVE-2023-0001", 7.5),
            ("1Password", "CVE-2023-0003", 8.1),
        ]
        self.assertEqual(parse_cves(fake_data, platform_filter="macos"), expected_macos)
        
        # With Windows filter - should only return Windows CVEs
        expected_windows = [
            ("1Password", "CVE-2023-0002", 5.6),
        ]
        self.assertEqual(parse_cves(fake_data, platform_filter="windows"), expected_windows)


if __name__ == "__main__":
    unittest.main()
