# CVE Fetcher Tool

A Python tool to fetch and filter CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD) API, with specific focus on 1Password vulnerabilities affecting macOS.

## 🎯 Project Structure

This repository contains two implementations demonstrating the evolution from simple to advanced Python coding:

### Before AI (`before ai/`)
- **Simple, human-readable code** - Basic Python without complex frameworks
- **Function-based architecture** - Clean, testable functions
- **macOS filtering** - Filters CVEs that specifically affect macOS

### After AI (`after ai/`)
- **Advanced features** - Interactive mode, command-line arguments
- **Multiple search options** - 1Password challenge or custom product/platform search
- **Enhanced functionality** - Platform filtering, error handling, CSV output

## 🚀 Features

### Core Functionality
- Fetches CVE data from NVD API
- Filters vulnerabilities by platform (macOS, Windows, Linux)
- Extracts CVSS scores (v4.0, v3.1, v3.0, v2.0)
- Outputs results in CSV format

### Platform Filtering
- Analyzes CVE configuration data
- Checks CPE (Common Platform Enumeration) criteria
- Filters for specific operating systems

## 📋 Usage

### Before AI (Simple Version)
```bash
cd "before ai"
python3 main_before_ai.py
```

### After AI (Advanced Version)
```bash
cd "after ai"

# Run 1Password challenge (macOS only)
python3 main.py --challenge

# Interactive mode
python3 main.py

# Custom search
python3 main.py --custom
```

## 🧪 Testing

### Before AI Tests
```bash
cd "before ai"
python3 test_main_before_ai.py
```

### After AI Tests
```bash
cd "after ai"
python3 -m unittest test_main.py -v
```

## 📊 Sample Output

```csv
Application Name,CVE ID,CVSS Score
1Password,CVE-2021-41795,6.5
1Password,CVE-2022-29868,5.5
1Password,CVE-2022-32550,4.8
1Password,CVE-2024-42218,4.7
1Password,CVE-2024-42219,7.8
```

## 🔧 Requirements

- Python 3.6+
- Internet connection (for NVD API access)
- No external dependencies (uses only Python standard library)

## 📁 File Structure

```
├── before ai/
│   ├── main_before_ai.py          # Simple CVE fetcher
│   └── test_main_before_ai.py     # Basic tests
├── after ai/
│   ├── main.py                    # Advanced CVE fetcher
│   └── test_main.py               # Comprehensive tests
├── CVE_details_NVD/
│   └── README.md                  # Original project documentation
├── json.json                      # Sample NVD API response
└── README.md                      # This file
```

## 🎓 Learning Objectives

This project demonstrates:
- **API Integration** - Working with REST APIs and JSON data
- **Data Filtering** - Complex nested data structure navigation
- **Testing** - Both simple and unittest-based testing approaches
- **Code Evolution** - From simple scripts to modular, testable code
- **Platform Detection** - Parsing CPE criteria for OS identification

## 🔍 Technical Details

### CVE Data Structure
The tool analyzes CVE data from the NVD API, specifically looking at:
- `vulnerabilities[].cve.configurations[].nodes[].cpeMatch[].criteria`
- `vulnerabilities[].cve.metrics.cvssMetricV*[].cvssData.baseScore`

### Platform Detection Logic
```python
def check_affects_platform(vulnerability, platform):
    # Searches for platform name in CPE criteria strings
    # Example: "cpe:2.3:a:1password:1password:*:*:*:*:*:macos:*:*"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📜 License

This project is for educational purposes. Please respect the NVD API usage guidelines.

## 🔗 References

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [Common Platform Enumeration (CPE)](https://cpe.mitre.org/)
- [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/)
