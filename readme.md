# 🛡️ SQLi-Scout

<a href="https://ibb.co/ymTHSVCM"><img src="https://i.ibb.co/NghcS7qk/image.png" alt="image" border="0"></a><br /><a target='_blank' href='https://freeonlinedice.com/'>roll a 20 sided die</a><br />

A cross-platform SQL injection testing tool designed for security professionals and penetration testers. SQLi-Scout helps identify SQL injection vulnerabilities in web applications on Windows, macOS (including Apple Silicon), and Linux systems.

## ⚠️ Disclaimer

**This tool is for ethical security testing only. Use responsibly and with permission.**

Unauthorized testing of systems you don't own or have explicit permission to test is illegal in most jurisdictions and may result in legal consequences. Always obtain proper authorization before scanning any systems.

## ✨ Features

- 🔍 Detects SQL injection vulnerabilities in web applications
- 🔄 Tests both GET and POST parameters
- 💻 Cross-platform compatibility (Windows, macOS, Linux)
- 🍎 Optimized for Apple Silicon (ARM) processors
- 🔎 Automatic form detection and parameter extraction
- 🛠️ Customizable SQL injection payloads
- 🚨 Error-based and time-based vulnerability detection
- ⚡ Multi-threaded scanning for improved performance
- 📊 Detailed scan reports
- 📈 Progress tracking during scans
- 🎨 Graceful color handling for different terminals

## 📥 Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Setup

1. Clone the repository or download the source code:

```bash
git clone https://github.com/anubhavmohandas/sqli-scout.git
cd sqli-scout
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

> 💡 On some systems, you might need to use `pip3` instead of `pip`.

## 🚀 Usage

### Basic Usage

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1"
```

### Command Line Options

```
usage: sqli-scout.py [-h] -u URL [-p PARAMETER] [-c COOKIE] [-d DATA] [-t THREADS] [--form]
                    [--timeout TIMEOUT] [-v] [--payload-file PAYLOAD_FILE]
                    [--error-pattern-file ERROR_PATTERN_FILE] [-o OUTPUT] [--no-color]

SQLi-Scout: A Cross-Platform SQL Injection Testing Tool

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to test
  -p PARAMETER, --parameter PARAMETER
                        Specific parameter to test
  -c COOKIE, --cookie COOKIE
                        Cookies to include with requests
  -d DATA, --data DATA  POST data to send
  -t THREADS, --threads THREADS
                        Number of concurrent threads
  --form                Test form parameters
  --timeout TIMEOUT     Request timeout in seconds
  -v, --verbose         Enable verbose output
  --payload-file PAYLOAD_FILE
                        Path to file containing custom SQL injection payloads
  --error-pattern-file ERROR_PATTERN_FILE
                        Path to file containing custom error patterns
  -o OUTPUT, --output OUTPUT
                        Save results to output file
  --no-color            Disable colored output
```

### 📋 Examples

#### Test a specific URL parameter

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" -p id
```

#### Test a form using POST

```bash
python sqli-scout.py -u "http://example.com/login.php" --form -d "username=test&password=test"
```

#### Use custom payloads

```bash
python sqli-scout.py -u "http://example.com/search.php?q=test" --payload-file custom_payloads.txt
```

#### Save scan results to a file

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" -o scan_results.txt
```

#### Enable verbose output

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" -v
```

#### Scan with custom cookies

```bash
python sqli-scout.py -u "http://example.com/member.php" -c "PHPSESSID=1234abcd; loggedin=true"
```

## 💻 Platform-Specific Notes

### Windows

- 🪟 Windows Terminal or PowerShell is recommended for proper color support
- 🔤 If you encounter encoding issues, use the `--no-color` option

### macOS

- 🍎 For Apple Silicon (M1/M2/M3) Macs, the tool will automatically optimize thread count
- 📟 Terminal.app and iTerm2 are fully supported

### Linux

- 🐧 Most terminal emulators are supported with color
- 🐍 Use `python3` explicitly if both Python 2 and 3 are installed

## 🔧 Custom Payload Files

You can create custom payload files for testing. Each payload should be on a separate line:

```
'
"
1' OR '1'='1
' OR 1=1 --
```

> 📝 Lines starting with `#` are treated as comments and ignored.

## 🔍 Error Pattern Files

Similarly, you can create custom error pattern files to match specific database errors:

```
SQL syntax.*?error
ORA-[0-9]{5}
Unclosed quotation mark
```

> 🔄 Each pattern is treated as a regular expression.

## ❓ Troubleshooting

### Color Issues

If you experience issues with colored output:

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" --no-color
```

### Connection Errors

If you're experiencing connection issues:

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" --timeout 30
```

### Performance Issues

For slower systems, reduce the number of threads:

```bash
python sqli-scout.py -u "http://example.com/page.php?id=1" -t 2
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. 🍴 Fork the repository
2. 🌿 Create your feature branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit your changes (`git commit -m 'Add some amazing feature'`)
4. 📤 Push to the branch (`git push origin feature/amazing-feature`)
5. 🔄 Open a Pull Request

---
Created with ❤️ by Anubhav Mohandas
