# LFI & RFI Scanner

## Overview
This tool is designed for penetration testers to scan for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities in web applications. It supports high-level payload detection, custom payload injection, and optional anonymity using the Tor network.

## Features
- Scans for LFI and RFI vulnerabilities
- Supports high-risk advanced payloads
- Allows adding custom payloads (`custom_lfi.txt`, `custom_rfi.txt`)
- Uses multi-threading for faster scanning
- Supports Tor for anonymous scanning
- Logs detected vulnerabilities in `scan_report.txt`

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/amithodkasia/lfi_rfi_scanner.git
   cd lfi_rfi_scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. (Optional) Run Tor for anonymous scanning.

## Usage
Basic usage:
```bash
python LFI_RFI_Scanner.py -u "http://target.com/index.php" -p "file"
```

Enable Tor for anonymous scanning:
```bash
python LFI_RFI_Scanner.py -u "http://target.com/index.php" -p "file" --tor
```

Use multiple threads:
```bash
python LFI_RFI_Scanner.py -u "http://target.com/index.php" -p "file" -t 10
```

Check common endpoints automatically:
```bash
python LFI_RFI_Scanner.py -u "http://target.com/" --check-endpoints
```

## Custom Payloads
To add your own payloads:
1. Create `custom_lfi.txt` and `custom_rfi.txt`.
2. Add one payload per line.
3. The scanner will automatically load them during execution.

## Contributing
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m "Add new feature"`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

## Disclaimer
This tool is for educational and authorized penetration testing purposes only. Unauthorized use against systems without explicit permission is illegal.

## License
MIT License

