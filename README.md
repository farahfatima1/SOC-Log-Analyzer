# SOC Log Analyzer | Blue Team Security Tool

A security log analysis tool designed to help Blue Team and SOC analysts identify suspicious activity, authentication failures, system errors, and potential attacks from log files.

## Features

- Analyze security log files.
- Detect repeated login failures and potential brute-force attempts.
- Identify suspicious IP addresses.
- Summarize log entries, errors, and warnings.
- Generate readable analysis reports.
- Support sample logs for testing.

## Technologies

- Bash / Shell scripting
- Security log analysis
- Blue Team and SOC fundamentals

## Getting Started

### Requirements
- Bash terminal
- A compatible security log file

### Run the Script

```bash
chmod +x log_analyzer.sh
./log_analyzer.sh -f /path/to/your/logfile.log --summary
```

For available options, run:

```bash
./log_analyzer.sh --help
```

## Sample Use Case

The analyzer can identify repeated failed login attempts from an IP address and flag them for further investigation.

## Limitations

This tool reports suspicious activity for investigation. It does not automatically block IP addresses or guarantee that every detected event is malicious. Supported file formats depend on the implemented parser.

## Author

**Farah Fatima**

Cybersecurity & Digital Forensics Student

GitHub: [@farahfatima1](https://github.com/farahfatima1)

---

*For educational and defensive cybersecurity purposes.*
