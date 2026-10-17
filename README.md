# 🛡️ SOC Log Analyzer — Blue Team Security Tool

A security log analysis tool designed to help security analysts identify suspicious activities, authentication failures, errors, and potential attacks in system and web server logs.

## ✨ Features

- **Log Analysis:** Analyze security logs to identify noteworthy events.
- **Brute-Force Detection:** Flag repeated failed login attempts.
- **IP Analysis:** Identify IP addresses associated with suspicious activity.
- **Error and Warning Summary:** Summarize errors, warnings, and log statistics.
- **Multiple Log Sources:** Work with supported authentication, application, and web server logs.
- **Security Reporting:** Present findings to support further investigation.
- **Sample Logs:** Test the analyzer using sample security logs.

## 🧰 Technologies

- TypeScript
- React
- Vite
- Bash / Shell scripting
- HTML and CSS

*Technologies and features should reflect the components actually implemented in this repository.*

## 🚀 Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) and npm
- Git (optional, for cloning the repository)

### 1. Clone the Repository

```bash
git clone https://github.com/farahfatima1/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

If your version uses the Gemini API, create a local `.env.local` file and add your API key:

```env
GEMINI_API_KEY=your_api_key_here
```

Never publish your actual API key. Keep `.env.local` out of Git and use `.env.example` to document required variables.

### 4. Run the Application

```bash
npm run dev
```

Open the local URL displayed in your terminal.

## 💻 Bash Log Analyzer

If `log_analyzer.sh` is included, make it executable in a Bash-compatible terminal:

```bash
chmod +x log_analyzer.sh
./log_analyzer.sh --help
```

Use the file and summary options supported by your script to analyze a log file.

## 🔍 Example Use Case

A security analyst reviews authentication logs and notices repeated failed login attempts from the same IP address. The analyzer flags the activity for further investigation.

## ⚠️ Limitations

- A flagged event is not necessarily a confirmed attack.
- Detection accuracy depends on log quality and the implemented detection rules.
- Supported formats depend on the parsers implemented in the project.
- The tool reports suspicious activity; it does not automatically block attackers unless that capability is explicitly implemented.

## 🔐 Responsible Use

Use this project for educational purposes and authorized defensive security monitoring. Do not upload confidential logs, credentials, API keys, or personally identifiable information to a public repository.

## 👩‍💻 Author

**Farah Fatima**

Cybersecurity & Digital Forensics Student

GitHub: [@farahfatima1](https://github.com/farahfatima1)

---

If you find this project useful, consider starring the repository ⭐.
