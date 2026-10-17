# 🛡️ SOC Log Analyzer — Blue Team Security Tool

A security log analysis tool for identifying suspicious activity, repeated authentication failures, potential brute-force attempts, IP-related events, and server errors. Built for cybersecurity students, SOC analysts, and blue-team learners.

## ✨ Features

- Analyze supported system and server log files.
- Identify repeated failed login attempts.
- Highlight suspicious IP addresses and activity.
- Summarize errors, warnings, and log statistics.
- Test the tool with included sample logs.
- Use the web interface and/or Bash analyzer, depending on the component you want to run.

## 🧰 Technologies

- React, TypeScript, and Vite
- Bash / Shell scripting
- HTML and CSS

## 📋 Requirements

Before starting, install:

1. **Node.js and npm:** https://nodejs.org/  
   Download the recommended LTS version. npm is included with Node.js.
2. **Git (optional):** https://git-scm.com/  
   You can download the project ZIP instead.
3. **A terminal:** PowerShell or Windows Terminal on Windows; Terminal on macOS/Linux.
4. **Bash:** Required to run the shell script. On Windows, use Git Bash or WSL.

## ⬇️ Download the Project

### Option 1: Download ZIP (easiest)

1. Open the project repository: https://github.com/farahfatima1/SOC-Log-Analyzer
2. Click the green **Code** button.
3. Select **Download ZIP**.
4. Extract the downloaded ZIP file.
5. Open the extracted project folder.
6. Open PowerShell or a terminal in that folder.

### Option 2: Clone with Git

Open a terminal and run:

```bash
git clone https://github.com/farahfatima1/SOC-Log-Analyzer.git
cd SOC-Log-Analyzer
```

## 🚀 Run the Web Application

### Step 1: Open the project folder

Make sure your terminal is inside the folder containing `package.json`.

### Step 2: Install dependencies

Run:

```bash
npm install
```

Wait for the installation to finish. You need an internet connection for the initial installation.

### Step 3: Configure environment variables (if required)

Check `.env.example` for the environment variables used by the project.

If the application requires a Gemini API key, create a local `.env.local` file in the project root and add:

```env
GEMINI_API_KEY=your_api_key_here
```

Replace the placeholder with your own key. Obtain one through Google's official AI developer platform: https://aistudio.google.com/

**Security:** Never share your API key or commit `.env.local` to GitHub. Some features may not work until the required environment variables are configured.

### Step 4: Start the application

Run:

```bash
npm run dev
```

### Step 5: Open it in your browser

Look for the local URL printed in the terminal, for example:

```text
http://localhost:3000/
```

Open the URL in your browser. If your terminal displays a different port, use the URL it provides.

Keep the terminal open while using the application. To stop the server, press `Ctrl + C`.

## 🖥️ Run the Bash Log Analyzer

The Bash analyzer is separate from the web application.

1. Open a Bash-compatible terminal in the project folder.
2. Check that the script exists:

```bash
ls
```

3. Make the script executable:

```bash
chmod +x log_analyzer.sh
```

4. Check the supported options:

```bash
./log_analyzer.sh --help
```

If the script does not support `--help`, open `log_analyzer.sh` and follow the usage instructions documented in the script. Use the actual arguments supported by your version to select a log file and analyze it.

On Windows, run these commands in Git Bash or WSL rather than ordinary PowerShell.

## 🧪 Try the Sample Logs

The project includes a `sample_logs/` folder for testing, if present in the downloaded version.

1. Open the application or Bash analyzer.
2. Select or provide a supported sample log file.
3. Run the analysis.
4. Review the findings and compare them with the sample log entries.

Start with sample data before analyzing real logs. Do not upload confidential organizational logs or personal information to a public repository.

## 🛠️ Troubleshooting

**`npm` is not recognized**

Install Node.js from https://nodejs.org/, then close and reopen your terminal. Check:

```bash
node --version
npm --version
```

**`npm install` fails**

Check your internet connection and Node.js installation. Read the full error message before trying again.

**`npm run dev` fails**

Make sure you are in the project directory containing `package.json`. Run `npm install` and then retry.

**The browser cannot open the application**

Check the terminal for the actual local URL and confirm the development server is still running.

**The Bash script will not run**

Use Git Bash or WSL on Windows, confirm the script exists, and check the usage instructions inside `log_analyzer.sh`.

## ⚠️ Limitations

- A suspicious event is not necessarily a confirmed attack.
- Detection quality depends on the available logs and implemented detection rules.
- Supported log formats depend on the actual parsers in the project.
- The tool should not be assumed to block attackers automatically.

## 🔐 Responsible Use

Use this project for educational purposes and authorized defensive security monitoring. Analyze only logs you are permitted to access.

## 👩‍💻 Author

**Farah Fatima**  
Cybersecurity & Digital Forensics Student

GitHub: https://github.com/farahfatima1

---

If you find this project useful, consider giving the repository a ⭐ star!

