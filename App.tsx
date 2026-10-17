import React, { useState } from 'react';
import {
  ShieldAlert,
  Upload,
  FileText,
  Play,
  Download,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Terminal,
  Layers,
  Database
} from 'lucide-react';
import { analyzeLogContent, generateTextReport, SocAnalysisResult } from './utils/socLogAnalyzer';
import { LOG_ANALYZER_SCRIPT_SOURCE } from './utils/bashScriptSource';
import {
  SAMPLE_SECURITY_LOG,
  SAMPLE_JSON_LOG,
  SAMPLE_CSV_LOG,
  generateSampleEvtxBuffer
} from './data/sampleSocLog';

export default function App() {
  const [rawInput, setRawInput] = useState<string | ArrayBuffer | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [fileSize, setFileSize] = useState<number>(0);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<SocAnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const supportedExtensions = ['log', 'txt', 'evtx', 'evt', 'etl', 'csv', 'json'];

  // File upload handler
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    processSelectedFile(file);
  };

  // Drag and drop handler
  const handleDrop = (e: React.DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    processSelectedFile(file);
  };

  const processSelectedFile = (file: File) => {
    const ext = file.name.toLowerCase().split('.').pop() || '';
    if (!supportedExtensions.includes(ext)) {
      setErrorMessage(
        `Unsupported file type ".${ext}". Please upload: .log, .txt, .evtx, .evt, .etl, .csv, or .json`
      );
      return;
    }

    setErrorMessage(null);
    setFileName(file.name);
    setFileSize(file.size);
    setAnalysisResult(null);

    const reader = new FileReader();

    // Binary Windows Event logs (.evtx, .evt, .etl) require ArrayBuffer reading
    if (['evtx', 'evt', 'etl'].includes(ext)) {
      reader.onload = (event) => {
        const buffer = event.target?.result as ArrayBuffer;
        setRawInput(buffer);
      };
      reader.onerror = () => {
        setErrorMessage('Failed to read the binary Windows log file. Please try again.');
      };
      reader.readAsArrayBuffer(file);
    } else {
      // Text, JSON, and CSV logs
      reader.onload = (event) => {
        const text = (event.target?.result as string) || '';
        setRawInput(text);
      };
      reader.onerror = () => {
        setErrorMessage('Failed to read the log file. Please try again.');
      };
      reader.readAsText(file);
    }
  };

  // Sample Log Loaders for 1-click testing
  const loadSample = (type: 'text' | 'evtx' | 'json' | 'csv') => {
    setErrorMessage(null);
    setAnalysisResult(null);

    if (type === 'text') {
      setFileName('auth_and_web.log');
      setFileSize(new Blob([SAMPLE_SECURITY_LOG]).size);
      setRawInput(SAMPLE_SECURITY_LOG);
    } else if (type === 'json') {
      setFileName('cloudtrail_siem.json');
      setFileSize(new Blob([SAMPLE_JSON_LOG]).size);
      setRawInput(SAMPLE_JSON_LOG);
    } else if (type === 'csv') {
      setFileName('firewall_export.csv');
      setFileSize(new Blob([SAMPLE_CSV_LOG]).size);
      setRawInput(SAMPLE_CSV_LOG);
    } else if (type === 'evtx') {
      const buffer = generateSampleEvtxBuffer();
      setFileName('Security.evtx');
      setFileSize(buffer.byteLength);
      setRawInput(buffer);
    }
  };

  // Analyze log button action
  const handleAnalyze = () => {
    if (!rawInput) {
      setErrorMessage('Please select or upload a log file first.');
      return;
    }

    setIsAnalyzing(true);
    setErrorMessage(null);

    setTimeout(() => {
      try {
        const result = analyzeLogContent(fileName || 'uploaded_log.log', rawInput, fileSize);
        setAnalysisResult(result);
      } catch (err) {
        setErrorMessage('An error occurred while analyzing the log file.');
      } finally {
        setIsAnalyzing(false);
      }
    }, 200);
  };

  // Download plain text report
  const handleDownloadReport = () => {
    if (!analysisResult) return;
    const reportText = generateTextReport(analysisResult);
    const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `log_analysis_${analysisResult.fileName.replace(/\.[^/.]+$/, '')}_report.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Download actual bash script
  const handleDownloadBashScript = () => {
    const blob = new Blob([LOG_ANALYZER_SCRIPT_SOURCE], { type: 'text/x-sh;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'log_analyzer.sh';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleReset = () => {
    setRawInput(null);
    setFileName('');
    setFileSize(0);
    setAnalysisResult(null);
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 flex flex-col font-sans">
      {/* Simple, Clean Top Header */}
      <header className="border-b border-neutral-800 bg-neutral-900/90 py-4 px-6">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <span>SOC Log Analyzer</span>
                <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  Blue Team Tool
                </span>
              </h1>
              <p className="text-xs text-neutral-400">
                Multi-format log analysis for Windows Events (.evtx, .evt, .etl), JSON, CSV, and Text logs
              </p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-4xl w-full mx-auto p-4 sm:p-6 flex-1 space-y-6">
        {/* Error Notification */}
        {errorMessage && (
          <div className="p-3.5 bg-rose-950/40 border border-rose-800 text-rose-300 rounded-lg text-xs flex items-center gap-2">
            <XCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Section 1: Upload Log File */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-neutral-200 flex items-center gap-2">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-mono">
                1
              </span>
              <span>Upload Log File</span>
            </h2>

            {fileName && (
              <button
                onClick={handleReset}
                className="text-xs text-neutral-400 hover:text-neutral-200 flex items-center gap-1 transition"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Choose another file</span>
              </button>
            )}
          </div>

          {/* Drag & Drop Upload Zone */}
          <label
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-6 flex flex-col items-center justify-center text-center cursor-pointer transition ${
              fileName
                ? 'border-emerald-500/50 bg-emerald-950/10'
                : 'border-neutral-800 hover:border-neutral-700 bg-neutral-950/60'
            }`}
          >
            <input
              type="file"
              accept=".log,.txt,.evtx,.evt,.etl,.csv,.json"
              onChange={handleFileUpload}
              className="hidden"
            />

            {fileName ? (
              <div className="flex flex-col items-center gap-2">
                <FileText className="w-8 h-8 text-emerald-400" />
                <div className="text-xs font-medium text-emerald-300 font-mono">{fileName}</div>
                <div className="text-[11px] text-neutral-400">
                  {(fileSize / 1024).toFixed(1)} KB loaded
                </div>
                <span className="text-[11px] text-neutral-500 mt-1">
                  Click or drag to replace this file
                </span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2">
                <Upload className="w-8 h-8 text-neutral-500" />
                <div className="text-xs font-medium text-neutral-300">
                  Click to browse or drag and drop your log file
                </div>
                <div className="text-[11px] text-neutral-400 font-mono">
                  Supported: <span className="text-emerald-400">.log</span>, <span className="text-emerald-400">.txt</span>, <span className="text-emerald-400">.evtx</span>, <span className="text-emerald-400">.evt</span>, <span className="text-emerald-400">.etl</span>, <span className="text-emerald-400">.csv</span>, <span className="text-emerald-400">.json</span>
                </div>
              </div>
            )}
          </label>

          {/* Quick Helper to load samples */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs gap-2 pt-1 border-t border-neutral-800/80">
            <span className="text-neutral-400">Or test with a sample log:</span>
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
              <button
                type="button"
                onClick={() => loadSample('text')}
                className="px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded border border-neutral-700 transition"
              >
                Linux Auth (.log)
              </button>
              <button
                type="button"
                onClick={() => loadSample('evtx')}
                className="px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-emerald-400 rounded border border-neutral-700 transition"
              >
                Windows Security (.evtx)
              </button>
              <button
                type="button"
                onClick={() => loadSample('json')}
                className="px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-sky-400 rounded border border-neutral-700 transition"
              >
                SIEM / CloudTrail (.json)
              </button>
              <button
                type="button"
                onClick={() => loadSample('csv')}
                className="px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-amber-300 rounded border border-neutral-700 transition"
              >
                Firewall Export (.csv)
              </button>
            </div>
          </div>

          {/* Section 2: Analyze Button */}
          <div className="pt-2">
            <button
              onClick={handleAnalyze}
              disabled={!rawInput || isAnalyzing}
              className={`w-full py-3 px-4 rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition shadow-md ${
                !rawInput || isAnalyzing
                  ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white active:scale-[0.99]'
              }`}
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Analyzing Log File...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Analyze Logs</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Section 3: Analysis Results */}
        {analysisResult && (
          <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 shadow-sm space-y-6">
            {/* Results Title & Action Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-neutral-800">
              <div>
                <h2 className="text-sm font-semibold text-neutral-200 flex items-center gap-2">
                  <span className="flex items-center justify-center w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-mono">
                    2
                  </span>
                  <span>Analysis Results</span>
                  <span className="text-xs font-normal text-neutral-400 font-mono">
                    ({analysisResult.fileName})
                  </span>
                </h2>
                <div className="text-[11px] text-neutral-400 font-mono mt-0.5 flex items-center gap-1.5">
                  <span>Detected Format:</span>
                  <span className="text-emerald-400 font-semibold px-1.5 py-0.5 bg-neutral-950 rounded border border-neutral-800">
                    {analysisResult.formatDetected}
                  </span>
                </div>
              </div>

              <button
                onClick={handleDownloadReport}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-sm transition active:scale-95"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Report (.txt)</span>
              </button>
            </div>

            {/* 1. Overview Numbers */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3.5 bg-neutral-950 rounded-lg border border-neutral-800">
                <span className="text-neutral-400">Total Entries</span>
                <div className="text-xl font-bold font-mono text-white mt-1">
                  {analysisResult.totalEntries.toLocaleString()}
                </div>
              </div>

              <div className="p-3.5 bg-neutral-950 rounded-lg border border-neutral-800">
                <span className="text-neutral-400">Errors</span>
                <div
                  className={`text-xl font-bold font-mono mt-1 ${
                    analysisResult.errorCount > 0 ? 'text-rose-400' : 'text-neutral-200'
                  }`}
                >
                  {analysisResult.errorCount}
                </div>
              </div>

              <div className="p-3.5 bg-neutral-950 rounded-lg border border-neutral-800">
                <span className="text-neutral-400">Warnings</span>
                <div
                  className={`text-xl font-bold font-mono mt-1 ${
                    analysisResult.warnCount > 0 ? 'text-amber-400' : 'text-neutral-200'
                  }`}
                >
                  {analysisResult.warnCount}
                </div>
              </div>

              <div className="p-3.5 bg-neutral-950 rounded-lg border border-neutral-800">
                <span className="text-neutral-400">Unique IPs</span>
                <div className="text-xl font-bold font-mono text-neutral-200 mt-1">
                  {analysisResult.uniqueIpsCount}
                </div>
              </div>
            </div>

            {/* 2. Brute-Force & Suspicious Activities */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-400 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Suspicious Activity & Potential Attacks</span>
              </h3>

              {analysisResult.suspiciousActivities.length > 0 ? (
                <div className="space-y-3">
                  {analysisResult.suspiciousActivities.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-4 bg-rose-950/20 border border-rose-900/40 rounded-lg space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              alert.severity === 'High'
                                ? 'bg-rose-500 text-white'
                                : 'bg-amber-500 text-neutral-950'
                            }`}
                          >
                            {alert.severity} Risk
                          </span>
                          <span className="font-semibold text-rose-200">{alert.title}</span>
                        </div>
                      </div>

                      <p className="text-neutral-300 leading-relaxed">{alert.description}</p>

                      <div className="bg-neutral-950 p-2.5 rounded font-mono text-[11px] text-neutral-300 border border-neutral-800/80 overflow-x-auto truncate">
                        <span className="text-neutral-500 select-none">Evidence: </span>
                        {alert.evidence}
                      </div>

                      <div className="text-[11px] text-neutral-400">
                        <span className="text-emerald-400 font-medium">Recommended SOC action: </span>
                        {alert.recommendation}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 bg-emerald-950/20 border border-emerald-900/40 rounded-lg flex items-center gap-2.5 text-xs text-emerald-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    No automated attack patterns or repeated brute-force login attempts detected in this log file.
                  </span>
                </div>
              )}
            </div>

            {/* 3. Windows Security Event IDs (Shown if EVTX/EVT/ETL or Windows Events found) */}
            {analysisResult.hasWindowsEvents && (
              <div className="space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-400 flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-sky-400" />
                  <span>Windows Event IDs Detected</span>
                </h3>

                <div className="border border-neutral-800 rounded-lg overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-neutral-950 border-b border-neutral-800 text-neutral-400 font-medium">
                      <tr>
                        <th className="py-2.5 px-4">Event ID</th>
                        <th className="py-2.5 px-4">Occurrences</th>
                        <th className="py-2.5 px-4">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-800/60 font-mono">
                      {analysisResult.windowsEvents.map((ev) => (
                        <tr
                          key={ev.eventId}
                          className={ev.isSecurityAlert ? 'bg-rose-950/20' : 'hover:bg-neutral-950/40'}
                        >
                          <td className="py-2.5 px-4 font-bold text-sky-300">
                            {ev.eventId}
                            {ev.isSecurityAlert && (
                              <span className="ml-2 text-[10px] font-sans px-1.5 py-0.2 bg-rose-500/20 text-rose-300 border border-rose-800/40 rounded">
                                Alert
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-4 text-neutral-300">{ev.count}</td>
                          <td className="py-2.5 px-4 text-neutral-300 font-sans text-xs">
                            {ev.description}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* 4. Top Suspicious & Active IP Addresses */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-400">
                Top Suspicious & Active IP Addresses
              </h3>

              {analysisResult.topIps.length > 0 ? (
                <div className="border border-neutral-800 rounded-lg overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-neutral-950 border-b border-neutral-800 text-neutral-400 font-medium">
                      <tr>
                        <th className="py-2.5 px-4">IP Address</th>
                        <th className="py-2.5 px-4">Total Requests</th>
                        <th className="py-2.5 px-4">Status / Reason</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-800/60 font-mono">
                      {analysisResult.topIps.map((ip) => (
                        <tr
                          key={ip.ip}
                          className={ip.isSuspicious ? 'bg-rose-950/10' : 'hover:bg-neutral-950/40'}
                        >
                          <td className="py-2.5 px-4 text-neutral-200 font-semibold">{ip.ip}</td>
                          <td className="py-2.5 px-4 text-neutral-300">{ip.count}</td>
                          <td className="py-2.5 px-4">
                            {ip.isSuspicious ? (
                              <span className="inline-flex items-center gap-1 text-rose-400 font-sans text-xs font-medium">
                                <AlertTriangle className="w-3.5 h-3.5" />
                                {ip.suspiciousReason}
                              </span>
                            ) : (
                              <span className="text-neutral-500 font-sans text-xs">
                                Normal Traffic
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-3 bg-neutral-950 rounded-lg text-xs text-neutral-500 text-center">
                  No IP addresses detected in this file.
                </div>
              )}
            </div>

            {/* 5. HTTP Status Codes (if available) */}
            {analysisResult.hasHttpLogs && (
              <div className="space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-400">
                  HTTP Status Codes Breakdown
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {analysisResult.httpStatusCodes.map((status) => (
                    <div
                      key={status.code}
                      className="p-3 bg-neutral-950 rounded-lg border border-neutral-800 flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`font-mono font-bold px-1.5 py-0.5 rounded text-xs ${
                            status.type === 'success'
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                              : status.type === 'client_error'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800/40'
                              : status.type === 'server_error'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800/40'
                              : 'bg-neutral-800 text-neutral-300'
                          }`}
                        >
                          {status.code}
                        </span>
                        <span className="text-neutral-300">{status.meaning}</span>
                      </div>
                      <span className="font-mono text-neutral-400 font-semibold">
                        {status.count} reqs
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Section 4: Standalone Bash Script Section (Strictly ONE Download Script Button) */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <Terminal className="w-5 h-5 text-emerald-400" />
              <div>
                <h3 className="text-sm font-semibold text-neutral-200">
                  Run in Bash Terminal (<code className="text-emerald-400 font-mono">log_analyzer.sh</code>)
                </h3>
                <p className="text-xs text-neutral-400">
                  Analyze logs directly in Linux, macOS, or WSL. Supports text, JSON, and CSV streams.
                </p>
              </div>
            </div>

            <button
              onClick={handleDownloadBashScript}
              className="flex items-center gap-1.5 px-4 py-2 bg-neutral-800 hover:bg-neutral-700 text-neutral-100 border border-neutral-700 rounded-lg text-xs font-semibold transition shrink-0"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>Download log_analyzer.sh</span>
            </button>
          </div>

          <div className="p-3 bg-neutral-950 rounded-lg border border-neutral-800 font-mono text-xs text-neutral-300 space-y-1">
            <div className="text-neutral-500 text-[11px] font-sans">How to run in terminal:</div>
            <div className="text-emerald-400">chmod +x log_analyzer.sh</div>
            <div className="text-emerald-400">./log_analyzer.sh -f /var/log/auth.log --summary</div>
            <div className="text-neutral-400">./log_analyzer.sh --help</div>
          </div>
        </div>
      </main>

      {/* Clean Footer */}
      <footer className="border-t border-neutral-800 py-3 text-center text-xs text-neutral-500">
        SOC Log Analyzer • Blue Team Security Tool
      </footer>
    </div>
  );
}
