/**
 * SOC Log Analyzer - Universal Multi-Format Log Parser
 * Beginner-friendly Blue Team log parser supporting:
 * - Plain Text Logs (.log, .txt)
 * - Windows Event Logs (.evtx, .evt, .etl)
 * - Structured JSON & NDJSON (.json)
 * - Delimited Table Logs (.csv)
 */

export type SupportedLogFormat = 'text' | 'json' | 'csv' | 'evtx' | 'evt' | 'etl';

export interface SuspiciousActivity {
  id: string;
  type:
    | 'Brute Force Attempt'
    | 'Windows Security Alert'
    | 'Web Attack / SQL Injection'
    | 'Reconnaissance Probe'
    | 'Server Error Spike';
  severity: 'High' | 'Medium' | 'Low';
  ip?: string;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
}

export interface IpSummary {
  ip: string;
  count: number;
  failedAttempts: number;
  isSuspicious: boolean;
  suspiciousReason?: string;
}

export interface HttpStatusSummary {
  code: string;
  count: number;
  meaning: string;
  type: 'success' | 'redirect' | 'client_error' | 'server_error';
}

export interface WindowsEventSummary {
  eventId: string;
  count: number;
  provider: string;
  description: string;
  isSecurityAlert: boolean;
}

export interface SocAnalysisResult {
  fileName: string;
  fileSizeBytes: number;
  formatDetected: string;
  totalEntries: number;
  errorCount: number;
  warnCount: number;
  uniqueIpsCount: number;
  topIps: IpSummary[];
  suspiciousActivities: SuspiciousActivity[];
  httpStatusCodes: HttpStatusSummary[];
  windowsEvents: WindowsEventSummary[];
  hasHttpLogs: boolean;
  hasWindowsEvents: boolean;
  firstLines: string[];
}

// Common Windows Security Event ID descriptions
const WINDOWS_EVENT_DESCRIPTIONS: Record<string, { desc: string; alert: boolean; severity?: 'High' | 'Medium' | 'Low'; title?: string }> = {
  '4625': {
    desc: 'An account failed to log on (Failed Logon / Brute Force indicator)',
    alert: true,
    severity: 'High',
    title: 'Windows Event 4625: Failed Logon Detected'
  },
  '4624': {
    desc: 'An account was successfully logged on',
    alert: false
  },
  '4720': {
    desc: 'A user account was created',
    alert: true,
    severity: 'Medium',
    title: 'Windows Event 4720: User Account Created'
  },
  '4726': {
    desc: 'A user account was deleted',
    alert: true,
    severity: 'Medium',
    title: 'Windows Event 4726: User Account Deleted'
  },
  '4738': {
    desc: 'A user account was modified',
    alert: false
  },
  '4672': {
    desc: 'Special privileges assigned to new logon (Admin/Elevated rights)',
    alert: false
  },
  '4688': {
    desc: 'A new process has been created (Command execution)',
    alert: false
  },
  '7045': {
    desc: 'A service was installed in the system (Persistence indicator)',
    alert: true,
    severity: 'High',
    title: 'Windows Event 7045: New Service Installed'
  },
  '1102': {
    desc: 'The audit log was cleared (Anti-Forensics attempt)',
    alert: true,
    severity: 'High',
    title: 'Windows Event 1102: Security Audit Log Cleared'
  },
  '4698': {
    desc: 'A scheduled task was created (Persistence indicator)',
    alert: true,
    severity: 'Medium',
    title: 'Windows Event 4698: Scheduled Task Created'
  },
  '4776': {
    desc: 'The domain controller attempted to validate account credentials',
    alert: false
  }
};

/**
 * Universal Entry Point: Analyzes any supported log file type (text or binary)
 */
export function analyzeLogContent(
  fileName: string,
  rawInput: string | ArrayBuffer,
  fileSizeBytes: number
): SocAnalysisResult {
  const ext = fileName.toLowerCase().split('.').pop() || '';

  // 1. Windows Binary formats (.evtx, .evt, .etl)
  if (['evtx', 'evt', 'etl'].includes(ext) || rawInput instanceof ArrayBuffer) {
    if (rawInput instanceof ArrayBuffer) {
      return parseWindowsBinaryLog(fileName, rawInput, fileSizeBytes, ext as 'evtx' | 'evt' | 'etl');
    }
  }

  // If input is text string:
  const textContent = typeof rawInput === 'string' ? rawInput : new TextDecoder().decode(rawInput);

  // 2. JSON / NDJSON format (.json)
  if (ext === 'json' || textContent.trim().startsWith('[') || (textContent.trim().startsWith('{') && textContent.includes('\n{'))) {
    return parseJsonLog(fileName, textContent, fileSizeBytes);
  }

  // 3. CSV format (.csv)
  if (ext === 'csv') {
    return parseCsvLog(fileName, textContent, fileSizeBytes);
  }

  // 4. Default: Plain text (.log, .txt)
  return parseTextLog(fileName, textContent, fileSizeBytes);
}

// ------------------------------------------------------------------------------
// Parser 1: Plain Text (.log, .txt, syslog, apache, nginx, auth.log)
// ------------------------------------------------------------------------------
function parseTextLog(fileName: string, content: string, fileSizeBytes: number): SocAnalysisResult {
  const lines = content.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const totalEntries = lines.length;

  let errorCount = 0;
  let warnCount = 0;

  const ipCounts: Record<string, number> = {};
  const ipFailures: Record<string, number> = {};
  const ipSuspiciousReasons: Record<string, string> = {};
  const statusCounts: Record<string, number> = {};
  const suspiciousActivities: SuspiciousActivity[] = [];

  const bruteForceByIp: Record<string, { count: number; sampleLine: string }> = {};
  const sqlInjectionLines: string[] = [];
  const reconLines: string[] = [];
  let fatalErrorFound = false;
  let fatalSample = '';

  const ipRegex = /\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g;
  const httpStatusRegex = /" (?:[A-Z]+ [^"]+ HTTP\/[0-9.]+" )?([1-5][0-9]{2}) /;

  for (const line of lines) {
    if (/\b(ERROR|FATAL|CRITICAL)\b|\[ERROR\]|failure|failed/i.test(line)) {
      errorCount++;
    } else if (/\b(WARN|WARNING)\b|\[WARN\]/i.test(line)) {
      warnCount++;
    }

    const matchedIps = line.match(ipRegex);
    let lineIp: string | null = null;
    if (matchedIps && matchedIps.length > 0) {
      lineIp = matchedIps[0];
      for (const ip of matchedIps) {
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
      }
    }

    if (line.includes('Failed password') || line.includes('Invalid user') || line.includes('Authentication failed')) {
      if (lineIp) {
        ipFailures[lineIp] = (ipFailures[lineIp] || 0) + 1;
        if (!bruteForceByIp[lineIp]) {
          bruteForceByIp[lineIp] = { count: 0, sampleLine: line };
        }
        bruteForceByIp[lineIp].count++;
      }
    }

    if (
      line.includes('UNION SELECT') ||
      line.includes('1=1') ||
      line.includes('select+*+from') ||
      line.includes('sqlmap') ||
      line.includes('%27')
    ) {
      sqlInjectionLines.push(line);
      if (lineIp) {
        ipSuspiciousReasons[lineIp] = 'SQL Injection Probing';
      }
    }

    if (
      line.includes('/.env') ||
      line.includes('/wp-login.php') ||
      line.includes('/xmlrpc.php') ||
      line.includes('/phpmyadmin') ||
      line.includes('/administrator') ||
      line.includes('/etc/passwd')
    ) {
      reconLines.push(line);
      if (lineIp && !ipSuspiciousReasons[lineIp]) {
        ipSuspiciousReasons[lineIp] = 'Sensitive Endpoint Probing';
      }
    }

    if (line.includes('Deadlock detected') || line.includes('OutOfMemory') || line.includes('Connection refused')) {
      fatalErrorFound = true;
      fatalSample = line;
    }

    const statusMatch = line.match(httpStatusRegex);
    if (statusMatch) {
      const code = statusMatch[1];
      statusCounts[code] = (statusCounts[code] || 0) + 1;
    }
  }

  // Brute Force Alerts
  for (const [ip, info] of Object.entries(bruteForceByIp)) {
    if (info.count >= 2) {
      ipSuspiciousReasons[ip] = `${info.count} Failed Logins (Brute Force)`;
      suspiciousActivities.push({
        id: `bf-${ip}`,
        type: 'Brute Force Attempt',
        severity: info.count >= 4 ? 'High' : 'Medium',
        ip,
        title: `Repeated Login Failures from IP ${ip}`,
        description: `This IP address attempted ${info.count} failed logins in a short timeframe (pattern for brute-force password guessing).`,
        evidence: info.sampleLine,
        recommendation: `Check firewall rules, block IP ${ip}, and verify if any targeted accounts were breached.`
      });
    }
  }

  // SQL Injection Alert
  if (sqlInjectionLines.length > 0) {
    suspiciousActivities.push({
      id: 'sqli',
      type: 'Web Attack / SQL Injection',
      severity: 'High',
      title: 'SQL Injection Attack Signatures Found',
      description: `Detected ${sqlInjectionLines.length} web requests containing SQL query syntax (such as UNION SELECT or 1=1). Attackers use these to try to extract database records.`,
      evidence: sqlInjectionLines[0],
      recommendation: 'Ensure your web application uses parameterized queries and an active Web Application Firewall (WAF).'
    });
  }

  // Reconnaissance Alert
  if (reconLines.length > 0) {
    suspiciousActivities.push({
      id: 'recon',
      type: 'Reconnaissance Probe',
      severity: 'Medium',
      title: 'Automated Vulnerability Probing Found',
      description: `Detected ${reconLines.length} requests searching for hidden configuration files (.env), WordPress logins, or phpMyAdmin portals.`,
      evidence: reconLines[0],
      recommendation: 'Restrict public access to administrative panels and block automated scanners.'
    });
  }

  // Server Fatal Alert
  if (fatalErrorFound) {
    suspiciousActivities.push({
      id: 'fatal',
      type: 'Server Error Spike',
      severity: 'High',
      title: 'Critical Server or Database Failure',
      description: 'The log contains critical server exceptions (e.g., connection refused, database deadlock, or memory error).',
      evidence: fatalSample,
      recommendation: 'Inspect backend database health, restart unresponsive services, and check system resources.'
    });
  }

  const topIps = buildTopIps(ipCounts, ipFailures, ipSuspiciousReasons);
  const httpStatusCodes = buildHttpStatusSummary(statusCounts);

  return {
    fileName,
    fileSizeBytes,
    formatDetected: 'Plain Text / Syslog (.log, .txt)',
    totalEntries,
    errorCount,
    warnCount,
    uniqueIpsCount: Object.keys(ipCounts).length,
    topIps,
    suspiciousActivities,
    httpStatusCodes,
    windowsEvents: [],
    hasHttpLogs: httpStatusCodes.length > 0,
    hasWindowsEvents: false,
    firstLines: lines.slice(0, 10)
  };
}

// ------------------------------------------------------------------------------
// Parser 2: Structured JSON & NDJSON (.json)
// (CloudTrail, Suricata EVE, Zeek, Elastic/Logstash, Container & App JSON logs)
// ------------------------------------------------------------------------------
function parseJsonLog(fileName: string, content: string, fileSizeBytes: number): SocAnalysisResult {
  let records: Record<string, any>[] = [];
  const rawLines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);

  // Try parsing as standard JSON (Array or single Object with items)
  try {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) {
      records = parsed;
    } else if (parsed && typeof parsed === 'object') {
      if (Array.isArray(parsed.Records)) records = parsed.Records; // AWS CloudTrail format
      else if (Array.isArray(parsed.events)) records = parsed.events;
      else if (Array.isArray(parsed.logs)) records = parsed.logs;
      else if (Array.isArray(parsed.data)) records = parsed.data;
      else records = [parsed];
    }
  } catch {
    // If not standard JSON, parse as NDJSON / JSON Lines (one JSON object per line)
    for (const line of rawLines) {
      try {
        const obj = JSON.parse(line.trim());
        if (obj && typeof obj === 'object') {
          records.push(obj);
        }
      } catch {
        // Skip malformed individual line in NDJSON stream
      }
    }
  }

  const totalEntries = records.length > 0 ? records.length : rawLines.length;
  let errorCount = 0;
  let warnCount = 0;

  const ipCounts: Record<string, number> = {};
  const ipFailures: Record<string, number> = {};
  const ipSuspiciousReasons: Record<string, string> = {};
  const statusCounts: Record<string, number> = {};
  const suspiciousActivities: SuspiciousActivity[] = [];

  const ipRegex = /\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g;

  for (const item of records) {
    const strRepr = JSON.stringify(item);

    // Level detection
    const level = (item.level || item.severity || item.log_level || item.type || '').toString().toUpperCase();
    if (level.includes('ERR') || level.includes('FATAL') || level.includes('CRIT') || item.error || item.errorCode) {
      errorCount++;
    } else if (level.includes('WARN')) {
      warnCount++;
    }

    // IP detection in common JSON fields or whole record
    const candidateIps = [
      item.src_ip,
      item.source_ip,
      item.sourceIPAddress,
      item.client_ip,
      item.clientIp,
      item.ip,
      item.remote_addr,
      item.dest_ip,
      item.destination_ip
    ].filter(Boolean);

    let foundIp = candidateIps.length > 0 ? candidateIps[0] : null;
    if (!foundIp) {
      const match = strRepr.match(ipRegex);
      if (match) foundIp = match[0];
    }

    if (foundIp && typeof foundIp === 'string') {
      ipCounts[foundIp] = (ipCounts[foundIp] || 0) + 1;
    }

    // HTTP Status detection
    const status = item.status || item.status_code || item.http_status || item.response_code;
    if (status) {
      const codeStr = status.toString();
      if (/^[1-5][0-9]{2}$/.test(codeStr)) {
        statusCounts[codeStr] = (statusCounts[codeStr] || 0) + 1;
      }
    }

    // Detect Brute Force / Auth Failure in JSON
    const eventName = (item.eventName || item.event_type || item.action || item.message || '').toString();
    if (
      strRepr.includes('Failed password') ||
      strRepr.includes('AuthFailure') ||
      eventName.includes('ConsoleLogin') && item.errorMessage
    ) {
      if (foundIp) {
        ipFailures[foundIp] = (ipFailures[foundIp] || 0) + 1;
      }
    }

    // SQL Injection / Web Attacks in JSON query fields
    if (strRepr.includes('UNION SELECT') || strRepr.includes('1=1') || strRepr.includes('sqlmap')) {
      if (foundIp) ipSuspiciousReasons[foundIp] = 'SQL Injection in JSON payload';
      if (!suspiciousActivities.some((a) => a.id === 'json-sqli')) {
        suspiciousActivities.push({
          id: 'json-sqli',
          type: 'Web Attack / SQL Injection',
          severity: 'High',
          title: 'SQL Injection Signature in JSON Data',
          description: 'Detected SQL injection syntax inside structured JSON log attributes.',
          evidence: strRepr.slice(0, 160),
          recommendation: 'Block source IPs and sanitize all incoming JSON and API query parameters.'
        });
      }
    }
  }

  // Check failed auth brute force counts
  for (const [ip, fails] of Object.entries(ipFailures)) {
    if (fails >= 2) {
      ipSuspiciousReasons[ip] = `${fails} Auth Failures in JSON events`;
      suspiciousActivities.push({
        id: `json-bf-${ip}`,
        type: 'Brute Force Attempt',
        severity: fails >= 5 ? 'High' : 'Medium',
        ip,
        title: `Repeated Authentication Failures from IP ${ip}`,
        description: `Source IP ${ip} generated ${fails} failed authorization / login attempts in structured events.`,
        evidence: `Multiple failed auth records recorded for IP ${ip}`,
        recommendation: 'Check user credentials and enable multi-factor authentication (MFA).'
      });
    }
  }

  const topIps = buildTopIps(ipCounts, ipFailures, ipSuspiciousReasons);
  const httpStatusCodes = buildHttpStatusSummary(statusCounts);

  return {
    fileName,
    fileSizeBytes,
    formatDetected: 'Structured JSON / NDJSON (.json)',
    totalEntries,
    errorCount,
    warnCount,
    uniqueIpsCount: Object.keys(ipCounts).length,
    topIps,
    suspiciousActivities,
    httpStatusCodes,
    windowsEvents: [],
    hasHttpLogs: httpStatusCodes.length > 0,
    hasWindowsEvents: false,
    firstLines: rawLines.slice(0, 10)
  };
}

// ------------------------------------------------------------------------------
// Parser 3: CSV Table Log (.csv)
// (Firewall exports, SIEM CSV, Suricata/Zeek CSV, Web Server CSV)
// ------------------------------------------------------------------------------
function parseCsvLog(fileName: string, content: string, fileSizeBytes: number): SocAnalysisResult {
  const lines = content.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    return parseTextLog(fileName, content, fileSizeBytes);
  }

  const headerLine = lines[0];
  const delimiter = headerLine.includes('\t') ? '\t' : headerLine.includes(';') ? ';' : ',';
  const headers = headerLine.split(delimiter).map((h) => h.trim().replace(/^["']|["']$/g, '').toLowerCase());

  // Find column indices
  const ipColIndices: number[] = [];
  let statusColIndex = -1;
  let levelColIndex = -1;
  let messageColIndex = -1;

  headers.forEach((h, idx) => {
    if (h.includes('ip') || h.includes('src') || h.includes('dst') || h.includes('client') || h.includes('host')) {
      ipColIndices.push(idx);
    }
    if (h.includes('status') || h.includes('code') || h.includes('response')) {
      statusColIndex = idx;
    }
    if (h.includes('level') || h.includes('severity') || h.includes('priority')) {
      levelColIndex = idx;
    }
    if (h.includes('message') || h.includes('msg') || h.includes('desc') || h.includes('info')) {
      messageColIndex = idx;
    }
  });

  const ipCounts: Record<string, number> = {};
  const ipFailures: Record<string, number> = {};
  const ipSuspiciousReasons: Record<string, string> = {};
  const statusCounts: Record<string, number> = {};
  const suspiciousActivities: SuspiciousActivity[] = [];

  let errorCount = 0;
  let warnCount = 0;
  const ipRegex = /\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g;

  // Process rows (skipping header)
  for (let i = 1; i < lines.length; i++) {
    const row = lines[i];
    const cols = row.split(delimiter).map((c) => c.trim().replace(/^["']|["']$/g, ''));

    // Check level
    if (levelColIndex !== -1 && cols[levelColIndex]) {
      const lvl = cols[levelColIndex].toUpperCase();
      if (lvl.includes('ERR') || lvl.includes('FATAL') || lvl.includes('CRIT') || lvl.includes('FAIL')) {
        errorCount++;
      } else if (lvl.includes('WARN')) {
        warnCount++;
      }
    } else {
      if (/\b(ERROR|FATAL|FAIL)\b/i.test(row)) errorCount++;
      else if (/\bWARN\b/i.test(row)) warnCount++;
    }

    // Check HTTP status code
    if (statusColIndex !== -1 && cols[statusColIndex]) {
      const st = cols[statusColIndex];
      if (/^[1-5][0-9]{2}$/.test(st)) {
        statusCounts[st] = (statusCounts[st] || 0) + 1;
      }
    }

    // Extract IPs
    let foundRowIp: string | null = null;
    for (const idx of ipColIndices) {
      if (cols[idx]) {
        const m = cols[idx].match(ipRegex);
        if (m) {
          foundRowIp = m[0];
          ipCounts[foundRowIp] = (ipCounts[foundRowIp] || 0) + 1;
        }
      }
    }

    if (!foundRowIp) {
      const allMatches = row.match(ipRegex);
      if (allMatches) {
        foundRowIp = allMatches[0];
        ipCounts[foundRowIp] = (ipCounts[foundRowIp] || 0) + 1;
      }
    }

    // Check auth failures / brute force
    if (row.includes('Failed') || row.includes('Invalid') || row.includes('Denied') || row.includes('Drop')) {
      if (foundRowIp) {
        ipFailures[foundRowIp] = (ipFailures[foundRowIp] || 0) + 1;
      }
    }

    // Check SQL injection in CSV
    if (row.includes('UNION SELECT') || row.includes('1=1') || row.includes('sqlmap')) {
      if (foundRowIp) ipSuspiciousReasons[foundRowIp] = 'SQL Injection pattern in CSV';
      if (!suspiciousActivities.some((a) => a.id === 'csv-sqli')) {
        suspiciousActivities.push({
          id: 'csv-sqli',
          type: 'Web Attack / SQL Injection',
          severity: 'High',
          title: 'SQL Injection Found in CSV Log',
          description: 'Detected SQL injection pattern in exported CSV records.',
          evidence: row.slice(0, 160),
          recommendation: 'Inspect backend database query logs and verify input validation.'
        });
      }
    }
  }

  for (const [ip, fails] of Object.entries(ipFailures)) {
    if (fails >= 3) {
      ipSuspiciousReasons[ip] = `${fails} Dropped/Failed Actions in CSV`;
      suspiciousActivities.push({
        id: `csv-bf-${ip}`,
        type: 'Brute Force Attempt',
        severity: 'High',
        ip,
        title: `Repeated Blocked / Failed Attempts from IP ${ip}`,
        description: `This IP registered ${fails} denied or failed events in the exported CSV log.`,
        evidence: `Multiple dropped/failed records for IP ${ip}`,
        recommendation: 'Check firewall drop logs and enforce permanent block.'
      });
    }
  }

  const topIps = buildTopIps(ipCounts, ipFailures, ipSuspiciousReasons);
  const httpStatusCodes = buildHttpStatusSummary(statusCounts);

  return {
    fileName,
    fileSizeBytes,
    formatDetected: 'CSV Delimited Table Log (.csv)',
    totalEntries: lines.length - 1,
    errorCount,
    warnCount,
    uniqueIpsCount: Object.keys(ipCounts).length,
    topIps,
    suspiciousActivities,
    httpStatusCodes,
    windowsEvents: [],
    hasHttpLogs: httpStatusCodes.length > 0,
    hasWindowsEvents: false,
    firstLines: lines.slice(0, 10)
  };
}

// ------------------------------------------------------------------------------
// Parser 4: Windows Event Logs & Trace Logs (.evtx, .evt, .etl)
// Binary chunk inspection, EventID extraction, Security Events (4625, 4624, 7045)
// ------------------------------------------------------------------------------
function parseWindowsBinaryLog(
  fileName: string,
  buffer: ArrayBuffer,
  fileSizeBytes: number,
  extension: string
): SocAnalysisResult {
  const bytes = new Uint8Array(buffer);
  const dataView = new DataView(buffer);

  let totalEntries = 0;
  let errorCount = 0;
  let warnCount = 0;

  const eventCounts: Record<string, { count: number; provider: string }> = {};
  const ipCounts: Record<string, number> = {};
  const ipFailures: Record<string, number> = {};
  const suspiciousActivities: SuspiciousActivity[] = [];
  const extractedLines: string[] = [];

  // Identify Windows Log format
  let formatLabel = 'Windows Event Log (.evtx)';
  const isEvtx = bytes.length >= 8 && bytes[0] === 0x45 && bytes[1] === 0x6c && bytes[2] === 0x66 && bytes[3] === 0x46; // "ElfFile"
  const isEvt = bytes.length >= 4 && bytes[0] === 0x30 && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x00; // Legacy 48 bytes header
  const isEtl = extension.toLowerCase() === 'etl';

  if (isEvt || extension.toLowerCase() === 'evt') formatLabel = 'Legacy Windows Event Log (.evt)';
  else if (isEtl) formatLabel = 'Windows Event Trace Log (.etl)';
  else if (isEvtx || extension.toLowerCase() === 'evtx') formatLabel = 'Windows XML Event Log (.evtx)';

  // 1. Structural EVTX Chunk Scanner (if .evtx)
  if (isEvtx && bytes.length > 4096) {
    const chunkSize = 65536; // 64 KB per EVTX chunk
    const totalChunks = Math.floor((bytes.length - 4096) / chunkSize);

    for (let c = 0; c < totalChunks; c++) {
      const chunkOffset = 4096 + c * chunkSize;
      // Check chunk header "ElfChnk\0"
      if (
        bytes[chunkOffset] === 0x45 &&
        bytes[chunkOffset + 1] === 0x6c &&
        bytes[chunkOffset + 2] === 0x66 &&
        bytes[chunkOffset + 3] === 0x43
      ) {
        try {
          const firstRecord = Number(dataView.getBigUint64(chunkOffset + 8, true));
          const lastRecord = Number(dataView.getBigUint64(chunkOffset + 16, true));
          if (lastRecord >= firstRecord) {
            totalEntries += lastRecord - firstRecord + 1;
          }
        } catch {
          // ignore BigUint64 fallback
        }
      }
    }
  }

  // 2. High-speed String & Token Decoders for UTF-16LE and UTF-8 Event Extraction
  // Windows Event logs store all provider names, EventIDs, Usernames, and IPs as UTF-16LE strings.
  const decodedUtf16 = decodeUtf16LeStrings(bytes);
  const decodedUtf8 = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const fullText = decodedUtf16 + '\n' + decodedUtf8;

  // Extract Event IDs via Regex
  // Pattern matches EventID tags or standard EVT / EVTX keywords
  const eventIdRegex = /(?:<EventID[^>]*>|EventID[:=\s]+)(\d{4,5})(?:<\/EventID>|\b)/g;
  let match: RegExpExecArray | null;
  while ((match = eventIdRegex.exec(fullText)) !== null) {
    const id = match[1];
    if (!eventCounts[id]) {
      eventCounts[id] = { count: 0, provider: 'Microsoft-Windows-Security-Auditing' };
    }
    eventCounts[id].count++;
  }

  // Also check common security Event IDs if not matched via XML tags
  const knownIds = ['4625', '4624', '4720', '4726', '7045', '1102', '4688', '4672', '4698'];
  for (const id of knownIds) {
    if (!eventCounts[id]) {
      const occurrences = (fullText.match(new RegExp(`\\b${id}\\b`, 'g')) || []).length;
      if (occurrences > 2) {
        eventCounts[id] = { count: occurrences, provider: 'Microsoft-Windows-Security-Auditing' };
      }
    }
  }

  // Extract IP Addresses from Windows Event Payload
  const ipRegex = /\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g;
  let ipMatch: RegExpExecArray | null;
  while ((ipMatch = ipRegex.exec(fullText)) !== null) {
    const ip = ipMatch[1];
    // Filter out common subnet masks or zero IPs
    if (ip !== '255.255.255.0' && ip !== '0.0.0.0' && ip !== '127.0.0.1' && !ip.startsWith('255.')) {
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }
  }

  // Calculate failed logons (Event 4625)
  const failed4625 = eventCounts['4625']?.count || 0;
  if (failed4625 > 0) {
    errorCount += failed4625;
    const topIp = Object.keys(ipCounts)[0] || 'Remote Client';
    ipFailures[topIp] = failed4625;

    suspiciousActivities.push({
      id: 'win-4625',
      type: 'Brute Force Attempt',
      severity: failed4625 >= 5 ? 'High' : 'Medium',
      ip: topIp !== 'Remote Client' ? topIp : undefined,
      title: `Windows Event 4625: Repeated Logon Failures (${failed4625} events)`,
      description: `Detected ${failed4625} instances of Event ID 4625 (An account failed to log on). This is a strong indicator of password brute-force or credential stuffing.`,
      evidence: `EventID: 4625 | Provider: Microsoft-Windows-Security-Auditing | Count: ${failed4625}`,
      recommendation: 'Identify the targeted username, verify account lockout policy, and inspect the caller IP address.'
    });
  }

  // Check Event 1102 (Audit Log Cleared)
  if (eventCounts['1102'] && eventCounts['1102'].count > 0) {
    suspiciousActivities.push({
      id: 'win-1102',
      type: 'Windows Security Alert',
      severity: 'High',
      title: 'Windows Event 1102: Security Audit Log Cleared!',
      description: 'The Windows security audit log was explicitly cleared. Attackers frequently clear event logs to hide their tracks.',
      evidence: 'EventID: 1102 - The audit log was cleared',
      recommendation: 'Immediately investigate the administrator session active at the time of log clearing.'
    });
  }

  // Check Event 7045 (New Service Installed)
  if (eventCounts['7045'] && eventCounts['7045'].count > 0) {
    suspiciousActivities.push({
      id: 'win-7045',
      type: 'Windows Security Alert',
      severity: 'High',
      title: 'Windows Event 7045: New Service Installed',
      description: 'A new system service was registered on the machine. This is a common persistence mechanism used by malware and adversaries.',
      evidence: 'EventID: 7045 - A service was installed in the system',
      recommendation: 'Check the service executable path and ensure it is signed and authorized.'
    });
  }

  // Check Event 4720 (User Created)
  if (eventCounts['4720'] && eventCounts['4720'].count > 0) {
    suspiciousActivities.push({
      id: 'win-4720',
      type: 'Windows Security Alert',
      severity: 'Medium',
      title: 'Windows Event 4720: User Account Created',
      description: 'A new Windows local or domain user account was created.',
      evidence: `EventID: 4720 | Count: ${eventCounts['4720'].count}`,
      recommendation: 'Verify whether the newly created account was authorized by IT management.'
    });
  }

  // Summary lines for preview
  const linesFound = fullText.split('\n').filter((l) => l.trim().length > 15 && /[a-zA-Z0-9]/.test(l));
  for (let i = 0; i < Math.min(10, linesFound.length); i++) {
    extractedLines.push(linesFound[i].trim().slice(0, 160));
  }

  // If totalEntries wasn't set from chunks, estimate from events or file size
  if (totalEntries === 0) {
    const sumEvents = Object.values(eventCounts).reduce((acc, curr) => acc + curr.count, 0);
    totalEntries = sumEvents > 0 ? sumEvents : Math.max(1, Math.floor(fileSizeBytes / 512));
  }

  // Build Windows Events table
  const windowsEvents: WindowsEventSummary[] = Object.entries(eventCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .map(([id, info]) => {
      const def = WINDOWS_EVENT_DESCRIPTIONS[id];
      return {
        eventId: id,
        count: info.count,
        provider: info.provider,
        description: def ? def.desc : `Windows Event ID ${id}`,
        isSecurityAlert: Boolean(def?.alert)
      };
    });

  const topIps = buildTopIps(ipCounts, ipFailures, {});

  return {
    fileName,
    fileSizeBytes,
    formatDetected: formatLabel,
    totalEntries,
    errorCount,
    warnCount,
    uniqueIpsCount: Object.keys(ipCounts).length,
    topIps,
    suspiciousActivities,
    httpStatusCodes: [],
    windowsEvents,
    hasHttpLogs: false,
    hasWindowsEvents: windowsEvents.length > 0,
    firstLines: extractedLines.length > 0 ? extractedLines : [`[Binary Windows Log: ${fileName}] (${totalEntries} records parsed)`]
  };
}

/**
 * Fast UTF-16LE String Extractor for Binary Windows Logs
 */
function decodeUtf16LeStrings(bytes: Uint8Array): string {
  const chunks: string[] = [];
  let currentChars: number[] = [];

  for (let i = 0; i < bytes.length - 1; i += 2) {
    const low = bytes[i];
    const high = bytes[i + 1];

    // Standard ASCII character encoded as UTF-16LE (high byte is 0)
    if (high === 0 && ((low >= 32 && low <= 126) || low === 10 || low === 13 || low === 9)) {
      currentChars.push(low);
    } else {
      if (currentChars.length >= 4) {
        chunks.push(String.fromCharCode(...currentChars));
      }
      currentChars = [];
    }

    if (chunks.length > 50000) break; // Memory safety cap for massive logs
  }

  if (currentChars.length >= 4) {
    chunks.push(String.fromCharCode(...currentChars));
  }

  return chunks.join(' ');
}

// ------------------------------------------------------------------------------
// Helper Builders
// ------------------------------------------------------------------------------
function buildTopIps(
  ipCounts: Record<string, number>,
  ipFailures: Record<string, number>,
  ipSuspiciousReasons: Record<string, string>
): IpSummary[] {
  return Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => {
      const failures = ipFailures[ip] || 0;
      const isSuspicious = failures >= 2 || Boolean(ipSuspiciousReasons[ip]);
      return {
        ip,
        count,
        failedAttempts: failures,
        isSuspicious,
        suspiciousReason: ipSuspiciousReasons[ip] || (isSuspicious ? `${failures} failed attempts` : undefined)
      };
    });
}

function buildHttpStatusSummary(statusCounts: Record<string, number>): HttpStatusSummary[] {
  const statusMeanings: Record<string, { meaning: string; type: 'success' | 'redirect' | 'client_error' | 'server_error' }> = {
    '200': { meaning: 'OK (Request succeeded)', type: 'success' },
    '201': { meaning: 'Created (Resource created)', type: 'success' },
    '301': { meaning: 'Moved Permanently', type: 'redirect' },
    '302': { meaning: 'Found (Temporary redirect)', type: 'redirect' },
    '304': { meaning: 'Not Modified (Cached)', type: 'redirect' },
    '400': { meaning: 'Bad Request (Malformed query or scanner)', type: 'client_error' },
    '401': { meaning: 'Unauthorized (Missing authentication)', type: 'client_error' },
    '403': { meaning: 'Forbidden (Access denied / blocked)', type: 'client_error' },
    '404': { meaning: 'Not Found (Missing page or probing)', type: 'client_error' },
    '500': { meaning: 'Internal Server Error (Application crashed)', type: 'server_error' },
    '502': { meaning: 'Bad Gateway (Backend down or timeout)', type: 'server_error' },
    '503': { meaning: 'Service Unavailable', type: 'server_error' }
  };

  return Object.entries(statusCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([code, count]) => {
      const def = statusMeanings[code] || {
        meaning: code.startsWith('2') ? 'Success' : code.startsWith('4') ? 'Client Error' : 'Server Error',
        type: code.startsWith('2') ? 'success' : code.startsWith('4') ? 'client_error' : 'server_error'
      };
      return {
        code,
        count,
        meaning: def.meaning,
        type: def.type
      };
    });
}

/**
 * Generates clean plain text report suitable for saving and sharing
 */
export function generateTextReport(result: SocAnalysisResult): string {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const lines: string[] = [];

  lines.push('======================================================================');
  lines.push('                   SOC LOG ANALYSIS REPORT                            ');
  lines.push('======================================================================');
  lines.push(`Generated:   ${timestamp} UTC`);
  lines.push(`Target File: ${result.fileName} (${(result.fileSizeBytes / 1024).toFixed(1)} KB)`);
  lines.push(`Format:      ${result.formatDetected}`);
  lines.push('----------------------------------------------------------------------');
  lines.push('');
  lines.push('1. OVERVIEW METRICS:');
  lines.push(`   - Total Log Entries:     ${result.totalEntries}`);
  lines.push(`   - Errors Detected:       ${result.errorCount}`);
  lines.push(`   - Warnings Detected:     ${result.warnCount}`);
  lines.push(`   - Unique IP Addresses:   ${result.uniqueIpsCount}`);
  lines.push('');

  lines.push('2. SUSPICIOUS ACTIVITY & BRUTE-FORCE ALERTS:');
  if (result.suspiciousActivities.length === 0) {
    lines.push('   [None] No clear attack patterns or brute-force attempts detected.');
  } else {
    result.suspiciousActivities.forEach((act, idx) => {
      lines.push(`   [Alert #${idx + 1}] ${act.type} (Severity: ${act.severity})`);
      lines.push(`   Title:          ${act.title}`);
      lines.push(`   Description:    ${act.description}`);
      lines.push(`   Evidence:       ${act.evidence}`);
      lines.push(`   Recommendation: ${act.recommendation}`);
      lines.push('');
    });
  }

  if (result.hasWindowsEvents) {
    lines.push('3. WINDOWS EVENT CODES DETECTED:');
    lines.push(`   ${'EVENT ID'.padEnd(10)} ${'COUNT'.padEnd(8)} ${'DESCRIPTION'}`);
    lines.push(`   ${'--------'.padEnd(10)} ${'-----'.padEnd(8)} ${'-----------'}`);
    result.windowsEvents.forEach((we) => {
      const alertTag = we.isSecurityAlert ? ' [ALERT]' : '';
      lines.push(`   ${we.eventId.padEnd(10)} ${we.count.toString().padEnd(8)} ${we.description}${alertTag}`);
    });
    lines.push('');
  }

  lines.push('4. TOP ACTIVE & SUSPICIOUS IP ADDRESSES:');
  if (result.topIps.length === 0) {
    lines.push('   (No IP addresses detected in this log file)');
  } else {
    lines.push(`   ${'COUNT'.padEnd(8)} ${'IP ADDRESS'.padEnd(18)} ${'STATUS / DETAILS'}`);
    lines.push(`   ${'-----'.padEnd(8)} ${'----------'.padEnd(18)} ${'----------------'}`);
    result.topIps.forEach((ip) => {
      const statusText = ip.isSuspicious ? `[SUSPICIOUS] ${ip.suspiciousReason}` : 'Normal Traffic';
      lines.push(`   ${ip.count.toString().padEnd(8)} ${ip.ip.padEnd(18)} ${statusText}`);
    });
  }
  lines.push('');

  if (result.hasHttpLogs) {
    lines.push('5. HTTP STATUS CODES:');
    lines.push(`   ${'CODE'.padEnd(8)} ${'COUNT'.padEnd(8)} ${'MEANING'}`);
    lines.push(`   ${'----'.padEnd(8)} ${'-----'.padEnd(8)} ${'-------'}`);
    result.httpStatusCodes.forEach((s) => {
      lines.push(`   ${s.code.padEnd(8)} ${s.count.toString().padEnd(8)} ${s.meaning}`);
    });
    lines.push('');
  }

  lines.push('======================================================================');
  lines.push('Bash Tool: log_analyzer.sh | End of Report');
  lines.push('======================================================================');

  return lines.join('\n');
}
