export const SAMPLE_SECURITY_LOG = `Oct 16 07:12:33 debian sshd[4912]: Accepted publickey for sysadmin from 192.168.1.50 port 54821 ssh2: RSA SHA256:abc123XYZ
Oct 16 07:14:02 debian sudo: sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/systemctl restart nginx
Oct 16 08:01:10 debian sshd[5210]: Invalid user admin from 185.220.101.5 port 41203
Oct 16 08:01:12 debian sshd[5210]: Failed password for invalid user admin from 185.220.101.5 port 41203 ssh2
Oct 16 08:01:15 debian sshd[5214]: Failed password for invalid user root from 185.220.101.5 port 41208 ssh2
Oct 16 08:01:18 debian sshd[5218]: Failed password for invalid user test from 185.220.101.5 port 41212 ssh2
Oct 16 08:01:21 debian sshd[5222]: Failed password for invalid user ubuntu from 185.220.101.5 port 41216 ssh2
Oct 16 08:01:25 debian sshd[5225]: Received disconnect from 185.220.101.5 port 41216:11: Bye Bye [preauth]
192.168.1.105 - - [16/Oct/2026:08:12:01 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
192.168.1.105 - - [16/Oct/2026:08:12:02 +0000] "GET /app.css HTTP/1.1" 200 1250 "https://example.com" "Mozilla/5.0"
203.0.113.42 - - [16/Oct/2026:08:14:15 +0000] "GET /api/v1/products HTTP/1.1" 200 8920 "-" "curl/7.88.1"
203.0.113.42 - - [16/Oct/2026:08:14:16 +0000] "POST /api/v1/checkout HTTP/1.1" 500 412 "-" "curl/7.88.1"
198.51.100.23 - - [16/Oct/2026:08:15:30 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Python-urllib/3.10"
198.51.100.23 - - [16/Oct/2026:08:15:32 +0000] "GET /.env HTTP/1.1" 403 281 "-" "Python-urllib/3.10"
198.51.100.23 - - [16/Oct/2026:08:15:33 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Python-urllib/3.10"
192.0.2.88 - - [16/Oct/2026:08:20:01 +0000] "GET /search?q=select+*+from+users HTTP/1.1" 400 310 "-" "sqlmap/1.7.2"
192.0.2.88 - - [16/Oct/2026:08:20:02 +0000] "GET /search?q=1+or+1=1 HTTP/1.1" 400 310 "-" "sqlmap/1.7.2"
192.0.2.88 - - [16/Oct/2026:08:20:05 +0000] "GET /search?q=%27%20UNION%20SELECT%20NULL-- HTTP/1.1" 400 310 "-" "sqlmap/1.7.2"
2026-10-16 08:20:15.340 [worker-1] ERROR com.app.worker.EmailWorker - Failed to send dispatch email: Connection refused
2026-10-16 08:25:40.910 [http-exec-9] WARN com.app.payment.StripeClient - Payment timeout after 3000ms
2026-10-16 08:25:41.005 [http-exec-9] FATAL com.app.service.TransactionManager - Deadlock detected in account balance reconciliation
Oct 16 08:30:00 debian sshd[5601]: Invalid user oracle from 45.33.32.156 port 39811
Oct 16 08:30:02 debian sshd[5601]: Failed password for invalid user oracle from 45.33.32.156 port 39811 ssh2
Oct 16 08:30:05 debian sshd[5601]: Failed password for invalid user oracle from 45.33.32.156 port 39814 ssh2`;

export const SAMPLE_JSON_LOG = `[
  {"timestamp": "2026-10-16T08:00:01Z", "level": "INFO", "client_ip": "192.168.1.105", "event": "UserLogin", "user": "alice", "status_code": 200},
  {"timestamp": "2026-10-16T08:01:12Z", "level": "ERROR", "client_ip": "185.220.101.5", "event": "AuthFailure", "user": "admin", "status_code": 401, "message": "Failed password attempt 1"},
  {"timestamp": "2026-10-16T08:01:15Z", "level": "ERROR", "client_ip": "185.220.101.5", "event": "AuthFailure", "user": "admin", "status_code": 401, "message": "Failed password attempt 2"},
  {"timestamp": "2026-10-16T08:01:18Z", "level": "ERROR", "client_ip": "185.220.101.5", "event": "AuthFailure", "user": "root", "status_code": 401, "message": "Failed password attempt 3"},
  {"timestamp": "2026-10-16T08:01:21Z", "level": "ERROR", "client_ip": "185.220.101.5", "event": "AuthFailure", "user": "test", "status_code": 401, "message": "Failed password attempt 4"},
  {"timestamp": "2026-10-16T08:14:00Z", "level": "INFO", "client_ip": "203.0.113.42", "event": "ApiRequest", "endpoint": "/api/v1/orders", "status_code": 200},
  {"timestamp": "2026-10-16T08:14:05Z", "level": "ERROR", "client_ip": "203.0.113.42", "event": "ApiRequest", "endpoint": "/api/v1/checkout", "status_code": 500, "message": "Database deadlock detected"},
  {"timestamp": "2026-10-16T08:20:00Z", "level": "WARN", "client_ip": "192.0.2.88", "event": "WafProbe", "payload": "GET /search?q=%27%20OR%201=1--", "status_code": 400, "message": "UNION SELECT detected"}
]`;

export const SAMPLE_CSV_LOG = `Timestamp,Level,Source_IP,Destination_IP,Status_Code,Action,Details
2026-10-16 08:00:10,INFO,192.168.1.105,10.0.0.5,200,ALLOW,Standard HTTPS traffic to /dashboard
2026-10-16 08:01:00,ERROR,185.220.101.5,10.0.0.22,401,DENIED,SSH Failed password for invalid user admin
2026-10-16 08:01:05,ERROR,185.220.101.5,10.0.0.22,401,DENIED,SSH Failed password for invalid user root
2026-10-16 08:01:10,ERROR,185.220.101.5,10.0.0.22,401,DENIED,SSH Failed password for invalid user ubuntu
2026-10-16 08:01:15,ERROR,185.220.101.5,10.0.0.22,401,DENIED,SSH Failed password for invalid user postgres
2026-10-16 08:15:20,WARN,198.51.100.23,10.0.0.80,404,DROP,Probing hidden endpoint /.env
2026-10-16 08:15:22,WARN,198.51.100.23,10.0.0.80,403,DROP,Probing hidden endpoint /wp-login.php
2026-10-16 08:20:01,ERROR,192.0.2.88,10.0.0.80,400,DROP,SQL Injection attempt: UNION SELECT 1=1
2026-10-16 08:25:12,ERROR,203.0.113.42,10.0.0.80,500,INTERNAL_ERROR,Backend database connection timeout`;

export function generateSampleEvtxBuffer(): ArrayBuffer {
  // Construct a minimal valid EVTX-like binary chunk with Windows Event headers
  // Header: "ElfFile\0"
  const buffer = new ArrayBuffer(8192);
  const u8 = new Uint8Array(buffer);

  // Magic "ElfFile\0"
  const magic = [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00];
  magic.forEach((byte, i) => (u8[i] = byte));

  // Chunk signature at offset 4096 "ElfChnk\0"
  const chnkMagic = [0x45, 0x6c, 0x66, 0x43, 0x68, 0x6e, 0x6b, 0x00];
  chnkMagic.forEach((byte, i) => (u8[4096 + i] = byte));

  // Write UTF-16LE Windows Security Events into the record payload
  const eventsString =
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-16T08:01:12Z"/></System>` +
    `<EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">185.220.101.5</Data><Data Name="Status">0xC000006D</Data></EventData></Event> ` +
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID></System>` +
    `<EventData><Data Name="TargetUserName">root</Data><Data Name="IpAddress">185.220.101.5</Data></EventData></Event> ` +
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID></System>` +
    `<EventData><Data Name="TargetUserName">guest</Data><Data Name="IpAddress">185.220.101.5</Data></EventData></Event> ` +
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID></System>` +
    `<EventData><Data Name="TargetUserName">sysadmin</Data><Data Name="IpAddress">192.168.1.50</Data></EventData></Event> ` +
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>7045</EventID></System>` +
    `<EventData><Data Name="ServiceName">MaliciousBackdoorSvc</Data><Data Name="ImagePath">C:\\temp\\agent.exe</Data></EventData></Event> ` +
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">` +
    `<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>1102</EventID></System>` +
    `<EventData><Data Name="Message">The audit log was cleared</Data></EventData></Event>`;

  // Encode as UTF-16LE starting at offset 4608
  let offset = 4608;
  for (let i = 0; i < eventsString.length; i++) {
    const code = eventsString.charCodeAt(i);
    u8[offset++] = code & 0xff;
    u8[offset++] = (code >> 8) & 0xff;
  }

  return buffer;
}
