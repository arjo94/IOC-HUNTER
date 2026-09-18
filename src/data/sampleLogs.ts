import { LogSample } from '../types';

export const SAMPLE_LOGS: LogSample[] = [
  {
    id: 'apache-web',
    name: '1. Apache Web Server (Infección Web & C2)',
    format: 'plain',
    description: 'Tráfico HTTP/HTTPS con accesos a webshells, descarga de cargas maliciosas y peticiones a IPs y dominios de URLhaus y Feodo.',
    content: `192.168.1.45 - - [16/Mar/2026:08:14:22 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
194.26.29.112 - - [16/Mar/2026:08:15:01 +0000] "POST /wp-login.php HTTP/1.1" 401 1234 "-" "Python-urllib/3.8"
194.26.29.112 - - [16/Mar/2026:08:15:05 +0000] "POST /wp-login.php HTTP/1.1" 401 1234 "-" "Python-urllib/3.8"
10.0.4.12 - - [16/Mar/2026:08:18:44 +0000] "GET /download?src=http://update-win-security.com/payloads/svchost_updater.exe HTTP/1.1" 200 84920 "-" "PowerShell/7.2"
10.0.4.12 - - [16/Mar/2026:08:20:10 +0000] "CONNECT 185.220.101.5:8080 HTTP/1.1" 200 1482 "-" "Qakbot-Beacon/4.1"
192.168.1.100 - - [16/Mar/2026:08:22:33 +0000] "GET /assets/style.css HTTP/1.1" 200 1204 "http://company.internal/dashboard" "Chrome/122.0.0.0"
103.145.13.84 - - [16/Mar/2026:08:25:12 +0000] "POST /xmlrpc.php HTTP/1.1" 403 294 "-" "curl/7.68.0"
10.0.4.12 - - [16/Mar/2026:08:31:00 +0000] "POST /api/telemetry HTTP/1.1" 200 48 "http://cdn-cloud-storage-auth.top" "Mozilla/5.0"
172.16.2.80 - - [16/Mar/2026:08:35:19 +0000] "GET /login HTTP/1.1" 302 0 "https://billing-portal-internal.online/auth" "Mozilla/5.0"
10.0.4.15 - - [16/Mar/2026:08:40:02 +0000] "GET /setup.ps1 HTTP/1.1" 200 3241 "https://cdn-cloud-storage-auth.top/certs/tunnel.ps1" "curl/8.1.2"`
  },
  {
    id: 'firewall-csv',
    name: '2. Firewall Egress Traffic (CSV)',
    format: 'csv',
    description: 'Exportación de logs de firewall perimetral con tráfico saliente, puertos de destino y hashes de archivos interceptados.',
    content: `timestamp,source_ip,dest_ip,dest_port,protocol,action,file_sha256,application
2026-03-16T09:00:12Z,10.20.1.15,8.8.8.8,53,UDP,ALLOW,,DNS
2026-03-16T09:01:04Z,10.20.1.44,185.220.101.5,8080,TCP,ALLOW,,Unknown-App
2026-03-16T09:02:15Z,10.20.1.88,45.154.255.89,443,TCP,ALLOW,,CobaltStrike-SSL
2026-03-16T09:04:22Z,10.20.1.12,198.51.100.42,443,TCP,DENY,,Rclone-Sync
2026-03-16T09:05:30Z,10.20.1.44,1.1.1.1,53,UDP,ALLOW,,DNS
2026-03-16T09:07:11Z,10.20.1.99,91.240.118.172,23,TCP,DENY,,Telnet
2026-03-16T09:08:45Z,10.20.1.44,192.168.1.1,443,TCP,ALLOW,,Internal-Web
2026-03-16T09:12:00Z,10.20.1.15,93.184.216.34,443,TCP,ALLOW,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,HTTP-Download
2026-03-16T09:14:19Z,10.20.1.22,142.250.190.46,443,TCP,ALLOW,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Google-Services`
  },
  {
    id: 'syslog-json',
    name: '3. Linux SIEM Syslog (JSON)',
    format: 'json',
    description: 'Registros de autenticación y auditoría del sistema (sshd, sudoers) con intentos de acceso no autorizados y hashes.',
    content: `[
  {
    "timestamp": "2026-03-16T10:11:00Z",
    "host": "srv-prod-db01",
    "facility": "auth",
    "event": "sshd_failed_password",
    "user": "root",
    "src_ip": "194.26.29.112",
    "message": "Failed password for invalid user admin from 194.26.29.112 port 48212 ssh2"
  },
  {
    "timestamp": "2026-03-16T10:11:03Z",
    "host": "srv-prod-db01",
    "facility": "auth",
    "event": "sshd_failed_password",
    "user": "postgres",
    "src_ip": "194.26.29.112",
    "message": "Failed password for postgres from 194.26.29.112 port 48218 ssh2"
  },
  {
    "timestamp": "2026-03-16T10:14:50Z",
    "host": "srv-app-gateway",
    "facility": "audit",
    "event": "binary_execution",
    "path": "/tmp/loader.dll",
    "file_hash": "d0e8284e314e191ecea330e704873262d1645e9a4f4ef179b32c028e08d6d9bf",
    "executed_by": "www-data",
    "message": "Dynamic library injection detected into process svchost"
  },
  {
    "timestamp": "2026-03-16T10:20:11Z",
    "host": "srv-app-gateway",
    "facility": "syslog",
    "event": "outbound_connection",
    "destination": "api-sync-telemetry.xyz",
    "message": "Outbound DNS resolution query for api-sync-telemetry.xyz succeeded"
  }
]`
  },
  {
    id: 'incident-notes',
    name: '4. Notas de Triaje SOC (Texto Plano con Defanging)',
    format: 'plain',
    description: 'Notas de un analista L2 con indicadores en formato seguro ("defanged") como hxxp, [.] y hashes de muestra para verificación.',
    content: `CASO DE INCIDENTE #2026-03-IR-9912
Analista: SOC Lead Triage
Fecha: 2026-03-16

Evidencia encontrada en el endpoint WIN-DEV-08:
- Usuario reportó descarga de actualización sospechosa desde hxxp[://]update-win-security[.]com/payloads/svchost_updater[.]exe
- Comunicación de red saliente hacia la IP 185[.]220[.]101[.]5 en el puerto 8080.
- Servidor secundario de mando y control detectado: 45.154.255.89 (perfil Cobalt Strike).
- Muestra ejecutada con hash MD5: 84c82835a5d21bbcf75a61706d8ab549
- Hash SHA256 del dropper secundario: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
- Se intentó conectar también a billing-portal-internal[.]online para cosechar credenciales O365.
- La IP 192.168.1.10 es la máquina interna de la víctima y no debe bloquearse en el perímetro.`
  }
];
