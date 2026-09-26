# SOC-Sentine1-KQL--Lab
Microsoft Sentinel SOC L1 Investigation Lab - 15+ KQL Queries - Phishing, Brute-force, Impossible Travel detection
# SOC Sentinel KQL Lab - 50 Alerts Investigated
Tools: Microsoft Sentinel | KQL | Defender XDR | VirusTotal | AbuseIPDB

## KQL Queries

### 1. Failed Logins - Brute-force Detection
```kql
SecurityEvent | where EventID==4625 | summarize FailedCount=count() by TargetUserName | where FailedCount > 5
SigninLogs | where ResultType==0 | summarize by UserPrincipalName, Location | where Location count >1
