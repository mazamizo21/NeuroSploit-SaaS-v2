# 🎯 TazoSploit Comprehensive Exploitation Report

**Generated:** 2026-01-12 17:12:26

## 📊 Executive Summary

- **Vulnerabilities Exploited:** 0
- **Credentials Obtained:** 12
- **Database Access:** 2
- **Shell Access:** 0
- **Lateral Movement:** 0
- **Data Exfiltrated:** 1

## 🔑 Obtained Credentials

| Username | Password | Service | Source |
|----------|----------|---------|--------|
| extracted | <em | config file | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| extracted | www | config file | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| extracted | www | config file | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| extracted | www | config file | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| http | //www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> | extracted from output | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| http | //www.w3.org/1999/xhtml"> | extracted from output | curl -s http://10.0.2.20/dvwa/
curl -s http://10.0 |
| extracted | <em | config file | curl -s http://10.0.2.20/setup.php |
| extracted | www | config file | curl -s http://10.0.2.20/setup.php |
| extracted | www | config file | curl -s http://10.0.2.20/setup.php |
| extracted | www | config file | curl -s http://10.0.2.20/setup.php |
| http | //www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> | extracted from output | curl -s http://10.0.2.20/setup.php |
| http | //www.w3.org/1999/xhtml"> | extracted from output | curl -s http://10.0.2.20/setup.php |

## 💾 Database Access

### 1. MySQL @ localhost
- **Credentials:** `unknown`
- **Databases:** unknown
- **Tables Dumped:** 0
- **Records:** ~72

### 2. MySQL @ 127.0.0.1
- **Credentials:** `root:p@ssw0rd`
- **Databases:** unknown
- **Tables Dumped:** 0
- **Records:** ~2

## 📦 Data Exfiltration

### 1. unknown
- **Source:** `find /usr/share -name "*.txt" -path "*/wordlists/*" | head -5`
- **Size:** 206 bytes
- **Preview:**
```
/usr/share/dirb/wordlists/common.txt
/usr/share/dirb/wordlists/small.txt
/usr/share/dirb/wordlists/others/best15.txt
/usr/share/dirb/wordlists/others/best1050.txt
/usr/share/dirb/wordlists/others/names.txt

```
