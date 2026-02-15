# Password Cracking Reference

## Hash Identification

### Tools
```
# Hashcat built-in identifier
hashcat --identify hash.txt

# hashid
hashid -m 'aab3238922bcc25a6f606eb525ffdc56'     # Suggests hashcat mode
hashid -m hash.txt

# name-that-hash (more accurate)
nth --text 'aab3238922bcc25a6f606eb525ffdc56'
nth --file hash.txt
```

### Common Hashcat Modes
```
Mode   | Hash Type                  | Example
-------|----------------------------|---------------------------
0      | MD5                        | aab3238922bcc25a6f606eb525
100    | SHA1                       | da39a3ee5e6b4b0d3255bfef95
400    | phpass (WordPress/Drupal7) | $P$B...
500    | md5crypt (Linux)           | $1$...
1000   | NTLM                       | b4b9b02e6f09a9bd760f388b67
1400   | SHA-256                    | e3b0c44298fc1c149afbf4c8996
1700   | SHA-512                    | cf83e1357eefb8bdf1542850d66
1800   | sha512crypt (Linux)        | $6$...
2100   | Domain Cached Creds 2      | $DCC2$...
3200   | bcrypt                     | $2a$.../$2b$...
5500   | NTLMv1                     | user::domain:challenge:resp
5600   | NTLMv2                     | user::domain:challenge:resp
7500   | Kerberos 5 AS-REQ (etype23)| $krb5pa$23$...
13100  | Kerberos TGS-REP (etype23) | $krb5tgs$23$...
18200  | Kerberos AS-REP (etype23)  | $krb5asrep$23$...
19600  | Kerberos TGS-REP (etype17) | $krb5tgs$17$...
19700  | Kerberos TGS-REP (etype18) | $krb5tgs$18$...
16500  | JWT (HS256)                | eyJ...
10000  | Django PBKDF2-SHA256       | pbkdf2_sha256$...
7900   | Drupal 7                   | $S$...
```

---

## Hashcat Attack Modes

### Mode 0: Dictionary (Straight)
```
hashcat -m <mode> hash.txt wordlist.txt
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt
```

### Mode 0 + Rules: Dictionary with Rules
```
# Single rule file
hashcat -m <mode> hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Popular rule files:
# best64.rule          — fast, good coverage (77 rules)
# rockyou-30000.rule   — massive rule set
# OneRuleToRuleThemAll.rule — community favorite
# dive.rule            — deep dive, slow but thorough
# d3ad0ne.rule         — classic aggressive rules
# Hob0Rules            — leaked password pattern rules

# Multiple rule files (stacked — creates combinations)
hashcat -m <mode> hash.txt wordlist.txt -r rule1.rule -r rule2.rule

# Generate rules from cracked passwords
hashcat -m <mode> hash.txt wordlist.txt --generate-rules=1000
```

### Mode 3: Mask (Brute Force with Pattern)
```
# Mask characters:
# ?l = lowercase    ?u = uppercase    ?d = digit
# ?s = special      ?a = all          ?b = binary (0x00-0xff)

# Common patterns:
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?d?d?d           # Ullllddd (Password1)
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?l?d?d?d?s        # Ulllllddd! 
hashcat -m <mode> hash.txt -a 3 ?d?d?d?d?d?d                 # 6-digit PIN
hashcat -m <mode> hash.txt -a 3 Company?d?d?d?d              # Company0001-9999

# Increment mode (try lengths 1 through 8)
hashcat -m <mode> hash.txt -a 3 ?a?a?a?a?a?a?a?a --increment --increment-min=4

# Custom charsets
hashcat -m <mode> hash.txt -a 3 -1 ?l?d ?1?1?1?1?1?1?1?1    # lowercase+digits
hashcat -m <mode> hash.txt -a 3 -1 ABC -2 123 ?1?1?2?2       # Custom sets
```

### Mode 1: Combinator
```
# Combine words from two wordlists
hashcat -m <mode> hash.txt -a 1 wordlist1.txt wordlist2.txt
# Produces: word1word2 for every combination
```

### Mode 6/7: Hybrid (Dictionary + Mask)
```
# Append mask to dictionary words
hashcat -m <mode> hash.txt -a 6 wordlist.txt ?d?d?d?d    # word0000-word9999
hashcat -m <mode> hash.txt -a 6 wordlist.txt ?d?d?s       # word00!

# Prepend mask to dictionary words
hashcat -m <mode> hash.txt -a 7 ?d?d?d wordlist.txt       # 000word-999word
```

---

## John the Ripper

### Basic Usage
```
# Auto-detect format
john hash.txt

# Specify format
john --format=NT hash.txt --wordlist=rockyou.txt
john --format=raw-sha256 hash.txt --wordlist=rockyou.txt

# Show cracked passwords
john --show hash.txt

# With rules
john --wordlist=rockyou.txt --rules hash.txt
john --wordlist=rockyou.txt --rules=best64 hash.txt

# Incremental (brute force)
john --incremental hash.txt
john --incremental=digits hash.txt    # Digits only
```

### Format Helpers
```
# Extract hashes from various files
zip2john archive.zip > zip_hash.txt
rar2john archive.rar > rar_hash.txt
ssh2john id_rsa > ssh_hash.txt
keepass2john database.kdbx > keepass_hash.txt
office2john document.docx > office_hash.txt
pdf2john document.pdf > pdf_hash.txt
```

---

## Wordlists and Resources

### Essential Wordlists
```
# Rockyou (classic — 14M passwords)
/usr/share/wordlists/rockyou.txt

# SecLists collection
/usr/share/seclists/Passwords/
/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
/usr/share/seclists/Passwords/Leaked-Databases/

# CeWL — custom wordlist from target website
cewl -m 5 -w custom_wordlist.txt http://target.com
cewl -m 5 -w custom_wordlist.txt --with-numbers http://target.com

# CUPP — profile-based wordlist
cupp -i    # Interactive mode, enter target's personal info
```

### Custom Wordlist Enhancement
```
# Add common mutations with hashcat rules
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > enhanced.txt

# Combine wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Generate from pattern
crunch 8 8 -t Company%% -o company_wordlist.txt    # Company00-Company99
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o brute.txt
```

---

## Performance Tips

### GPU Optimization
```
# Show device info
hashcat -I

# Select specific GPU
hashcat -m <mode> hash.txt wordlist.txt -d 1

# Benchmark
hashcat -b -m <mode>

# Optimize for speed vs thoroughness
hashcat -m <mode> hash.txt wordlist.txt -w 3    # Workload profile (1=low, 3=high)
hashcat -m <mode> hash.txt wordlist.txt -O       # Optimized kernels (limits password length)
```

### Strategy Order (fastest to slowest)
```
1. Dictionary: rockyou.txt (minutes)
2. Dictionary + best64.rule (minutes-hours)
3. Dictionary + OneRuleToRuleThemAll.rule (hours)
4. Hybrid: wordlist + ?d?d?d?d (hours)
5. Mask: common patterns (hours-days)
6. Dictionary + dive.rule (days)
7. Full brute force (impractical for >8 chars)
```

---

## OPSEC Notes
- All cracking is offline — zero network traffic to target
- GPU cracking is orders of magnitude faster than CPU
- bcrypt/scrypt/Argon2 are intentionally slow — expect days not hours
- NTLM is extremely fast to crack (~100 GH/s on good GPU)
- Store cracked results: hashcat -m <mode> hash.txt --show > cracked.txt
- Use --session and --restore for long-running jobs
