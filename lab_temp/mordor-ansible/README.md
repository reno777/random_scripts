# mordor-ansible

Ansible playbooks for Proxmox cluster maintenance.

## Prerequisites (Mac)

```bash
brew install ansible
```

Make sure your SSH key is loaded:
```bash
ssh-add ~/.ssh/id_ed25519
```

Verify connectivity before running:
```bash
ansible proxmox_nodes -m ping
```

---

## Usage

### Run everything (repos + nosub + cluster + update) on all active nodes
```bash
ansible-playbook site.yml
```

### Fix repositories only (disable enterprise, enable no-sub trixie)
```bash
ansible-playbook site.yml --tags repos
```

### Nosub UI patch only
```bash
ansible-playbook site.yml --tags nosub
```

### Cluster create/join only
```bash
ansible-playbook site.yml --tags cluster
```

### Update packages only
```bash
ansible-playbook site.yml --tags update
```

### Target a single node
```bash
ansible-playbook site.yml --limit sauron
```

### Dry run — see what would change without doing anything
```bash
ansible-playbook site.yml --check
```

---

## Adding a New Node

1. Install Proxmox on the node
2. Copy your Mac SSH key to the node (required before Ansible can connect):
   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519.pub root@172.21.13.x
   ```
3. Uncomment the node in `inventory/hosts.ini`
4. Run the full playbook:
   ```bash
   ansible-playbook site.yml
   ```
   This will — in order, one node at a time:
   - Fix repos (disable enterprise, enable no-sub)
   - Apply the nosub UI patch
   - Distribute SSH keys across all nodes
   - Join the node to the mordor cluster
   - Update all packages and reboot if needed

That's it. Already-configured nodes skip through idempotently.

---

## How Cluster Formation Works

- **sauron** — if not already in a cluster, runs `pvecm create mordor`
- **All other nodes** — if not already a cluster member, accepts sauron's SSH host key then runs `pvecm add 172.21.13.16`
- `serial: 1` guarantees sauron is always processed first so the cluster exists before any node tries to join
- Re-running on nodes already in the cluster is safe — membership is checked first and the join step is skipped

---

## Notes

- `serial: 1` in `site.yml` ensures nodes are updated one at a time.
  This is intentional — do not change it to avoid quorum loss during reboots.
- The dpkg hook at `/etc/apt/apt.conf.d/99pve-nosub-patch` on each node
  means the nosub patch re-applies automatically after any future apt upgrade,
  even if run manually outside of Ansible.
- Nodes requiring a reboot (kernel update) will reboot automatically and
  Ansible will wait for them to come back before moving to the next node.

---

## Manual Steps (per role)

Use these to test on a single node before running the playbook across the cluster.
SSH into the target node first: `ssh root@172.21.13.x`

---

### pve-repos — Fix repositories

```bash
# Disable PVE enterprise repo
cat > /etc/apt/sources.list.d/pve-enterprise.sources << 'EOF'
Types: deb
URIs: https://enterprise.proxmox.com/debian/pve
Suites: trixie
Components: pve-enterprise
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: no
EOF

# Disable Ceph enterprise repo
cat > /etc/apt/sources.list.d/ceph.sources << 'EOF'
Types: deb
URIs: https://enterprise.proxmox.com/debian/ceph-squid
Suites: trixie
Components: enterprise
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: no
EOF

# Enable no-subscription repo
cat > /etc/apt/sources.list.d/pve-no-subscription.sources << 'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: yes
EOF

# Refresh apt cache
apt update
```

---

### pve-nosub-patch — Remove subscription popup

```bash
# Deploy patch script
cat > /usr/local/bin/pve-nosub-patch.sh << 'EOF'
#!/bin/bash
JS_FILE="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"
if [ ! -f "$JS_FILE" ]; then echo "ERROR: $JS_FILE not found"; exit 1; fi
if grep -q "no_such_method_placeholder" "$JS_FILE"; then echo "Already patched."; exit 0; fi
if [ ! -f "${JS_FILE}.orig" ]; then cp "$JS_FILE" "${JS_FILE}.orig"; fi
sed -i "s/Ext.Msg.show({/void({/g" "$JS_FILE"
echo "Patch applied."
EOF
chmod 755 /usr/local/bin/pve-nosub-patch.sh

# Deploy dpkg hook so patch survives apt upgrades
cat > /etc/apt/apt.conf.d/99pve-nosub-patch << 'EOF'
DPkg::Post-Invoke { "if [ -x /usr/local/bin/pve-nosub-patch.sh ]; then /usr/local/bin/pve-nosub-patch.sh; fi"; };
EOF

# Run patch now
/usr/local/bin/pve-nosub-patch.sh
```

---

### pve-node-setup — Per-node Proxmox setup

Run on each node after Proxmox install, before cluster join.

```bash
# Disable swap
swapoff -a
sed -i '/\sswap\s/d' /etc/fstab

# CPU performance governor
apt install -y cpufrequtils
echo 'GOVERNOR="performance"' > /etc/default/cpufrequtils
systemctl enable --now cpufrequtils

# AMD-Vi IOMMU — edit GRUB
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet amd_iommu=on iommu=pt"/' /etc/default/grub
update-grub

# Mesa OpenCL for AMD iGPU (Hashtopolis)
apt install -y mesa-opencl-icd

# Useful packages
apt install -y vim curl wget htop nvme-cli

# Reboot to apply GRUB/IOMMU changes — do this before joining the cluster
reboot
```

> Verify IOMMU is active after reboot:
> ```bash
> dmesg | grep -i iommu
> ```

---

### pve-cluster — Create or join cluster

**On sauron only (first time):**
```bash
# Verify not already in a cluster
pvecm status

# Create the cluster
pvecm create mordor --link0 172.21.13.16

# Verify
pvecm status
```

**On every other node:**
```bash
# Verify not already in a cluster
ls /etc/pve/corosync.conf   # should not exist

# Accept sauron host key
ssh-keyscan -H 172.21.13.16 >> /root/.ssh/known_hosts

# Join the cluster
pvecm add 172.21.13.16 --link0 $(hostname -I | awk '{print $1}') --use_ssh

# Wait ~45 seconds then verify
pvecm status
pvecm nodes
```

---

### pve-update — Update packages

```bash
# Install vim if not present
apt install -y vim

# Full upgrade
apt update && apt dist-upgrade -y && apt autoremove -y

# Check if reboot needed
cat /var/run/reboot-required 2>/dev/null && echo "REBOOT REQUIRED" || echo "No reboot needed"

# Reboot if needed (verify cluster health first)
pvecm status
reboot
```
