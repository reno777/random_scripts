#!/bin/bash
# pve-nosub-patch.sh
# Patches the Proxmox no-subscription popup out of the web UI.
# Safe to run multiple times — checks if already patched before applying.
# Automatically re-applied after apt upgrades via the dpkg hook.

JS_FILE="/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js"

if [ ! -f "$JS_FILE" ]; then
  echo "ERROR: $JS_FILE not found — is this a Proxmox node?"
  exit 1
fi

# Check if already patched
if grep -q "no_such_method_placeholder" "$JS_FILE"; then
  echo "Already patched — nothing to do."
  exit 0
fi

# Backup original before first patch
if [ ! -f "${JS_FILE}.orig" ]; then
  cp "$JS_FILE" "${JS_FILE}.orig"
  echo "Backup created: ${JS_FILE}.orig"
fi

# Apply patch — replaces the subscription check function call with a no-op
sed -i "s/Ext.Msg.show({/void({/g" "$JS_FILE"

echo "Patch applied to $JS_FILE"
