#!/usr/bin/env python
"""
snapshot.py - VMware VM snapshot management - for restoring the environment after a test.

vmrun and VMX paths are read from environment variables (VMWARE_RUN / VMX_PATH, see .env.example);
no local path is hardcoded. This module is optional: harness calls it before each experiment
via the EnvironmentResetter adapter; when unconfigured it returns False and continues.
"""

import subprocess
import os


def _vmrun():
    return os.getenv("VMWARE_RUN", "")


def _vmx():
    return os.getenv("VMX_PATH", "")


def revert_snapshot(snapshot_name="ready"):
    """Revert to the given snapshot (default 'ready'). Returns False when paths are unconfigured."""
    vmrun, vmx = _vmrun(), _vmx()
    if not vmrun or not vmx:
        print("[snapshot] VMWARE_RUN/VMX_PATH not set, skipping snapshot revert")
        return False
    cmd = f'"{vmrun}" revertToSnapshot "{vmx}" "{snapshot_name}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"reverted to snapshot: {snapshot_name}")
    else:
        print(f"revert failed: {result.stderr}")
    return result.returncode == 0


def start_vm():
    """Start the VM."""
    vmrun, vmx = _vmrun(), _vmx()
    if not vmrun or not vmx:
        print("[snapshot] VMWARE_RUN/VMX_PATH not set, skipping start")
        return False
    cmd = f'"{vmrun}" start "{vmx}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("VM started")
    else:
        print(f"start failed: {result.stderr}")
    return result.returncode == 0


def stop_vm():
    """Shut down the VM."""
    vmrun, vmx = _vmrun(), _vmx()
    if not vmrun or not vmx:
        print("[snapshot] VMWARE_RUN/VMX_PATH not set, skipping stop")
        return
    cmd = f'"{vmrun}" stop "{vmx}"'
    subprocess.run(cmd, shell=True, capture_output=True, text=True)


def get_snapshots():
    """List all snapshots."""
    vmrun, vmx = _vmrun(), _vmx()
    if not vmrun or not vmx:
        print("[snapshot] VMWARE_RUN/VMX_PATH not set")
        return
    cmd = f'"{vmrun}" listSnapshots "{vmx}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)


if __name__ == "__main__":
    # Usage example: set VMWARE_RUN/VMX_PATH env vars, then run
    revert_snapshot("ready")
    start_vm()
