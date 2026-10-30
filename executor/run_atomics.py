"""
run_atomics.py - execute attack commands
Required functions: 1) receive a command and execute it on the target via pywinrm automatically;
2) fetch and return the result after execution.
"""

import winrm


def _get_credentials(target_info):
    """Use admin credentials when admin_password is available, otherwise fall back to the initial user."""
    if target_info.get("admin_password"):
        return target_info["admin_name"], target_info["admin_password"]
    return target_info["user_name"], target_info["password"]


def run_with_powershell_on_target(powershell_command, ip_address, user_name, password):
    """Run a PowerShell command via WinRM on the given IP with the given credentials."""
    session = winrm.Session(ip_address, auth=(user_name, password))
    resp = session.run_ps(powershell_command)
    return resp.std_out.decode("utf-8", errors="replace"), resp.status_code


def run_with_command_prompt_on_target(command, ip_address, user_name, password):
    """Run a CMD command via WinRM on the given IP with the given credentials."""
    session = winrm.Session(ip_address, auth=(user_name, password))
    resp = session.run_cmd(command)
    return resp.std_out.decode("utf-8", errors="replace"), resp.status_code


def run_with_powershell(powershell_command, target_info):
    user, pwd = _get_credentials(target_info)
    return run_with_powershell_on_target(powershell_command, target_info["ip_address"], user, pwd)


def run_with_command_prompt(command_prompt_command, target_info):
    user, pwd = _get_credentials(target_info)
    return run_with_command_prompt_on_target(command_prompt_command, target_info["ip_address"], user, pwd)


if __name__ == "__main__":
    """Command-line debug entry: credentials come from environment variables (see .env.example), never hardcoded."""
    import os
    import sys
    target_info = {
        "ip_address": os.getenv("TARGET_IP", ""),
        "os_version": os.getenv("TARGET_OS", "windows server 2022"),
        "user_name": os.getenv("TARGET_USER", ""),
        "password": os.getenv("TARGET_PASSWORD", ""),
        "admin_name": os.getenv("TARGET_ADMIN_USER", "Administrator"),
        "admin_password": ""
    }
    if not target_info["ip_address"]:
        print("Error: TARGET_IP / TARGET_USER / TARGET_PASSWORD not set")
        sys.exit(1)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"
    exe = sys.argv[2] if len(sys.argv) > 2 else "ps"
    if len(sys.argv) > 3:
        target_info["admin_password"] = sys.argv[3]
    if exe == "cmd":
        out, code = run_with_command_prompt(cmd, target_info)
    else:
        out, code = run_with_powershell(cmd, target_info)
    print(f"[exit_code={code}]\n{out}")
