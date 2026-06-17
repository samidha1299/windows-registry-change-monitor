import winreg
import json
import os
import time
from datetime import datetime

# ==========================================
# 1. CONFIGURATION: TARGET REGISTRY PATHS
# ==========================================
WATCH_PATHS = [
    {
        "hive_name": "HKEY_CURRENT_USER",
        "hive": winreg.HKEY_CURRENT_USER,
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run"
    },
    {
        "hive_name": "HKEY_CURRENT_USER",
        "hive": winreg.HKEY_CURRENT_USER,
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    },
    {
        "hive_name": "HKEY_LOCAL_MACHINE",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "path": r"Software\Microsoft\Windows\CurrentVersion\Run"
    },
    {
        "hive_name": "HKEY_LOCAL_MACHINE",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    },
    {
        "hive_name": "HKEY_LOCAL_MACHINE",
        "hive": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    }
]

SNAPSHOT_FILE = "registry_baseline.json"
LOG_FILE = "Registry_Report.txt"

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_event(message):
    print(message)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{message}\n")

# ==========================================
# 2. STEP 2 & 3: SCANNING & BASELINE CREATION
# ==========================================
def scan_registry():
    """Queries all target keys and maps values to a memory map dictionary."""
    current_state = {}
    
    for item in WATCH_PATHS:
        full_key_string = f"{item['hive_name']}\\{item['path']}"
        try:
            # Open registry key handle securely in Read-Only mode
            handle = winreg.OpenKey(item["hive"], item["path"], 0, winreg.KEY_READ)
            
            # Enumerate through all value indexes inside the key
            index = 0
            while True:
                try:
                    val_name, val_data, val_type = winreg.EnumValue(handle, index)
                    # Use a compound string key to uniquely track every property
                    unique_id = f"{full_key_string} | {val_name}"
                    current_state[unique_id] = {
                        "path": full_key_string,
                        "value_name": val_name,
                        "data": str(val_data),
                        "type": val_type
                    }
                    index += 1
                except OSError:
                    # End of registry entries reached for this key path
                    break
            winreg.CloseKey(handle)
        except Exception as e:
            # Key might not exist or lacks read rights on this machine profile
            pass
            
    return current_state

# ==========================================
# 3. STEP 4 & 5: DIFFERENTIAL CHANGE ANALYSIS
# ==========================================
def create_baseline():
    print(f"[{get_timestamp()}] Initializing Baseline Snapshot Mapping...")
    baseline = scan_registry()
    
    with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)
        
    print(f"[{get_timestamp()}] Baseline profile created successfully! Saved to '{SNAPSHOT_FILE}'")
    print(f"[*] Cataloged {len(baseline)} active registry elements.\n")
    return baseline

def monitor_registry(baseline):
    log_event(f"============================================================")
    log_event(f"[+] Continuous monitoring loop initiated. Polling interval: 5s.")
    log_event(f"============================================================")
    
    try:
        while True:
            time.sleep(5)
            current = scan_registry()
            
            # Check for Added and Modified Entries
            for uid, info in current.items():
                if uid not in baseline:
                    # Threat Behavior Classification Check
                    alert_type = "[ALERT]"
                    category = "Autorun Persistence Injection Detected"
                    if "Policies\\System" in info["path"]:
                        alert_type = "[CRITICAL]"
                        category = "User Account Control Security Policy Altered"
                        
                    log_event(f"\n{alert_type} [{get_timestamp()}] UNAUTHORIZED CHANGE DETECTED!")
                    log_event(f"    -> Category: {category}")
                    log_event(f"    -> Key Path: {info['path']}")
                    log_event(f"    -> Value Name: {info['value_name']}")
                    log_event(f"    -> Action: NEW VALUE ADDED / INJECTED")
                    log_event(f"    -> Extracted Payload: {info['data']}")
                    
                    # Update baseline to prevent alert flooding
                    baseline[uid] = info
                    
                elif baseline[uid]["data"] != info["data"]:
                    alert_type = "[ALERT]"
                    category = "Value Configuration Shift"
                    if "Policies\\System" in info["path"] and info["value_name"] == "ConsentPromptBehaviorAdmin":
                        alert_type = "[CRITICAL]"
                        category = "System UAC Security Bypass Modification"
                        
                    log_event(f"\n{alert_type} [{get_timestamp()}] MALWARE-LIKE CONFIGURATION TAMPERING DETECTED!")
                    log_event(f"    -> Category: {category}")
                    log_event(f"    -> Key Path: {info['path']}")
                    log_event(f"    -> Value Name: {info['value_name']}")
                    log_event(f"    -> Action: VALUE MODIFIED FROM BASELINE")
                    log_event(f"    -> Old Baseline Value: {baseline[uid]['data']}")
                    log_event(f"    -> New Detected Value: {info['data']}")
                    
                    baseline[uid] = info
            
            # Check for Deleted Entries
            for uid, info in list(baseline.items()):
                if uid not in current:
                    log_event(f"\n[ALERT] [{get_timestamp()}] REGISTRY INTEGRITY ANOMALY!")
                    log_event(f"    -> Key Path: {info['path']}")
                    log_event(f"    -> Value Name: {info['value_name']}")
                    log_event(f"    -> Action: AUTHORIZED KEY DELETED FROM SYSTEM")
                    
                    del baseline[uid]
                    
    except KeyboardInterrupt:
        log_event(f"\n[-] [{get_timestamp()}] Monitoring session terminated gracefully by user.")

if __name__ == "__main__":
    print("==============================================================")
    print("      WINDOWS REGISTRY CHANGE MONITORING SYSTEM (EDR SIMULATOR)  ")
    print("==============================================================\n")
    
    # If a previous baseline snapshot file exists, load it; otherwise create a fresh one
    if os.path.exists(SNAPSHOT_FILE):
        choice = input("[?] Existing baseline snapshot found. Load it? (y/n): ").strip().lower()
        if choice == 'y':
            with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
                baseline_data = json.load(f)
            print(f"[+] Loaded baseline profile with {len(baseline_data)} tracked keys.\n")
        else:
            baseline_data = create_baseline()
    else:
        baseline_data = create_baseline()
        
    monitor_registry(baseline_data)