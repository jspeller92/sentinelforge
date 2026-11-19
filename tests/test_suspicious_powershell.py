import json
from pathlib import Path

def is_suspicious_powershell(event):
    
    """Model the intended matching logic of the Sigma detection."""
    
    image = event.get("Image", "").lower()

    command_line = event.get("CommandLine", "").lower()

    is_powershell = image.endswith(("powershell.exe","pwsh.exe"))

    uses_hidden_window = (
        "-windowstyle hidden" in command_line
        or " -w hidden" in command_line
    )

    uses_encoded_command = (
        "-encodedcommand" in command_line
        or " -enc " in command_line
    )

    return is_powershell and (
        uses_hidden_window or uses_encoded_command
    )

def test_detects_hidden_powershell():
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -WindowStyle Hidden -File update.ps1",
    }
    assert is_suspicious_powershell(event) is True

def test_detects_encoded_powershell():
    event = {
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -EncodedCommand VwByAGkAdABlAA==",
    }
    assert is_suspicious_powershell(event) is True

def test_ignores_normal_powershell():
    event = {
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -File maintenance.ps1",
    }
    assert is_suspicious_powershell(event) is False

def test_ignores_unrelated_process():
    event = {
    "Image": r"C:\Windows\System32\notepad.exe",
    "CommandLine": "notepad.exe notes.txt",
    }
    assert is_suspicious_powershell(event) is False

def test_real_sysmon_encoded_powershell_event():
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "sysmon_encoded_powershell.json"
    )

    with open(fixture_path, encoding="utf-8)") as file:
        event = json.load(file)

    assert is_suspicious_powershell(event)

def test_real_sysmon_benign_powershell_event():
    fixture_path = (
        Path(__file__).parent/"fixtures"/"sysmon_benign_powershell.json"
    )

    with open(fixture_path, encoding="utf-8") as file:
        event = json.load(file)

    assert is_suspicious_powershell(event) is False