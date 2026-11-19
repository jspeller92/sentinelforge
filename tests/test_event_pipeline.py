from sentinelforge.event_analysis import analyze_event_file
from sentinelforge.event_analysis import get_suspicious_powershell_events
from sentinelforge.event_ingestion import load_events
from sentinelforge.event_analysis import get_suspicious_powershell_findings

def test_analyze_encoded_powershell_file():
    result = analyze_event_file("tests/fixtures/sysmon_encoded_powershell.json")
    assert result == 1

def test_analyze_benign_powershell_file():
    result = analyze_event_file("tests/fixtures/sysmon_benign_powershell.json")
    assert result == 0

def test_get_suspicious_powershell_events():
    result = load_events("tests/fixtures/sysmon_encoded_powershell.json")
    matches = get_suspicious_powershell_events(result)

    assert len(matches) == 1
    assert matches[0]["Image"].lower().endswith("powershell.exe")

def test_get_benign_powershell_events():
    result = load_events("tests/fixtures/sysmon_benign_powershell.json")

    assert len(get_suspicious_powershell_events(result)) == 0

def test_get_suspicious_powershell_findings():
    result = load_events("tests/fixtures/sysmon_encoded_powershell.json")
    matches = get_suspicious_powershell_findings(result)

    assert len(matches) == 1
    assert matches[0]["reasons"][0] == "Encoded flag found"

def test_get_benign_powershell_findings():
    result = load_events("tests/fixtures/sysmon_benign_powershell.json")
    matches = get_suspicious_powershell_findings(result)

    assert matches == []

def test_multiple_suspicious_powershell_findings():
    events = [
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ABC123"
        },
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Hidden"
        }
    ]

    findings = get_suspicious_powershell_findings(events)

    assert len(findings) == 2
    assert "Encoded flag found" in findings[0]["reasons"]
    assert "Hidden window flag found" in findings[1]["reasons"]


def test_finding_with_missing_command_line():
    events = [{"Image": "powershell.exe"}]

    findings = get_suspicious_powershell_findings(events)

    assert findings == []


def test_finding_with_none_command_line():
    events = [{"Image": "powershell.exe", "CommandLine": None}]

    findings = get_suspicious_powershell_findings(events)

    assert findings == []


def test_finding_with_invalid_command_line_type():
    events = [{"Image": "powershell.exe", "CommandLine": 12345}]

    findings = get_suspicious_powershell_findings(events)

    assert findings == []

def test_detects_encoded_command_parameter():
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand VwByAGkAdABl"
    }
    findings = get_suspicious_powershell_findings([event])

    assert len(findings) == 1
    assert "Encoded flag found" in findings[0]["reasons"]

def test_does_not_detect_encoded_flag_inside_command_text():
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": """powershell.exe -Command "Write-Output '-EncodedCommand'" """
    }

    findings = get_suspicious_powershell_findings([event])

    assert findings == []