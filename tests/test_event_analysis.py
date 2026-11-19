from sentinelforge.event_analysis import count_powershell_events, count_encoded_powershell_events, get_powershell_suspicion_reasons, encoded_command_flags, hidden_window_command_flags, hidden_window_values


def test_counts_powershell():
    events = [
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Hidden"
        }
    ]

    assert count_powershell_events(events) == 1

def test_counts_pwsh():
    events = [
        {
            "Image": "pwsh.exe",
            "CommandLine": "pwsh.exe -EncodedCommand ABC123"
        }
    ]

    assert count_powershell_events(events) == 1


def test_counts_full_windows_path():
    events=[
        {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Hidden"
        }
        ]

    assert count_powershell_events(events) == 1

def test_counts_mixed_case():
    events=[
        {
            "Image": "C:\\Windows\\System32\\POWERSHELL.EXE",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Hidden"
        }
    ]
    assert count_powershell_events(events) == 1

def test_handles_missing_image():
    events=[
        {
            "CommandLine": "POWERSHELL.EXE -WindowStyle Hidden"
        }
    ]
    assert count_powershell_events(events) == 0

def test_handles_none_image():
    events=[
        {
            "Image": None
        }
    ]
    assert count_powershell_events(events) == 0

def test_handles_invalid_image_type():
    events=[
        {
            "Image": 123,
        }
    ]
    assert count_powershell_events(events) == 0

def test_counts_encoded_powershell():
    events=[
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ABC123"
        }
    ]
    assert count_encoded_powershell_events(events) == 1

def test_counts_mixed_events():
    events=[
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand ABC123"
        },
        {
            "Image": "pwsh.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Hidden"
        },
        {
            "Image": "cmd.exe",
            "CommandLine": "ipconfig"
        }
    ]
    assert count_encoded_powershell_events(events) == 1

def test_missing_CommandLine():
    events=[
        {
            "Image": "powershell.exe",
        }
    ]
    assert count_encoded_powershell_events(events) == 0

def test_case_insensitive():
    events=[
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -ENCODEDCOMMAND ABC123"
        },
        {
            "Image": "pwsh.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Hidden"
        }
    ]
    assert count_encoded_powershell_events(events) == 1

def test_count_encoded_powershell_events():
    events = [
        {
            "Image": "pwsh.exe",
            "CommandLine": "powershell.exe -encodedcommand"
        }
    ]

    assert count_encoded_powershell_events(events) == 1

def test_count_hidden_powershell_events():
    events = [
        {
            "Image": "pwsh.exe",
            "CommandLine": "pwsh.exe -NoProfile -WindowStyle Hidden"
        }
    ]

    assert get_powershell_suspicion_reasons(events[0]) == ['Hidden window flag found']

def test_rejects_similarly_named_executable():
    event = {
        "Image": r"C:\Temp\maliciouspowershell.exe"
    }
    assert count_powershell_events([event]) == 0

def test_encoded_command_flags():
    for flag in encoded_command_flags:
        event = {
            "Image": "pwsh.exe",
            "CommandLine": f"pwsh.exe -NoProfile {flag}"
        }
        
        result = get_powershell_suspicion_reasons(event)
        assert result == ["Encoded flag found"]

def test_hidden_window_command_flags():
    for flag in hidden_window_command_flags:
        event = {
            "Image": "pwsh.exe",
            "CommandLine": f"pwsh.exe -NoProfile {flag} {hidden_window_values[0]}"
        }
        result = get_powershell_suspicion_reasons(event)
        assert result == ["Hidden window flag found"]

def test_non_suspicious_window_flags():
    events=[
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -WindowStyle Maximized"
        },
        {
            "Image": "pwsh.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Normal"
        },
        {
            "Image": "cmd.exe",
            "CommandLine": "ipconfig"
        },
        {
            "Image": "pwsh.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Minimized"
        },
    ]
    for event in events:
        result = get_powershell_suspicion_reasons(event)
        assert result == []

def test_no_hidden_flag():
    event = {
        "Image": "powershell.exe",
        "CommandLine": "POWERSHELL.EXE -WindowStyle"
    }
    result = get_powershell_suspicion_reasons(event)
    assert result == []

def test_hidden_flag_out_of_place():
    event={
        "Image": "pwsh.exe",
        "CommandLine": "pwsh.exe -Command \"Write-Output hidden\""
    }
    result = get_powershell_suspicion_reasons(event)
    assert result == []

def test_combined_findings():
    event = {
        "Image": "powershell.exe",
        "CommandLine": "powershell.exe -encodedcommand ABC123 -WindowStyle Hidden"
    }
    result = get_powershell_suspicion_reasons(event)
    assert result == ["Encoded flag found", "Hidden window flag found"]

def test_multiple_powershell_events():
    events=[
        {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -encodedcommand ABC123"
        },
        {
            "Image": "pwsh.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Hidden"
        },
        {
            "Image": "powershell.exe",
            "CommandLine": "POWERSHELL.EXE -WindowStyle Minimized"
        },
    ]
    
    expected_results = [["Encoded flag found"],["Hidden window flag found"],[]]
    
    for event, expected in zip(events,expected_results):
        result = get_powershell_suspicion_reasons(event)
        assert result == expected

def test_duplicate_flags():
    event = {
        "Image": "powershell.exe",
        "CommandLine": "powershell.exe -encodedcommand -encoded ABC123 -w Hidden -WindowStyle Hidden"
    }
    result = get_powershell_suspicion_reasons(event)
    assert result == ["Encoded flag found", "Hidden window flag found"]

def test_malformed_command_line():
    event = {
        "Image": "powershell.exe",
        "CommandLine": ' powershell.exe -Command "Write-Output hello'
    }
    result = get_powershell_suspicion_reasons(event)
    assert result == []