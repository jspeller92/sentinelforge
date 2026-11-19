from sentinelforge.event_ingestion import load_events
import ntpath
import shlex

encoded_command_flags = [
    "-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encode",
    "-encoded", "-encodedc", "-encodedco", "-encodedcom", "-encodedcomm",
    "-encodedcomma", "-encodedcomman", "-encodedcommand"
]

hidden_window_command_flags = [
    "-w", "-wi", "-win", "-wind", "-windo", "-window", "-windows", "-windowst", "-windowsty", 
    "-windowstyl", "-windowstyle"
]

hidden_window_values = [
    "hidden"
]

def count_powershell_events(events):
    count = 0
    for event in events:
        if is_powershell_process(event):
            count +=1
    return count

def count_encoded_powershell_events(events):
    count = 0
    for event in events:

        if is_powershell_process(event):
            reasons = get_powershell_suspicion_reasons(event)
            if "Encoded flag found" in reasons:
                count += 1

    return count

def count_suspicious_powershell_events(events):
    
    count = 0

    for event in events:
        is_suspicious = is_suspicious_powershell(event)
        if is_suspicious:
            count+=1

    return count

def analyze_event_file(file_path):
    events = load_events(file_path)
    suspicious_events = count_suspicious_powershell_events(events)

    return suspicious_events

def get_suspicious_powershell_events(events):
    matches = []
    for event in events:
        if is_suspicious_powershell(event):
            matches.append(event)

    return matches

def is_powershell_process(event):
    image = event.get("Image") or ""

    if not isinstance(image, str):
        return False

    image_basename = ntpath.basename(image).lower()

    return image_basename in ("powershell.exe", "pwsh.exe")

def get_suspicious_powershell_findings(events):
    findings = []

    for event in events:
        if not is_powershell_process(event):
            continue

        reasons = get_powershell_suspicion_reasons(event)

        if reasons:
            finding = {
                "event": event,
                "reasons": reasons
            }

            findings.append(finding)

    return findings

def get_powershell_suspicion_reasons(event):
    reasons = []

    command_line = event.get("CommandLine") or ""

    if not isinstance(command_line,str):
        return reasons
    
    command_line = command_line.lower()
    
    try: 
        arguments = shlex.split(command_line, posix=False)
    except ValueError:
        return reasons

    

    for argument in arguments:
        if 'Encoded flag found' in reasons:
            continue
        if argument in encoded_command_flags:
            reasons.append('Encoded flag found')
    
    x = 0
    while x < len(arguments) - 1:
        if 'Hidden window flag found' in reasons:
            x += 1
            continue
        if arguments[x] in hidden_window_command_flags and arguments[x+1] == hidden_window_values[0]:
            reasons.append("Hidden window flag found")
        x+=1

    return reasons

def is_suspicious_powershell(event):
    return (
        is_powershell_process(event)
        and bool(get_powershell_suspicion_reasons(event))
    )
