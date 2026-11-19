import json
import pytest
from sentinelforge.event_ingestion import load_events

def test_load_single_event(tmp_path):
    event = {
        "EventID": 1,
        "Image": "powershell.exe"
    }

    file_path = tmp_path / "single_event.json"
    file_path.write_text(json.dumps(event))

    events = load_events(file_path)

    assert isinstance(events, list)
    assert len(events) ==1
    assert events[0]["EventID"] == 1

def test_load_multiple_events(tmp_path):

    events = [
        {
        "EventID": 4688,
        "Image": "powershell.exe"
    },
    {
        "EventID": 4624,
        "Image": "powershell.exe"
    },
    {
        "EventID": 4625,
        "Image": "powershell.exe"
    }
    ]

    file_path = tmp_path / "multiple_events.json"
    file_path.write_text(json.dumps(events))

    json_events = load_events(file_path)

    assert isinstance(json_events, list)
    assert len(json_events) == 3
    assert json_events[0]["EventID"] == 4688

def test_reject_invalid_event(tmp_path):

    events = [
        {
            "EventID": 4625,
            "Image": "powershell.exe"
        }, 
        "test"]
    
    file_path = tmp_path / "invalid_file.json"
    file_path.write_text(json.dumps(events))

    with pytest.raises(ValueError):
        load_events(file_path)


def test_reject_unsupported_json_structure(tmp_path):
    
    just_string = "This is just a string"

    file_path = tmp_path / "unsupported.json"
    file_path.write_text(json.dumps(just_string))

    with pytest.raises(ValueError):
        load_events(file_path)


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_events("missing_events.json")


def test_invalid_json(tmp_path):

    malformed_json = '{"EventID": 1, "Image": "powershell.exe"'

    file_path = tmp_path / "malformed.json"
    file_path.write_text(malformed_json)

    with pytest.raises(json.JSONDecodeError):
        load_events(file_path)



























