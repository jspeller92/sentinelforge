import json

def load_events(file_path):
    try:
        with open(file_path,"r") as file:
            events = json.load(file)
            
    except FileNotFoundError as error:
        raise FileNotFoundError("Security event file was not found") from error
    
    except json.JSONDecodeError as error:
        raise

    except PermissionError as error:
         raise PermissionError("Permission denied when accessing security event file") from error
      
    if isinstance(events,dict):
        events = [events]
    elif not isinstance(events,list):
        raise ValueError("Invalid format")
    
    if not all(isinstance(data, dict) for data in events):
        raise ValueError("Invalid format")
    
    return events

    
