import json
from collections import defaultdict
from datetime import datetime

def load_data(filename):
    """ Load JSON data from a file with error handling for malformed JSON. """
    data = []
    with open(filename, 'r') as file:
        for line_number, line in enumerate(file, 1):
            try:
                data.append(json.loads(line.strip()))
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON on line {line_number}: {e}")
    return data 

def parse_timestamp(timestamp):
    """ Convert ISO 8601 date strings to datetime objects, considering timezone. """
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None

def analyze_sessions(data):
    """ Analyze sessions to extract IP, port, protocol, and alert details from the JSON data. """
    results = defaultdict(lambda: {
        'sessions': set(),
        'ports': set(),
        'protocols': set(),
        'alerts': []
    })
    
    for entry in data:
        src_ip = entry.get('src_ip')
        dest_ip = entry.get('dest_ip')
        src_port = entry.get('src_port')
        dest_port = entry.get('dest_port')
        protocol = entry.get('proto')
        alert = entry.get('alert', {})
        
        if src_ip and dest_ip:
            session_key = (src_ip, dest_ip, src_port, dest_port)
            results[session_key]['sessions'].add(session_key)
            results[session_key]['ports'].update({src_port, dest_port})
            results[session_key]['protocols'].add(protocol)
            results[session_key]['alerts'].append({
                'action': alert.get('action'),
                'signature': alert.get('signature'),
                'category': alert.get('category'),
                'severity': alert.get('severity')
            })
    
    return results

def print_analysis(results):
    """ Print analysis results in a structured format. """
    for (src_ip, dest_ip, src_port, dest_port), details in results.items():
        print(f"Session between {src_ip}:{src_port} and {dest_ip}:{dest_port}")
        print(f"Protocols: {', '.join(details['protocols'])}")
        print("Alerts:")
        for alert in details['alerts']:
            print(f"  Action: {alert['action']}, Signature: {alert['signature']}")
            print(f"  Category: {alert['category']}, Severity: {alert['severity']}")
        print("\n")

if __name__ == "__main__":
    filename = 'C:\\Users\\sylve\\Skrivebord\\AAU\\eve.json.1\\eve.json.1'
    data = load_data(filename)
    analyzed_data = analyze_sessions(data)
    print_analysis(analyzed_data)
