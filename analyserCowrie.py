import json
from collections import defaultdict
from datetime import datetime

def load_data(filename):
    """ Load JSON data from a file while filtering out entries without a destination IP. """
    with open(filename, 'r') as file:
        data = [json.loads(line.strip()) for line in file if 'dest_ip' not in line]
    return data

def parse_timestamp(timestamp):
    """ Convert ISO 8601 date strings to datetime objects. """
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None

def classify_attack(entries):
    """ Classify the type of attack based on the diversity and frequency of event types. """
    types = set(e.get('eventid') for e in entries)
    timestamps = [parse_timestamp(e['timestamp']) for e in entries if parse_timestamp(e['timestamp'])]
    timestamps.sort()

    rapid_succession = any(
        (timestamps[i] - timestamps[i - 1]).total_seconds() < 3 for i in range(1, len(timestamps))
    )

    diverse_attacks = len(types) > 2
    automated_signs = rapid_succession and diverse_attacks

    return 'Automated' if automated_signs else 'Manual'

def analyze_sessions(data):
    """ Analyze sessions to extract IPs, ports, login attempts, and commands from the JSON data. """
    results = defaultdict(lambda: {
        'sessions': set(),
        'ports': set(),
        'login_attempts': [],
        'commands': []
    })
    
    for entry in data:
        ip = entry.get('src_ip')
        session_id = entry.get('session')
        ports = {entry.get('src_port'), entry.get('dest_port')}
        
        if ip and session_id:
            results[ip]['sessions'].add(session_id)
        results[ip]['ports'].update(filter(None, ports))  # Only add non-None ports
        
        if 'username' in entry and 'password' in entry:
            results[ip]['login_attempts'].append((entry['username'], entry['password']))
        
        if 'input' in entry:
            results[ip]['commands'].append(entry['input'])

        # Classify the attack type per IP based on all their activities.
        results[ip]['attack_type'] = classify_attack([entry for entry in data if entry.get('src_ip') == ip])
    
    return results

def print_analysis(results):
    """ Print analysis results in a structured format. """
    for ip, details in results.items():
        print(f"IP: {ip}")
        print(f"Sessions: {len(details['sessions'])}")
        print(f"Ports: {', '.join(map(str, details['ports']))}")
        print(f"Attack Type: {details['attack_type']}")
        print("Login Attempts:")
        for username, password in details['login_attempts']:
            print(f"  {username}: {password}")
        print("Commands:")
        for command in details['commands']:
            print(f"  {command}")
        print("\n")

if __name__ == "__main__":
    filename = 'C:\\Users\\sylve\\Skrivebord\\AAU\\eve.json.1\\eve.json.1'
    data = load_data(filename)
    analyzed_data = analyze_sessions(data)
    print("this is somthing", analyzed_data);
    print_analysis(analyzed_data)
