import re
import datetime
import collections

"""
Analytics module for parsing and analyzing application logs.
"""

def parse_logs(log_lines):
    """
    Parse application logs and extract useful analytics.
    
    Args:
        log_lines (list): List of log line strings to parse
        
    Returns:
        dict: Analytics data extracted from logs
    """
    data = {
        'user_logins': {},
        'errors': [],
        'registrations': 0,
        'encryptions': 0,
        'decryptions': 0,
        'requests_by_hour': collections.Counter(),
        'status_codes': collections.Counter(),
        'top_errors': collections.Counter(),
    }
    
    # Regular expressions for log parsing
    timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    login_pattern = r'User logged in.+username: ([^,]+)'
    error_pattern = r'ERROR.+: (.+)'
    
    for line in log_lines:
        # Extract timestamp if available
        ts_match = re.search(timestamp_pattern, line)
        if ts_match:
            try:
                timestamp = datetime.datetime.strptime(ts_match.group(1), '%Y-%m-%d %H:%M:%S')
                data['requests_by_hour'][timestamp.hour] += 1
            except Exception:
                pass
        
        # Track user logins
        login_match = re.search(login_pattern, line)
        if login_match:
            username = login_match.group(1)
            if username not in data['user_logins']:
                data['user_logins'][username] = 0
            data['user_logins'][username] += 1
        
        # Track registrations
        if "User registered" in line:
            data['registrations'] += 1
        
        # Track encryptions
        if "Encrypted image" in line:
            data['encryptions'] += 1
        
        # Track decryptions
        if "Message decrypted successfully" in line:
            data['decryptions'] += 1
        
        # Track HTTP status codes
        status_match = re.search(r'HTTP/\d\.\d" (\d{3})', line)
        if status_match:
            data['status_codes'][status_match.group(1)] += 1
        
        # Track errors
        error_match = re.search(error_pattern, line)
        if error_match:
            error_msg = error_match.group(1)
            data['errors'].append(error_msg)
            # Get a shorter version of the error for counting
            short_error = re.sub(r'\s+', ' ', error_msg[:50])
            data['top_errors'][short_error] += 1
    
    # Convert counters to sorted lists for the frontend
    data['requests_by_hour'] = sorted(
        [{'hour': h, 'count': c} for h, c in data['requests_by_hour'].items()],
        key=lambda x: x['hour']
    )
    data['status_codes'] = sorted(
        [{'code': k, 'count': v} for k, v in data['status_codes'].items()],
        key=lambda x: -x['count']
    )
    data['top_errors'] = sorted(
        [{'error': k, 'count': v} for k, v in data['top_errors'].items()],
        key=lambda x: -x['count']
    )[:10]  # Only return top 10
    
    # Only return the most recent 50 errors
    data['errors'] = data['errors'][-50:]
    
    return data