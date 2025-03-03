import re
import math

def tokenize(text):
    # Extract words from text, converting to lowercase.
    return re.findall(r'\w+', text.lower())

def cosine_similarity(tokens_a, tokens_b):
    # Build frequency dictionaries for both token lists.
    vec_a = {}
    vec_b = {}
    for t in tokens_a:
        vec_a[t] = vec_a.get(t, 0) + 1
    for t in tokens_b:
        vec_b[t] = vec_b.get(t, 0) + 1
    common = set(vec_a.keys()) & set(vec_b.keys())
    score = sum(vec_a[t] * vec_b[t] for t in common)
    mag_a = math.sqrt(sum(val * val for val in vec_a.values()))
    mag_b = math.sqrt(sum(val * val for val in vec_b.values()))
    return score / (mag_a * mag_b) if mag_a and mag_b else 0

"""
Magic Box - A module for advanced analysis of log files to detect suspicious activities
"""

def detect_suspicious(log_lines):
    """
    Analyze log lines to detect suspicious activity patterns
    Returns a list of suspicious activities with their details
    """
    # This is a placeholder implementation
    suspicious = []
    
    # Look for multiple failed login attempts
    failed_logins = {}
    for i, line in enumerate(log_lines):
        if "Login failed for username" in line:
            # Extract username
            parts = line.split("Login failed for username: ")
            if len(parts) > 1:
                username = parts[1].strip()
                if username not in failed_logins:
                    failed_logins[username] = []
                failed_logins[username].append(i)
    
    # Flag users with 3+ failed login attempts
    for username, attempts in failed_logins.items():
        if len(attempts) >= 3:
            suspicious.append({
                'type': 'multiple_failed_logins',
                'username': username,
                'attempts': len(attempts),
                'line_numbers': attempts
            })
    
    # Look for potential steganography data that's too large
    for i, line in enumerate(log_lines):
        if "Message too large for image" in line:
            suspicious.append({
                'type': 'oversized_steganography',
                'line_number': i,
                'line': line.strip()
            })
    
    return suspicious