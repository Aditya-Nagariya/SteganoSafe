import re
from collections import defaultdict
from datetime import datetime

DATE_PATTERN = re.compile(r'(\d{4}-\d{2}-\d{2})')

def parse_logs(log_lines):
    date_level_map = defaultdict(lambda: defaultdict(int))
    for line in log_lines:
        match = DATE_PATTERN.search(line)
        parts = line.split(' - ', 2)
        if match and len(parts) > 1:
            date_str = match.group(1)
            level = parts[1].strip()
            try:
                dt = datetime.strptime(date_str, '%Y-%m-%d')
                date_str = dt.strftime('%Y-%m-%d')
                date_level_map[date_str][level] += 1
            except ValueError:
                pass
    return date_level_map