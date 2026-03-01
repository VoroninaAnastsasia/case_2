# operation_data_shield.py

import re

# Анализирует логи веб-сервера на предмет атак
def analyze_logs(log_text):
    patterns = {
        
        # sql-инъекции
        'sql_injections': re.compile(
            r"(\bUNION\b.*\bSELECT\b|\bOR\b\s+1=1|\bDROP\b\s+\bTABLE\b|\bSELECT\b.*\bFROM\b)",
            re.IGNORECASE
        ),

        # XSS-атаки
        'xss_attempts':re.compile(
            r"(<script.*?>.*?</script>|javascript:onerror\s*=|onload\s*=)",
            re.IGNORECASE
        ),

        # подозрительные user-agent
        'suspicious_user_agents':re.compile(
            r"(sqlmap|curl|wget|python-requests|nikto|nmap|bot)",
            re.IGNORECASE
        ),

        # неудачные входы
        'failed_logins':re.compile(
            r"(401|failed\s+login|invalid\s+password|authentication\s+failed)",
            re.IGNORECASE
        )
    }


    log_results = {}

    lines = log_text.split('\n')

    for key, pattern in patterns.items():
        found_lines = []

        for line in lines:
            if pattern.search(line):
                found_lines.append(line)

        log_results[key] = {
            'count': len(set(found_lines)),
            'items': list(set(found_lines))
        }

    return log_results


# Поиск email, IPv4 и файлов
def extract_system_info(text):
    email_pattern = (
        r'(?<!\S)[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*@'
        r'(?:[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\.)+[A-Za-z]{2,6}'
        r'(?=\s|$|[,;])'
    )

    ip_pattern = (
        r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'
        r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])'
    )

    file_pattern = (
        r'(?<!\S)[\w\-]+(?:\.[\w\-]+)*\.(?:txt|log|csv|json|xml|pdf|docx?)'
        r'(?=\s|$|[,;\'"])'
    )

    result = {}

    # Emails
    emails = list(dict.fromkeys(re.findall(email_pattern, text)))
    result['emails'] = emails

    # IPs
    ips = list(dict.fromkeys(re.findall(ip_pattern, text)))
    result['ips'] = ips

    # Files с фильтрацией некорректных имен
    file_candidates = re.findall(file_pattern, text)
    valid_files = []
    # фильтруем некорректные имена файлов (точка в начале/конце, двойные точки)
    for file_name in file_candidates:
        base_name = file_name.rsplit('.', 1)[0]
        invalid_name = (
            base_name.startswith('.') or
            base_name.endswith('.') or
            '..' in base_name
        )
        if invalid_name:
            continue
        valid_files.append(file_name)
    result['files'] = list(dict.fromkeys(valid_files))

    return result
