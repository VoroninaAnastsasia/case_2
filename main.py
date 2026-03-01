# operation_data_shield.py

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

