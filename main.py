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

    result_info = {}

    # Emails
    emails = list(dict.fromkeys(re.findall(email_pattern, text)))
    result_info['emails'] = emails

    # IPs
    ips = list(dict.fromkeys(re.findall(ip_pattern, text)))
    result_info['ips'] = ips

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
    result_info['files'] = list(dict.fromkeys(valid_files))

    return result_info

# Функция проверки Луна
def luhn(card_num):
    digits = []
    for sym in card_num:
        if sym.isdigit():
            digits.append(int(sym))
            
    if len(digits) != 16:
        return False

    reversed_digits = []
    for i in range(len(digits)-1, -1, -1):
        reversed_digits.append(digits[i])

    total = 0
    for index in range(len(reversed_digits)):
        digit = reversed_digits[index]

        if index % 2 == 1:
            digit = digit * 2
            if digit > 9:
                digit = digit - 9 
        
        total = total + digit
        
    if total % 10 == 0:
        return True
    else:
        return False

# Функция поиска банковских карт
def find_and_validate_credit_cards(text):
    pravilnye_karty = []
    nepravilnye_karty = []

    rv = r'\b(?:\d[ -]*?){15}\d\b'
    vse_potencialnye_karty = re.findall(rv, text)
    
    for karta in vse_potencialnye_karty:
        tolko_cifry = ''
        for sym in karta:
            if sym.isdigit():
                tolko_cifry = tolko_cifry + sym
        
        if len(tolko_cifry) != 16:
            continue
        
        if proverka_luna(tolko_cifry):
            pravilnye_karty.append(karta)
        else:
            nepravilnye_karty.append(karta)

    return {'valid': pravilnye_karty, 'invalid': nepravilnye_karty}

# Функция поиска секретов
def find_secrets(text):
    vse = []
    
    key1 = re.findall(r'sk_live_[a-zA-Z0-9]+', text)
    for k in key1:
        vse.append(k)
        
    key2 = re.findall(r'pk_test_[a-zA-Z0-9]+', text)
    for k in key2:
        vse.append(k)

    slova = text.split()
    spec = '!@#$%^&*()_+-=[]{};:,.<>?/~`'
    
    for slovo in slova:
        if len(slovo) >= 8:
            buk = 0
            cif = 0
            spc = 0
            
            for s in slovo:
                if s.isalpha():
                    buk = 1
                if s.isdigit():
                    cif = 1
                if s in spec:
                    spc = 1

            if buk == 1 and cif == 1 and spc == 1:
                if 'sk_live_' not in slovo and 'pk_test_' not in slovo:
                    vse.append(slovo)
    
    result = list(set(vse))
    return resault
