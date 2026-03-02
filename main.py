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
def find_credit_cards(text):
    correct_cards = []
    not_correct_cards = []

    rv = r'\b(?:\d[ -]*?){15}\d\b'
    would_be_cards = re.findall(rv, text)
    
    for card in would_be_cards:
        only_digits = ''
        for sym in card:
            if sym.isdigit():
                only_digits = only_digits + sym
        
        if len(only_digits) != 16:
            continue
        
        if luhn(only_digits):
            correct_cards.append(card)
        else:
            not_correct_cards.append(card)

    return {'valid': correct_cards, 'invalid': not_correct_cards}

# Функция поиска секретов
def find_secrets(text):
    all_secrets = []
    
    key1 = re.findall(r'sk_live_[a-zA-Z0-9]+', text)
    for k in key1:
        all_secrets.append(k)
        
    key2 = re.findall(r'pk_test_[a-zA-Z0-9]+', text)
    for k in key2:
        all_secrets.append(k)

    words = text.split()
    spec = '!@#$%^&*()_+-=[]{};:,.<>?/~`'
    
    for word in words:
        if len(word) >= 6:
            alph = 0
            digit = 0
            special = 0
            
            for sym in word:
                if sym.isalpha():
                    alph = 1
                if sym.isdigit():
                    digit = 1
                if sym in spec:
                    special = 1

            if alph == 1 and digit == 1 and special == 1:
                if 'sk_live_' not in word and 'pk_test_' not in word:
                    all_secrets.append(word)
    
    result = list(set(all_secrets))
    return result


# нормализовать и валидировать данные 
def normalize_and_validate(text):
    data_result = {
        'phones': {'valid':[], 'invalid':[]},
        'dates' : {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    # номер телефона 
    phone_pattern = r'(?:\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}'
    phones = re.findall(phone_pattern, text)

    for phone in phones:
        digits = re.sub(r"\D", "", phone)

        if re.fullmatch(r"7\d{10}", digits):
            data_result["phones"]["valid"].append("+" + digits)
        elif re.fullmatch(r"8\d{10}", digits):
            normalized = "7" + digits[1:]
            data_result["phones"]["valid"].append("+" + normalized)
        else:
            data_result["phones"]["invalid"].append(phone)

    # дата 
    date_pattern = r'\b\d{2}[./-]\d{2}[./-]\d{4}\b|\b\d{4}/\d{2}/\d{2}\b|\b\d{2}-[A-Za-z]{3}-\d{4}\b'
    dates = re.findall(date_pattern, text)

    for match in dates:
        date_str = ''.join(match)

        # 15.02.2024
        if re.fullmatch(r'\d{2}\.\d{2}\.\d{4}', date_str):
            day, month, year = date_str.split('.')
            data_result['dates']['normalized'].append(f'{year}-{month}-{day}')

        # 2024/02/15
        elif re.fullmatch(r'\d{4}/\d{2}/\d{2}', date_str):
            year, month, day = date_str.split('/')
            data_result['dates']['normalized'].append(f'{year}-{month}-{day}')

        # 15-Feb-2024
        elif re.fullmatch(r'\d{2}-[A-Za-z]{3}-\d{4}', date_str):
            day, month_str, year = date_str.split('-')
            months = {
                'Jan': '01','Feb': '02','Mar': '03','Apr': '04',
                'May': '05','Jun': '06','Jul': '07','Aug': '08',
                'Sep': '09','Oct': '10','Nov': '11','Dec': '12'
            }
            month = months.get(month_str, None)
            if month:
                data_result['dates']['normalized'].append(f'{year}-{month}-{day}')
            else:
                data_result['dates']['invalid'].append(date_str)

    # инн
    inn_pattern = r"\b\d{10}\b|\b\d{12}\b"
    inns = re.findall(inn_pattern, text)

    for inn in inns:
        # только форматная проверка через рег
        if re.fullmatch(r"\d{10}", inn) or re.fullmatch(r"\d{12}",inn):
            data_result["inn"]["valid"].append(inn)
        else:
            data_result["inn"]["invalid"].append(inn)

    # карты 
    card_pattern = r'\b(?:\d{4}[\s-]?){4}\b'
    cards = re.findall(card_pattern, text)

    for card in cards:
        digits = re.sub(r'\D', '', card)

        if re.fullmatch(r'\d{16}', digits) and luhn(digits):
            data_result['cards']['valid'].append(digits)
        else:
            data_result['cards']['invalid'].append(card)

    return data_result


# Поиск и расшифровка скрытых сообщений
def decode_messages(text):
    result_kripto = {'base64': [], 'hex': [], 'rot13': []}

    # Base64
    base64_pattern = r'(?:^|(?<=\s))([A-Za-z0-9+/]{8,}={0,2})(?:$|(?=\s))'
    base64_matches = re.findall(base64_pattern, text)
    seen_base64 = set()

    for encoded in base64_matches:
        encoded = encoded.strip()
        if encoded in seen_base64:
            continue
        seen_base64.add(encoded)
        # добавляем padding для корректного декодирования
        padding = '=' * (-len(encoded) % 4)
        try:
            decoded = base64.b64decode(encoded + padding, validate=True).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            decoded = None
        result_kripto['base64'].append({'encoded': encoded, 'decoded': decoded})

    # Hex 
    hex_pattern = r'\b0x[A-Fa-f0-9]+\b|\\x[A-Fa-f0-9]{2}'
    hex_matches = re.findall(hex_pattern, text)
    seen_hex = set()

    for encoded in hex_matches:
        if encoded in seen_hex:
            continue
        seen_hex.add(encoded)
        try:
            if encoded.startswith('0x'):
                decoded_bytes = bytes.fromhex(encoded[2:])
            else:  # формат \x..
                decoded_bytes = bytes.fromhex(encoded[2:])
            try:
                decoded = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                decoded = decoded_bytes
        except ValueError:
            decoded = None
        result_kripto['hex'].append({'encoded': encoded, 'decoded': decoded})

    # ROT13
    rot13_pattern = r'\b[a-zA-Z]{2,}\b'
    rot13_matches = re.findall(rot13_pattern, text)
    seen_rot13 = set()

    for word in rot13_matches:
        if word in seen_rot13:
            continue
        seen_rot13.add(word)
        decoded = codecs.decode(word, 'rot_13')
        result_kripto['rot13'].append({'encoded': word, 'decoded': decoded})

    return result_kripto

