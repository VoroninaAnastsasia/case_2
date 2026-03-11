# operation_data_shield.py

import re
import base64
import codecs
import json

def analyze_logs(log_text):
    patterns = {
        'sql_injections': re.compile(
            r"(\bUNION\b\s+ALL?\s+\bSELECT\b|\bOR\b\s+1\s*=\s*1|\bDROP\b\s+TABLE\b|--|\bINSERT\b\s+INTO\b.*\bVALUES\b\s*\()",
            re.IGNORECASE
        ),
        'xss_attempts': re.compile(
            r"(<script.*?>.*?</script>|javascript:onerror\s*=|onload\s*=)",
            re.IGNORECASE
        ),
        'suspicious_user_agents': re.compile(
            r"(sqlmap|curl|wget|python-requests|nikto|nmap|bot)",
            re.IGNORECASE
        ),
        'failed_logins': re.compile(
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
    emails = list(dict.fromkeys(re.findall(email_pattern, text)))
    ips = list(dict.fromkeys(re.findall(ip_pattern, text)))
    file_candidates = re.findall(file_pattern, text)
    valid_files = []
    for file_name in file_candidates:
        base_name = file_name.rsplit('.', 1)[0]
        if base_name.startswith('.') or base_name.endswith('.') or '..' in base_name:
            continue
        valid_files.append(file_name)
    result_info['emails'] = emails
    result_info['ips'] = ips
    result_info['files'] = list(dict.fromkeys(valid_files))
    return result_info

def luhn(card_num):
    digits = [int(sym) for sym in card_num if sym.isdigit()]
    if len(digits) != 16:
        return False
    reversed_digits = digits[::-1]
    total = 0
    for index, digit in enumerate(reversed_digits):
        if index % 2 == 1:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

def find_credit_cards(text):
    correct_cards = []
    not_correct_cards = []
    rv = r'\b(?:\d[ -]*?){15}\d\b'
    would_be_cards = re.findall(rv, text)
    for card in would_be_cards:
        only_digits = ''.join([c for c in card if c.isdigit()])
        if len(only_digits) != 16:
            continue
        if luhn(only_digits):
            correct_cards.append(card)
        else:
            not_correct_cards.append(card)
    return {'valid': correct_cards, 'invalid': not_correct_cards}

def find_secrets(text):
    all_secrets = []
    all_secrets += re.findall(r'sk_live_[a-zA-Z0-9]+', text)
    all_secrets += re.findall(r'pk_test_[a-zA-Z0-9]+', text)
    words = text.split()
    spec = '!@#$%^&*()_+-=[]{};:,.<>?/~`'
    
    base64_pattern = r'^[A-Za-z0-9+/]{20,}=*$'
    
    for word in words:
        if len(word) >= 6:
            if re.match(base64_pattern, word):
                continue
                
            alph = any(c.isalpha() for c in word)
            digit = any(c.isdigit() for c in word)
            special = any(c in spec for c in word)
            if alph and digit and special and 'sk_live_' not in word and 'pk_test_' not in word:
                all_secrets.append(word)
                
    seen = set()
    unique_secrets = []
    for secret in all_secrets:
        if secret not in seen:
            seen.add(secret)
            unique_secrets.append(secret)
    return unique_secrets

def normalize_and_validate(text):
    data_result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }
    # телефоны
    phone_pattern = r'(?:\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}'
    phones = re.findall(phone_pattern, text)
    for phone in phones:
        digits = re.sub(r'\D', '', phone)
        if re.fullmatch(r"7\d{10}", digits):
            data_result["phones"]["valid"].append("+" + digits)
        elif re.fullmatch(r"8\d{10}", digits):
            normalized = "7" + digits[1:]
            data_result["phones"]["valid"].append("+" + normalized)
        else:
            data_result["phones"]["invalid"].append(phone)
    # даты
    date_pattern = r'\b\d{2}[./-]\d{2}[./-]\d{4}\b|\b\d{4}/\d{2}/\d{2}\b|\b\d{2}-[A-Za-z]{3}-\d{4}\b'
    dates = re.findall(date_pattern, text)
    for match in dates:
        date_str = ''.join(match)
        if re.fullmatch(r'\d{2}\.\d{2}\.\d{4}', date_str):
            day, month, year = date_str.split('.')
            data_result['dates']['normalized'].append(f'{year}-{month}-{day}')
        elif re.fullmatch(r'\d{4}/\d{2}/\d{2}', date_str):
            year, month, day = date_str.split('/')
            data_result['dates']['normalized'].append(f'{year}-{month}-{day}')
        elif re.fullmatch(r'\d{2}-[A-Za-z]{3}-\d{4}', date_str):
            day, month_str, year = date_str.split('-')
            months = {'Jan':'01','Feb':'02','Mar':'03','Apr':'04','May':'05','Jun':'06',
                      'Jul':'07','Aug':'08','Sep':'09','Oct':'10','Nov':'11','Dec':'12'}
            month = months.get(month_str)
            if month:
                data_result['dates']['normalized'].append(f'{year}-{month}-{day}')
            else:
                data_result['dates']['invalid'].append(date_str)
    # ИНН
    inn_pattern = r"\b\d{10}\b|\b\d{12}\b"
    inns = re.findall(inn_pattern, text)
    for inn in inns:
        if re.fullmatch(r"\d{10}", inn) or re.fullmatch(r"\d{12}", inn):
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


def decode_messages(text):
    seen_base64 = set()
    seen_hex = set()
    seen_rot13 = set()
    output_lines = []

    base64_pattern = r'[A-Za-z0-9+/]{20,}(?:={0,2})'
    for encoded in re.findall(base64_pattern, text):
        if encoded in seen_base64:
            continue
        if re.match(r'^[A-Za-z0-9+/]+=*$', encoded) and len(encoded) % 4 == 0:
            try:
                decoded_bytes = base64.b64decode(encoded, validate=True)
                decoded_str = decoded_bytes.decode('utf-8')
                if all(ord(c) < 128 and c.isprintable() for c in decoded_str):
                    seen_base64.add(encoded)
                    output_lines.append(f"Base64 encoded: {encoded}")
                    output_lines.append(f"Base64 decoded: {decoded_str}")
            except Exception:
                continue

    hex_pattern = r'(?:\\x[a-fA-F0-9]{2})+'
    for encoded in re.findall(hex_pattern, text):
        if encoded in seen_hex:
            continue
        try:
            hex_str = encoded.replace('\\x', '')
            if len(hex_str) % 2 == 0:
                decoded_bytes = bytes.fromhex(hex_str)
                decoded_str = decoded_bytes.decode('utf-8', errors='replace')
                if all(ord(c) < 128 and c.isprintable() for c in decoded_str) and len(decoded_str) > 2:
                    seen_hex.add(encoded)
                    output_lines.append(f"HEX encoded: {encoded}")
                    output_lines.append(f"HEX decoded: {decoded_str}")
        except Exception:
            continue
        
    rot13_examples = [
        (r'Gur\s+cnffjbeq\s+vf\s+\S+', 'The password is'),
        (r'Guvf\s+vf\s+n\s+\S+', 'This is a'),
        (r'Fbzr\S+\s+vf\s+\S+', 'Something is'),
    ]

    for pattern, hint in rot13_examples:
        for match in re.finditer(pattern, text):
            encoded_phrase = match.group()
            if encoded_phrase in seen_rot13:
                continue
            try:
                decoded = codecs.decode(encoded_phrase, 'rot_13')
                if all(ord(c) < 128 for c in decoded):
                    seen_rot13.add(encoded_phrase)
                    output_lines.append(f"ROT13 encoded: {encoded_phrase}")
                    output_lines.append(f"ROT13 decoded: {decoded}")
            except Exception:
                continue

    return output_lines

def generate_report(text):
    report = {}
    report["financial_data"] = find_credit_cards(text)
    report["secrets"] = find_secrets(text)
    report["system_info"] = extract_system_info(text)
    report["decoded_messages"] = decode_messages(text)
    report["security_threats"] = analyze_logs(text)
    report["normalized_data"] = normalize_and_validate(text)
    return report

def print_report(report):
    print("=" * 40)
    print("ОТЧЕТ")
    print("=" * 40)
    print("Валидных карт:", len(report["financial_data"]["valid"]))
    print("Невалидных карт:", len(report["financial_data"]["invalid"]))
    print("Секретов:", len(report["secrets"]))
    print("Email:", len(report["system_info"]["emails"]))
    print("IP:", len(report["system_info"]["ips"]))
    print("Файлы:", len(report["system_info"]["files"]))
    print("Base64:", len(report["decoded_messages"]))
    
    total_threats = 0
    for key, val in report["security_threats"].items():
        total_threats += len(val["items"])
    print("Ошибки:", total_threats)
    
    print("Телефоны:", len(report["normalized_data"]["phones"]["valid"]))
    print("ИНН:", len(report["normalized_data"]["inn"]["valid"]))


def save_all_artifacts(report, filename):
    artifacts = []
    seen = set()
    
    for item in report["financial_data"]["valid"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    for item in report["financial_data"]["invalid"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    
    for item in report["secrets"]:
        if len(item) < 10 or len(item) > 200:  
            continue
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    
    for item in report["system_info"]["emails"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    for item in report["system_info"]["ips"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    for item in report["system_info"]["files"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    
    for item in report["decoded_messages"]:
        if isinstance(item, str) and len(item) < 200: 
            if "Base64 encoded:" in item:
                encoded = item.split(": ", 1)[-1]
                if re.match(r'^[A-Za-z0-9+/]{20,}=*$', encoded) and len(encoded) < 100:
                    if encoded not in seen:
                        seen.add(encoded)
                        artifacts.append(encoded)
    
    for item in report["normalized_data"]["phones"]["valid"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    for item in report["normalized_data"]["inn"]["valid"]:
        if item not in seen:
            seen.add(item)
            artifacts.append(item)
    
    for key, val in report["security_threats"].items():
        for item in val["items"]:
            if len(item) < 200:  
                if item not in seen:
                    seen.add(item)
                    artifacts.append(item)
    
    with open(filename, "w", encoding="utf-8") as f:
        for item in artifacts:
            f.write(str(item) + "\n")
            
def compare_results(group_number, other_groups):
    
    your_file = f"result{group_number}.txt"
    with open(your_file, 'r', encoding='utf-8') as f:
        your_results = set([line.strip() for line in f if line.strip()])
    
    print(f"\n{'='*50}")
    print(f"СРАВНЕНИЕ ГРУППЫ {group_number} С ДРУГИМИ ГРУППАМИ")
    print(f"{'='*50}")
    print(f"В вашем файле: {len(your_results)} артефактов\n")
    
    for other in other_groups:
        try:
            other_file = f"result{other}.txt"
            with open(other_file, 'r', encoding='utf-8') as f:
                other_results = set([line.strip() for line in f if line.strip()])
            
            common = your_results & other_results
            only_in_yours = your_results - other_results
            only_in_theirs = other_results - your_results
            
            print(f"Группа {other}: {len(other_results)} артефактов")
            print(f"Совпадает: {len(common)}")
            print(f"Есть только у вас: {len(only_in_yours)}")
            print(f"Есть только у них: {len(only_in_theirs)}")
            
            if only_in_yours:
                print(f"Примеры (только у вас):")
                for item in list(only_in_yours):
                    print(f"     • {item}")
            if only_in_theirs:
                print(f"Примеры (только у них):")
                for item in list(only_in_theirs):
                    print(f"     • {item}")
            print()
            
        except FileNotFoundError:
            print(f"Файл группы {other} не найден\n")

if __name__ == "__main__":
    group_number = 8   # номер группы (1-10)
    with open("input.txt", "r", encoding="utf-8") as f:
        text = f.read()
    report = generate_report(text)
    print_report(report)
    output_file = f"result{group_number}.txt"
    save_all_artifacts(report, output_file)
    print(f"\nСоздан файл {output_file}")
    compare_results(8, [1, 2, 3, 4, 5, 6, 7, 9, 10])
