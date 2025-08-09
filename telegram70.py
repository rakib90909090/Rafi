import requests
from bs4 import BeautifulSoup
import time
import re
import sys
import signal
import sqlite3
import os
import threading
import hashlib
import queue
import random

# --- Configuration ---
BOT_NAME = "Ivas Otp Received"
EMAIL = "lancejackson9054@gmail.com"
PASSWORD = "Roki@9080"
DB_FILE = "sms_database.db"

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN ="8250684252:AAGpXT4xkl9SMvQ4zHCJTDmSTCuB9_pxgNo"
DEFAULT_GROUP_CHAT_ID = "-1002596941909" # 
DM_CHAT_ID = "6000804411" # 
TELEGRAM_DEVELOPER_USER_ID = "6000804411" #
notification_text = """🔔{flag} <b>𝐍𝐞𝐰 {country_name} {service_name} 𝐎𝐓𝐏 𝐑𝐞𝐜𝐞𝐢𝐯𝐞𝐝...</b>

⚙️ <b>𝚂𝚎𝚛𝚟𝚒𝚌𝚎</b> : <code>{service_name}</code> 📱
🌐 <b>𝙲𝚘𝚞𝚗𝚝𝚛𝚢</b> : <code>{country_name}</code> {flag}
☎️ <b>𝙽𝚞𝚖𝚋𝚎𝚛</b> : <code>{phone_number}</code>
⏰ <b>𝚃𝚒𝚖𝚎</b> : <code>{current_time}</code>

🔑 <b>𝐘𝐨𝐮𝐫 𝐎𝐓𝐏</b> : <code>{otp_code}</code>

📱 <b>𝐌𝐞𝐬𝐬𝐚𝐠𝐞</b> :
<code>{message_content}</code>

🚀<b>𝐁𝐞 𝐀𝐜𝐭𝐢𝐯𝐞 - 𝐍𝐞𝐰 𝐎𝐓𝐏 𝐂𝐨𝐦𝐢𝐧𝐠...</b>"""
MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiW(AwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"

POLLING_INTERVAL_SECONDS = 1
COUNTRY_INFO = {
    '1': {'name': 'USA/Canada', 'flag': '🇺🇸'}, '7': {'name': 'Russia', 'flag': '🇷🇺'},
    '20': {'name': 'Egypt', 'flag': '🇪🇬'}, '27': {'name': 'South Africa', 'flag': '🇿🇦'},
    '30': {'name': 'Greece', 'flag': '🇬🇷'}, '31': {'name': 'Netherlands', 'flag': '🇳🇱'},
    '32': {'name': 'Belgium', 'flag': '🇧🇪'}, '33': {'name': 'France', 'flag': '🇫🇷'},
    '34': {'name': 'Spain', 'flag': '🇪🇸'}, '36': {'name': 'Hungary', 'flag': '🇭🇺'},
    '39': {'name': 'Italy', 'flag': '🇮🇹'}, '40': {'name': 'Romania', 'flag': '🇷🇴'},
    '41': {'name': 'Switzerland', 'flag': '🇨🇭'}, '43': {'name': 'Austria', 'flag': '🇦🇹'},
    '44': {'name': 'United Kingdom', 'flag': '🇬🇧'}, '45': {'name': 'Denmark', 'flag': '🇩🇰'},
    '46': {'name': 'Sweden', 'flag': '🇸🇪'}, '47': {'name': 'Norway', 'flag': '🇳🇴'},
    '48': {'name': 'Poland', 'flag': '🇵🇱'}, '49': {'name': 'Germany', 'flag': '🇩🇪'},
    '51': {'name': 'Peru', 'flag': '🇵🇪'}, '52': {'name': 'Mexico', 'flag': '🇲🇽'},
    '53': {'name': 'Cuba', 'flag': '🇨🇺'}, '54': {'name': 'Argentina', 'flag': '🇦🇷'},
    '55': {'name': 'Brazil', 'flag': '🇧🇷'}, '56': {'name': 'Chile', 'flag': '🇨🇱'},
    '57': {'name': 'Colombia', 'flag': '🇨🇴'}, '58': {'name': 'Venezuela', 'flag': '🇻🇪'},
    '60': {'name': 'Malaysia', 'flag': '🇲🇾'}, '61': {'name': 'Australia', 'flag': '🇦🇺'},
    '62': {'name': 'Indonesia', 'flag': '🇮🇩'}, '63': {'name': 'Philippines', 'flag': '🇵🇭'},
    '64': {'name': 'New Zealand', 'flag': '🇳🇿'}, '65': {'name': 'Singapore', 'flag': '🇸🇬'},
    '66': {'name': 'Thailand', 'flag': '🇹🇭'}, '81': {'name': 'Japan', 'flag': '🇯🇵'},
    '82': {'name': 'South Korea', 'flag': '🇰🇷'}, '84': {'name': 'Vietnam', 'flag': '🇻🇳'},
    '86': {'name': 'China', 'flag': '🇨🇳'}, '90': {'name': 'Turkey', 'flag': '🇹🇷'},
    '91': {'name': 'India', 'flag': '🇮🇳'}, '92': {'name': 'Pakistan', 'flag': '🇵🇰'},
    '93': {'name': 'Afghanistan', 'flag': '🇦🇫'}, '94': {'name': 'Sri Lanka', 'flag': '🇱🇰'},
    '95': {'name': 'Myanmar', 'flag': '🇲🇲'}, '98': {'name': 'Iran', 'flag': '🇮🇷'},
    '212': {'name': 'Morocco', 'flag': '🇲🇦'}, '213': {'name': 'Algeria', 'flag': '🇩🇿'},
    '225': {'name': 'Ivory Coast', 'flag': '🇨🇮'},
    '880': {'name': 'Bangladesh', 'flag': '🇧🇩'},
    '966': {'name': 'Saudi Arabia', 'flag': '🇸🇦'}, '971': {'name': 'United Arab Emirates', 'flag': '🇦🇪'},
    '996': {'name': 'Kyrgyzstan', 'flag': '🇰🇬'}, '998': {'name': 'Uzbekistan', 'flag': '🇺🇿'},
}


def get_country_info_manually(phone_number):
    for length in range(4, 0, -1):
        prefix = phone_number[:length]
        if prefix in COUNTRY_INFO:
            return COUNTRY_INFO[prefix]['name'], COUNTRY_INFO[prefix]['flag']
    return "Unknown Country", "🌍"



BASE_URL = "https://www.ivasms.com"
LOGIN_URL = f"{BASE_URL}/login"
MY_ACTIVE_SMS_PAGE_URL = f"{BASE_URL}/portal/live/my_sms"
GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"
GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"
RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"

db_connection = None
stop_event = threading.Event()
reported_sms_hashes_cache = set()

class TelegramSender:
    def __init__(self, token):
        self.token = token
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._worker, daemon=True)

    def start(self):
        self.thread.start()
        print("[*] Telegram Sender thread started.")

    def _worker(self):
        while not stop_event.is_set():
            try:
                chat_id, text, sms_hash = self.queue.get(timeout=1)
                if self._send_message(chat_id, text, 'HTML'):
                    add_sms_to_reported_db(sms_hash)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Error in Telegram worker thread: {e}")

    def _send_message(self, chat_id, text, parse_mode='HTML'):
        api_url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode, 'disable_web_page_preview': True}
        while not stop_event.is_set():
            try:
                response = requests.post(api_url, json=payload, timeout=20)
                if response.status_code == 200:
                    print(f"[TG] Successfully sent SMS notification to {chat_id}.")
                    return True
                elif response.status_code == 429:
                    retry_after = response.json().get('parameters', {}).get('retry_after', 30)
                    print(f"[!] Telegram rate limit hit. Cooling down for {retry_after} seconds...")
                    time.sleep(retry_after)
                else:
                    print(f"[!] TELEGRAM API ERROR: Status {response.status_code}, Response: {response.text}")
                    return False
            except requests.exceptions.RequestException as e:
                print(f"[!] TELEGRAM NETWORK ERROR: {e}. Retrying in 30 seconds...")
                time.sleep(30)
        return False

    def queue_message(self, chat_id, text, sms_hash):
        self.queue.put((chat_id, text, sms_hash))

telegram_sender = TelegramSender(TELEGRAM_BOT_TOKEN)

def setup_database():
    global db_connection, reported_sms_hashes_cache
    try:
        db_connection = sqlite3.connect(DB_FILE, check_same_thread=False)
        cursor = db_connection.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS reported_sms (hash TEXT PRIMARY KEY)')
        cursor.execute("SELECT hash FROM reported_sms")
        reported_sms_hashes_cache = {row[0] for row in cursor.fetchall()}
        db_connection.commit()
        print(f"[*] Database '{DB_FILE}' connected. Loaded {len(reported_sms_hashes_cache)} existing hashes.")
        return True
    except sqlite3.Error as e:
        print(f"[!!!] DATABASE ERROR: {e}")
        return False

def add_sms_to_reported_db(sms_hash):
    try:
        cursor = db_connection.cursor()
        cursor.execute("INSERT INTO reported_sms (hash) VALUES (?)", (sms_hash,))
        db_connection.commit()
    except sqlite3.Error as e:
        if "UNIQUE constraint failed" not in str(e):
            print(f"[!] DB_INSERT_ERROR: {e}")

def send_operational_message(chat_id, text):
    message_to_send = f"{text}\n\n🤖 _{BOT_NAME}_"
    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message_to_send, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, json=payload, timeout=15)
        print(f"[TG] Sent operational message to {chat_id}.")
    except Exception as e:
        print(f"[!] TELEGRAM ERROR (Operational): {e}")

def graceful_shutdown(signum, frame):
    print("\n\n[!!!] Shutdown signal detected. Bot is stopping.")
    send_operational_message(TELEGRAM_DEVELOPER_USER_ID, "🛑 *SMS Fetcher Shutting Down*")
    stop_event.set()
    if db_connection:
        db_connection.close()
        print("[*] Database connection closed.")
    time.sleep(2)
    sys.exit(0)

def get_polling_csrf_token(session):
    try:
        response = session.get(RECEIVED_SMS_PAGE_URL, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        token_tag = soup.find('meta', {'name': 'csrf-token'})
        if token_tag:
            return token_tag['content']
        raise Exception("CSRF token meta tag not found.")
    except Exception as e:
        print(f"[!] Error getting CSRF token: {e}")
        return None

def _process_and_queue_sms(phone_number, sender_cli, message_content, range_name, destination_chat_id):
    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()

    if sms_hash not in reported_sms_hashes_cache:
        reported_sms_hashes_cache.add(sms_hash)
        print(f"[+] New SMS Queued! From: '{sender_cli}', Number: {phone_number}")

        otp_code = "N/A"
        code_match = re.search(r'\b(\d{4,8})\b|\b(\d{3}[- ]?\d{3})\b', message_content)
        if code_match:
            raw_code = code_match.group(1) or code_match.group(2)
            if raw_code:
                clean_code = re.sub(r'[- ]', '', raw_code)
                otp_code = f"{clean_code[:3]}-{clean_code[3:]}" if len(clean_code) == 6 else clean_code

        service_name = sender_cli.title() if sender_cli and sender_cli != "N/A" else "Unknown"

        country_name, flag = get_country_info_manually(phone_number)
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        
        formatted_notification = notification_text.format(
            flag=flag,
            country_name=country_name,
            service_name=service_name,
            phone_number=phone_number,
            current_time=current_time,
            otp_code=otp_code,
            message_content=message_content
        )
        
        telegram_sender.queue_message(DEFAULT_GROUP_CHAT_ID, formatted_notification, sms_hash)

def get_available_ranges(session):
    try:
        response = session.get(MY_ACTIVE_SMS_PAGE_URL, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        range_links = soup.select('#accordion a.d-block')
        available_ranges = [link.get_text(strip=True) for link in range_links if link.get_text(strip=True)]
        return available_ranges
    except Exception as e:
        print(f"[!] Error fetching available ranges: {e}")
        return []

def watch_all_ranges_with_updates(session):
    polling_interval = POLLING_INTERVAL_SECONDS
    range_update_interval = 60
    last_range_update = 0
    current_ranges = []
    
    print("\n" + "="*60 + f"\n[*] STARTING DYNAMIC RANGE MONITORING (Polling every {polling_interval}s, Range updates every {range_update_interval}s)\n[*] Press Ctrl+C to stop.\n" + "="*60)
    
    try:
        while not stop_event.is_set():
            start_time = time.time()
            
            if time.time() - last_range_update >= range_update_interval:
                print(f"\n[*] Updating available ranges... (Last update: {time.strftime('%H:%M:%S')})")
                new_ranges = get_available_ranges(session)
                
                if new_ranges:
                    if set(new_ranges) != set(current_ranges):
                        current_ranges = new_ranges
                        ranges_text = ", ".join(current_ranges)
                        print(f"[SUCCESS] Ranges updated! Now watching {len(current_ranges)} ranges: {current_ranges}")
                        send_operational_message(TELEGRAM_DEVELOPER_USER_ID, f"🔄 *Ranges Updated!*\n\nNow watching: `{ranges_text}`")
                    else:
                        print("[*] No changes in available ranges.")
                    last_range_update = time.time()
                else:
                    print("[!] No ranges found during update. Keeping current ranges.")
            
            if not current_ranges:
                print("[!] No ranges available. Waiting for next range update...")
                time.sleep(polling_interval)
                continue
            
            csrf_token = get_polling_csrf_token(session)
            if not csrf_token:
                time.sleep(polling_interval)
                continue

            headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-CSRF-TOKEN': csrf_token}
            print(f"[*] Checking {len(current_ranges)} ranges... (Last check: {time.strftime('%H:%M:%S')})")
            
            for target_range in current_ranges:
                if stop_event.is_set():
                    break
                    
                payload_numbers = {'_token': csrf_token, 'range': target_range}
                response_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)
                soup_numbers = BeautifulSoup(response_numbers.text, 'html.parser')
                
                number_divs = soup_numbers.find_all('div', onclick=re.compile(r"getDetialsNumber"))
                if not number_divs: 
                    print(f"    - No numbers with messages found in range '{target_range}'.")
                    continue
                
                for number_div in number_divs:
                    phone_match = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)'", number_div['onclick'])
                    if not phone_match: continue
                    phone_number = phone_match.group(1)

                    payload_messages = {'_token': csrf_token, 'Number': phone_number, 'Range': target_range}
                    response_messages = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_messages, headers=headers)
                    soup_messages = BeautifulSoup(response_messages.text, 'html.parser')
                    
                    for card in soup_messages.find_all('div', class_='card-body'):
                        p_tag = card.find('p', class_='mb-0')
                        msg_content = p_tag.get_text(strip=True) if p_tag else ""

                        sender_cli = "N/A"
                        cli_label_div = card.find('div', string=re.compile(r'\s*CLI\s*'))
                        if cli_label_div:
                            service_name_div = cli_label_div.find_next_sibling('div')
                            if service_name_div:
                                sender_cli = service_name_div.get_text(strip=True)
                        
                        if msg_content:
                            _process_and_queue_sms(phone_number, sender_cli, msg_content, target_range, None)
            
            elapsed_time = time.time() - start_time
            sleep_duration = max(0, polling_interval - elapsed_time)
            time.sleep(sleep_duration)
            
    except KeyboardInterrupt:
        graceful_shutdown(None, None)

def start_automatic_watch(session):
    print("\n[*] Starting automatic watch mode with dynamic range updates.")
    try:
        print("[*] Fetching initial available ranges...")
        initial_ranges = get_available_ranges(session)
        
        if initial_ranges:
            print(f"[SUCCESS] Found {len(initial_ranges)} initial ranges: {initial_ranges}")
            ranges_text = ", ".join(initial_ranges)
            send_operational_message(TELEGRAM_DEVELOPER_USER_ID, f"✅ *Bot Started Successfully!*\n\nInitial ranges: `{ranges_text}`\n\n🔄 Ranges will be updated every minute automatically.")
            
            watch_all_ranges_with_updates(session)
            print("[*] Watch loop ended. Shutting down bot.")
        else:
            print("[!] No active ranges found. Retrying in 60 seconds...")
            time.sleep(60)
            start_automatic_watch(session)
            
    except requests.exceptions.RequestException as req_e:
        print(f"[!] Network error during range fetching: {req_e}. Retrying in 30 seconds...")
        time.sleep(30)
        start_automatic_watch(session)
    except Exception as e:
        print(f"[!!!] CRITICAL ERROR in automatic watch setup: {e}. Retrying in 30 seconds...")
        time.sleep(30)
        start_automatic_watch(session)

def main():
    signal.signal(signal.SIGINT, graceful_shutdown)
    print("="*60 + "\n--- Israel's C&C Bot: SMS Fetcher (V7 - Final CLI Fix) ---\n" + "="*60)

    if not setup_database(): return
    if "MAGIC_RECAPTCHA_TOKEN" in MAGIC_RECAPTCHA_TOKEN or len(MAGIC_RECAPTCHA_TOKEN) < 50:
        print("\n[!!!] FATAL ERROR: Update 'MAGIC_RECAPTCHA_TOKEN'.")
        return
    if "YOUR_USER_ID" in TELEGRAM_DEVELOPER_USER_ID or len(TELEGRAM_DEVELOPER_USER_ID) < 6:
        print("\n[!!!] FATAL ERROR: Please set your 'TELEGRAM_DEVELOPER_USER_ID'.")
        return

    destination_chat_id = DEFAULT_GROUP_CHAT_ID
    print(f"[*] OTP notifications will be sent to group ID: {destination_chat_id}")
    print(f"[*] Status/Update messages will be sent to developer ID: {TELEGRAM_DEVELOPER_USER_ID}")

    try:
        with requests.Session() as session:
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})
            print("\n[*] Step 1: Authenticating...")
            login_page = session.get(LOGIN_URL)
            soup = BeautifulSoup(login_page.text, 'html.parser')
            csrf_token_login = soup.find('input', {'name': '_token'})['value']
            
            login_payload = {'_token': csrf_token_login, 'email': EMAIL, 'password': PASSWORD, 'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN}
            login_response = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

            if "login" not in login_response.url and "Logout" in login_response.text:
                print("[SUCCESS] Authentication complete!")
                telegram_sender.start()
                start_automatic_watch(session)
            else:
                print("\n[!!!] AUTHENTICATION FAILED.")
                soup_error = BeautifulSoup(login_response.text, 'html.parser')
                error_msg = soup_error.find('span', class_='invalid-feedback')
                if error_msg: print(f"[!] Login page error: {error_msg.strong.text}")
    except Exception as e:
        print(f"[!!!] A critical error occurred during startup: {e}")

if __name__ == "__main__":
    main()