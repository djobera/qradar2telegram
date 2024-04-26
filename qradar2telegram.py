import datetime
import json
import os
from os import path
import requests
from dotenv import load_dotenv

load_dotenv()

# Script para postar eventos no Telegram
SIEM_KEY = os.getenv("SIEM_KEY")
BOT_TOKEN = os.getenv("BOT_TOKEN")
BOT_CHAT_ID = os.getenv("BOT_CHAT_ID")
SIEM_URL = os.getenv("SIEM_URL")

# Verifica se as variáveis de ambiente foram carregadas corretamente
if not all([SIEM_KEY, BOT_TOKEN, BOT_CHAT_ID, SIEM_URL]):
    raise ValueError("As variáveis de ambiente não foram carregadas corretamente. Verifique o arquivo .env.")

def post_telegram_issue(message):
    """Função para enviar mensagens para um chat do Telegram."""
    send_text = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage?chat_id={BOT_CHAT_ID}&parse_mode=Markdown&text={message}'
    try:
        response = requests.get(send_text)
        response.raise_for_status()  # Levanta um erro para respostas de falha
        return response.json()
    except requests.RequestException as e:
        print(f"Erro ao enviar mensagem para o Telegram: {e}")
        return None

def get_siem_offenses(base_url, sec_code, fields="id,description,status,categories,start_time,severity,offense_source,source_network,destination_networks"):
    """Função para buscar ofensas do SIEM."""
    headers = {
        'sec': sec_code,
        'version': '8.1',
    }
    try:
        response = requests.get(f'{base_url}api/siem/offenses', headers=headers, params={"fields": fields, "filter": "status=OPEN"}, verify=True)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Erro ao buscar ofensas do SIEM: {e}")
        return []

def get_severity_appearance(severity):
    """Representa visualmente a severidade da ofensa."""
    if severity <= 2:
        return "🟦🟦⬜️⬜️⬜️⬜️"
    elif severity <= 4:
        return "🟩🟩🟩⬜️⬜️⬜️"
    elif severity <= 6:
        return "🟨🟨🟨🟨⬜️⬜️"
    elif severity <= 8:
        return "🟧🟧🟧🟧🟧⬜️"
    return "🟥🟥🟥🟥🟥🟥"

def create_offense_for_telegram(raw_offense):
    """Cria uma mensagem formatada para ser enviada ao Telegram."""
    time = datetime.datetime.fromtimestamp(raw_offense['start_time'] / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
    offense_url = f"{SIEM_URL}console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={raw_offense['id']}"
    source = raw_offense.get('offense_source', "")

    return  f'*Offense id*: {raw_offense["id"]} - {raw_offense["description"].replace("\\n", "")}\n' \
            f'*Time:* {time}\n' \
            f'*Category:* {raw_offense.get("categories", "N/A")}\n' \
            f'*Offense Source:* {raw_offense.get("offense_source", "N/A")}\n' \
            f'*Source Network:* {raw_offense.get("source_network", "N/A")}\n' \
            f'*Destination Networks:* {raw_offense.get("destination_networks", "N/A")}\n' \
            f'*Severity:* {get_severity_appearance(raw_offense["severity"])}\n' \
            f'*URL:* [click here]({offense_url})'

def load_cache(filename='cache1.json'):
    """Carrega o cache de IDs já enviados."""
    if not path.exists(filename):
        return set()

    with open(filename, 'r') as f:
        return set(json.load(f))

def save_cache(cache, filename='cache1.json'):
    """Salva o cache de IDs no arquivo."""
    with open(filename, 'w') as f:
        json.dump(list(cache), f)

if __name__ == '__main__':
    sent_offenses_cache = load_cache()
    print('in cache:', sent_offenses_cache)
    offenses = get_siem_offenses(SIEM_URL, SIEM_KEY)

    for offense in offenses:
        if offense['id'] not in sent_offenses_cache:
            telegram_issue = create_offense_for_telegram(offense)
            print(f'posting offense #: {offense["id"]} ...')
            post_telegram_issue(telegram_issue)
            sent_offenses_cache.add(offense['id'])

    save_cache(sent_offenses_cache)
