import sys
import subprocess

# List of third-party dependencies that need installation
REQUIRED_PACKAGES = ['configparser', 'csv', 'telethon', 'cryptography','base58','tqdm','qrcode','aiofiles','pygments']

def install_packages():
    """Install missing third-party packages automatically."""
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)  # Try importing the package
        except ImportError:
            print(f"{package} is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Ensure required packages are installed
install_packages()


# Built-in modules
import os
import re
import ctypes
import configparser
import csv
import time
from datetime import datetime, timedelta
import signal
import argparse
import platform
import json
import asyncio
import warnings

# Ignore specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Third-party libraries
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer

from telethon import errors
from telethon import TelegramClient # type: ignore
from telethon.tl.functions.messages import GetDialogsRequest # type: ignore
from telethon.tl.functions.channels import InviteToChannelRequest, GetParticipantRequest, GetParticipantsRequest # type: ignore
from telethon.tl.types import InputPeerEmpty, Channel, Chat, ChannelParticipantsAdmins, PeerChannel, ChannelParticipantsSearch, User # type: ignore
from telethon.errors import FloodWaitError, UserAlreadyParticipantError, ChannelPrivateError, RPCError # type: ignore

from cryptography.hazmat.primitives import serialization, hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
# from cryptography.hazmat.primitives.serialization import load_pem_public_key # type: ignore

from qrcode import QRCode

# Initializing the QR code generator
qr = QRCode()

# ANSI color codes for console output https://i.sstatic.net/9UVnC.png
color_reset = "\033[0m"
color_black = color_reset + "\033[1;30m"
color_red = color_reset + "\033[1;31m"
color_green = color_reset + "\033[1;32m"
color_cyan = color_reset + "\033[1;36m"
color_gray = color_reset + "\033[1;90m"
color_yellow = color_reset + "\033[0;33m"
color_purple = color_reset + "\033[95m" # purple
color_blue = color_reset + "\033[94m" # blue
color_sun = color_reset + "\033[93m" #lightyellow
text_bold = "\033[1m" #bold
text_under = "\033[4m" #underline

sleep_prevention_process = None

valid_license = False


# Constants
PUBLIC_KEY_PEM = b"""
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAk0RLzetzsOP17x6+lSHRRc0n8QAk4KRVMerwiLQMrj1skGyb3iiu
9vbvv+Ju40cJTM8zSwGlamB+bkgm7SpSWpu2v3H8HJpoSYfo8YlQ1pEFMUavpuKe
xnQUWvCrTC1wbzgY0qATyIdRiCbGm80daEPu8dLJz4wWwr/w7ofhjmCNmG/GuxsN
0HqXuZ8Dxz6hx9kUplC0kbtRjXLIfzPlow2VdTRhSXuTWPDkcvh3lpVTUt1YvFEw
iueJf/2xY5V5rNztJPTLs5MYsooOf3MrFCfXwcDsRATQBLalQNAYROsEB61DCb+6
kT8w5vsJ5vqLu9KYha9qhgaww1foDGy9AwIDAQAB
-----END RSA PUBLIC KEY-----
"""


def print_json(jsontext):
    json_data = json.dumps(jsontext, indent=4)
    highlighted = highlight(json_data, JsonLexer(), TerminalFormatter())
    print(highlighted)

# Function to generate and display the QR code in ASCII format
def gen_qr(token: str):
    qr.clear()
    qr.add_data(token)
    qr.print_ascii()

# Function to display the URL as a QR code in the terminal
def display_url_as_qr(url: str):
    os.system("cls" if os.name == "nt" else "clear")  # Clear terminal on Windows or Unix-like systems
    print("Generated new QR Code...")
    gen_qr(url)



# Graceful exit on Ctrl+C
def signal_handler(sig, frame):
    print(f"\nProcess terminated unexpectedly! Cleaning up...{color_reset}")
    global sleep_prevention_process

    if sleep_prevention_process:
        # Allow sleep again
        allow_sleep(sleep_prevention_process)
        print(f"{color_black}Sleep mode allowed again{color_reset}")

    sys.exit(0)

# Attach signal handler to Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

def banner():
    print(color_gray + f"""
                                                                       
{color_red}888888888888{color_sun}  ,ad8888ba,   {color_green} ad88888ba        {color_cyan}88888888ba  {color_blue}8b        d8  
{color_red}     88     {color_sun} d8"'    `"8b  {color_green}d8"     "8b       {color_cyan}88      "8b {color_blue} Y8,    ,8P   
{color_red}     88     {color_sun}d8'            {color_green}Y8,               {color_cyan}88      ,8P {color_blue}  Y8,  ,8P    
{color_red}     88     {color_sun}88             {color_green}`Y8aaaaa,         {color_cyan}88aaaaaa8P' {color_blue}   "8aa8"     
{color_red}     88     {color_sun}88      88888  {color_green}  `\"\"\"\"\"8b,       {color_cyan}88\"\"\"\"\"\"'   {color_blue}    `88'      
{color_red}     88     {color_sun}Y8,        88  {color_green}        `8b       {color_cyan}88          {color_blue}     88       
{color_red}     88     {color_sun} Y8a.    .a88  {color_green}Y8a     a8P  {color_purple}888  {color_cyan}88          {color_blue}     88       
{color_red}     88     {color_sun}  `"Y88888P"   {color_green} "Y88888P"   {color_purple}888  {color_cyan}88          {color_blue}     88       
                                                                       
""" + color_reset)

async def touch(file_path):
    if not os.path.dirname(file_path):  # If no path is specified
        file_path = os.path.join(os.getcwd(), file_path)  # Use current working directory

    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Create parent directories

    return file_path

async def config_setup(config="config.data", phone=None, api_id=None, api_hash=None):
    banner()
    cpass = configparser.RawConfigParser()
    cpass.add_section('cred')
    
    if not phone:
        xphone = input(color_green + "[+] enter phone number : " + color_red)
        cpass.set('cred', 'phone', xphone)
    else:
        cpass.set('cred', 'phone', phone)

    if not api_id or not api_hash:
        print("Please create an app at https://my.telegram.org/apps with any data you want and enter data below")

    if not api_id:
        xid = input(color_green + "[+] enter api ID : " + color_red)
        cpass.set('cred', 'id', xid)
    else:
        cpass.set('cred', 'id', api_id)

    if not api_hash:
        xhash = input(color_green + "[+] enter hash ID : " + color_red)
        cpass.set('cred', 'hash', xhash)
    else:
        cpass.set('cred', 'hash', api_hash)

    setup = open(await touch(config), 'w')
    cpass.write(setup)
    setup.close()
    print(color_green + f"[+] setup complete, saved to file {config}!")


# Function to generate and display the QR code in ASCII format
def gen_qr(token: str):
    qr = QRCode()
    qr.clear()
    qr.add_data(token)
    qr.print_ascii()

# Function to display the URL as a QR code in the terminal
def display_url_as_qr(url: str):
    os.system("cls" if os.name == "nt" else "clear")
    print("Generated new QR Code...")
    gen_qr(url)

# Function to initialize TelegramClient
async def init_client(config="config.data"):
    cpass = configparser.RawConfigParser()

    # Attempt to read API credentials from config file
    try:
        cpass.read(config)
        api_id = cpass['cred']['id']
        api_hash = cpass['cred']['hash']
        phone = cpass['cred']['phone']
        client = TelegramClient(phone, api_id, api_hash)
    except KeyError:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("[!] run python3 setup.py first !!\n")
        sys.exit(1)

    # Start the client
    await client.start()

    # Check if user is authorized (logged in)
    if not await client.is_user_authorized():
        os.system("cls" if os.name == "nt" else "clear")
        print("[#] User not authorized, attempting login...")

        # Check if config provides a phone number for regular login
        if phone:
            try:
                # Send code and prompt for login
                await client.send_code_request(phone)
                os.system('cls' if os.name == 'nt' else 'clear')
                code = input('[#] Enter the code: ')
                await client.sign_in(phone, code)
            except errors.SessionPasswordNeededError:
                # Handle 2FA
                password = input("[#] 2FA enabled. Enter your password: ")
                await client.sign_in(password=password)
        else:
            # If no phone provided, fallback to QR login
            qr_login = await client.qr_login()

            r = False
            while not r:
                display_url_as_qr(qr_login.url)
                try:
                    r = await qr_login.wait(10)  # Wait for the user to scan the QR code
                except errors.SessionPasswordNeededError:
                    # Handle 2FA after QR login
                    password = input("[#] 2FA enabled. Enter your password: ")
                    await client.sign_in(password=password)
                    r = True
                except Exception as e:
                    print(f"[!] Error: {e}. Recreating QR code...")
                    await qr_login.recreate()

    return client


# Function to convert seconds to a human-readable format
def format_time(input_secs):
    seconds = int(input_secs)
    days = seconds // (24 * 3600)
    seconds = seconds % (24 * 3600)
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    time_str = ""
    if days > 0:
        time_str += f"{days} day(s) "
    if hours > 0:
        time_str += f"{hours} hour(s) "
    if minutes > 0:
        time_str += f"{minutes} minute(s) "
    if seconds > 0 or time_str == "":
        time_str += f"{seconds} second(s)"
    
    return time_str

async def get_groups(client):
    chats = []
    last_date = None
    chunk_size = 200
    result = await client(GetDialogsRequest(  # Await the request
        offset_date=last_date,
        offset_id=0,
        offset_peer=InputPeerEmpty(),
        limit=chunk_size,
        hash=0
    ))
    chats.extend(result.chats)

    groups = [chat for chat in chats if getattr(chat, 'megagroup', False)]
    return groups

async def get_target_group(client, source):
    if source:
        try:
            # Check if source is numeric (ID) or text (username)
            target_group_id = int(source)
            try:
                return await client.get_entity(target_group_id)  # Await the entity fetching
            except Exception as e:
                print(color_red + f"[!] Error fetching group by ID: {e}" + color_reset)
                return None
        except ValueError:
            # If conversion fails, treat source as username
            try:
                result = await client(GetDialogsRequest(  # Await the request
                    offset_date=None,
                    offset_id=0,
                    offset_peer=InputPeerEmpty(),
                    limit=200,
                    hash=0
                ))
                groups = [chat for chat in result.chats if isinstance(chat, (Channel, Chat))]
                
                source_lower = source.lower().strip()  # Normalize the input
                matching_groups = [
                    g for g in groups if hasattr(g, 'username') and g.username and source_lower == g.username.lower().strip()
                ]
                if matching_groups:
                    return matching_groups[0]
                else:
                    print(color_red + "[!] No matching group found. Please select from the list below:" + color_reset)
                    return await select_group(groups, "target")  # Await the selection
            except Exception as e:
                print(color_red + f"[!] Error fetching groups by username: {e}" + color_reset)
                return None
    else:
        # No source provided; user must select from available groups
        try:
            result = await client(GetDialogsRequest(  # Await the request
                offset_date=None,
                offset_id=0,
                offset_peer=InputPeerEmpty(),
                limit=200,
                hash=0
            ))
            groups = [chat for chat in result.chats if isinstance(chat, (Channel, Chat))]
            return await select_group(groups, "target")  # Await the selection
        except Exception as e:
            print(color_red + f"[!] Error fetching groups: {e}" + color_reset)
            return None

async def select_group(groups, typetitle):
    print(color_green + f'[#] Choose a {color_yellow}{typetitle}{color_green} group:' + color_red + color_reset)
    i = 0
    for g in groups:
        # Use 'username' safely
        username = f" @{g.username}" if hasattr(g, 'username') and g.username else ""
        print(color_green + '[' + color_cyan + str(i) + color_green + ']' + color_cyan + ' #' + str(g.id) + ' ' + g.title + username + color_reset)
        i += 1
    print('' + color_reset)
    g_index = input(color_green + "[#] Enter a Number : " + color_red)
    try:
        selected_index = int(g_index)
        if 0 <= selected_index < len(groups):
            return groups[selected_index]
        else:
            print(color_red + "[!] Invalid selection. Please try again." + color_reset)
            return await select_group(groups, typetitle)  # Await the selection
    except ValueError:
        print(color_red + "[!] Invalid input. Please enter a number." + color_reset)
        return await select_group(groups, typetitle)  # Await the selection

async def scrape_members(client, target_group=None, output_file="members.csv"):
    print(target_group)
    if target_group is None:
        target_group = await select_group(await get_groups(client), "target")  # Await the group selection

    # Check if target_group is a Channel object or a string
    if isinstance(target_group, str):
        if target_group.isdigit():
            target_group_id = int(target_group)
            target_group_username = None
        else:
            target_group_id = None
            target_group_username = target_group
    elif hasattr(target_group, 'id') and hasattr(target_group, 'username'):
        # Assume target_group is already a Channel object
        target_group_id = target_group.id
        target_group_username = target_group.username
    else:
        print(color_red + "[!] Invalid target group format." + color_reset)
        return

    if not valid_license:
        print(f'{color_red}[!] No valid license, functions are limited')

    print(color_green + '[@] Fetching Members...' + color_reset)

    try:
        if target_group_id:
            # If target_group is an ID
            target_group_entity = await client.get_entity(target_group_id)  # Await the entity fetching
        else:
            # If target_group is a username
            target_group_entity = await client.get_entity(target_group_username)  # Await the entity fetching
    except Exception as e:
        print(color_red + f"[!] Error fetching group: {e}" + color_reset)
        return

    # Fetch members
    all_participants = []
    filter = ChannelParticipantsSearch('')  # Fetch all participants

    try:
        async for participant in client.iter_participants(target_group_entity, filter=filter):
            all_participants.append(participant)
    except Exception as e:
        print(color_red + f"[!] Error fetching members: {e}" + color_reset)
        return

    user_count = len(all_participants)

        # Output file name
    if output_file is None:
        output_file = f"scraped/members_{int(time.time())}.csv"

    print(color_yellow + '[↓] Saving to file: ' + output_file + color_reset)
    await asyncio.sleep(1)  # Use await for sleep in async context

    try:
        # Await the touch function to ensure the file path is valid
        file_path = await touch(output_file)  
        with open(file_path, "w", encoding='UTF-8') as f:
            writer = csv.writer(f, delimiter=",", lineterminator="\n")
            writer.writerow(['username', 'user id', 'access hash', 'name', 'group', 'group id'])
            for user in all_participants:
                username = user.username if user.username else ""
                first_name = user.first_name if user.first_name else ""
                last_name = user.last_name if user.last_name else ""
                name = (first_name + ' ' + last_name).strip()
                writer.writerow([username, user.id, user.access_hash, name, target_group_entity.title, target_group_entity.id])
    except Exception as e:
        print(color_red + f"[!] Error saving to file: {e}" + color_reset)
        return

    print(color_green + '[✓] Members scraped successfully.' + color_reset)
    print(color_yellow + f"[$] Total users fetched: {user_count}" + color_reset)
    print(color_yellow + f"[@] Group ID: {target_group_entity.id}" + color_reset)
    print(color_yellow + f"[@] Group Title: {target_group_entity.title}" + color_reset)
    print(color_cyan + f"[✓] Saved to File: {output_file}" + color_reset)

async def user_already_in_group(client, user, target_group_entity):
    """Check if a user (by id or username) is already a participant in the target group."""
    try:
        # Determine the peer for the group
        group_peer = PeerChannel(target_group_entity.id)
        
        # Check if the user is in the group by ID or username
        if user['id']:
            participant = await client(GetParticipantRequest(group_peer, user['id']))
        elif user['username']:
            participant = await client(GetParticipantRequest(group_peer, user['username']))
        else:
            print(color_red + f"[!] No valid user id or username for user: {user}. Skipping check." + color_reset)
            return False

        # If we get here, the user is a participant
        return participant.participant is not None
    except UserAlreadyParticipantError:  # UserNotParticipantError
        return True
    except Exception as e:
        # Specific handling for users not in the group
        if "The target user is not a member" in str(e):
            return False
        else:
            print(color_red + f"[!] Error checking if user {user['username'] or user['id']} is in the group: {str(e)}" + color_reset)
            return False

async def add_user_to_group(client, user, target_group_entity, existing_users, mode):
    """Add a single user to the target group."""
    print('Sorry, available only in binary version.')

async def add_users_with_delay(client, members_csv=None, source_group=None, target_group=None, mode='user_id', delay=None):
    
    print('Sorry, available only in binary version.')

async def add_users(client, members_csv=None, source_group=None, target_group=None, mode='user_id'):
    
    print('Sorry, available only in binary version.')

# Platform-specific sleep prevention functions
async def prevent_sleep_windows():
    ES_CONTINUOUS = 0x80000000  # Keeps the current state of the display/sleep behavior
    ES_SYSTEM_REQUIRED = 0x00000001  # Prevents the system from sleeping
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)

async def allow_sleep_windows():
    ES_CONTINUOUS = 0x80000000  # Keeps the current state of the display/sleep behavior
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)

def allow_sleep_posix(process):
    # Terminate the process that was preventing sleep
    process.terminate()

async def prevent_sleep_macos():
    # Start the 'caffeinate' process to prevent sleep
    return await asyncio.create_subprocess_exec('caffeinate')

async def prevent_sleep_linux():
    # Use 'systemd-inhibit' to prevent sleep on Linux
    return await asyncio.create_subprocess_exec('systemd-inhibit', '--what=idle', '--why="Preventing sleep during app runtime"', 'sleep', 'infinity')

async def allow_sleep_linux(process):
    # Terminate the process that was preventing sleep
    if process:
        process.terminate()
        await process.wait()  # Wait for the process to terminate

async def prevent_sleep_termux():
    # Start the Termux wake lock command
    return await asyncio.create_subprocess_exec('termux-wake-lock')

async def allow_sleep_termux():
    # Release the Termux wake lock
    await asyncio.create_subprocess_exec('termux-wake-unlock')

# Cross-platform sleep prevention
async def prevent_sleep():
    system = platform.system()
    
    if system == "Windows":
        await prevent_sleep_windows()
        return None  # No process to return in Windows case
    elif system == "Darwin":  # macOS
        return await prevent_sleep_macos()
    elif "termux" in platform.uname().release.lower():  # Check if it's Termux on Android
        return await prevent_sleep_termux()
    elif system == "Linux":  # Normal Linux
        return await prevent_sleep_linux()
    else:
        raise NotImplementedError(f"Sleep prevention not implemented for OS: {system}")

async def allow_sleep(process=None):
    system = platform.system()
    
    if system == "Windows":
        await allow_sleep_windows()
    elif system in ["Darwin"]:
        if process:
            await allow_sleep_posix(process)
    elif "termux" in platform.uname().release.lower():  # Check if it's Termux on Android
        await allow_sleep_termux()
    elif system == "Linux":
        if process:
            await allow_sleep_linux(process)
    else:
        raise NotImplementedError(f"Sleep allowance not implemented for OS: {system}")

def parse_delay(delay):
    """
    Parses the delay argument to determine whether it's in seconds or a specific time format (HH:MM or HH:MM:SS).
    If a time format is passed (like 21:23), the delay is calculated from the current time until the specified time.
    """
    # Check if the input is in HH:MM:SS or HH:MM format
    time_format = re.match(r'^(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?$', delay)
    
    if time_format:
        hours, minutes, seconds = time_format.groups()
        hours = int(hours)
        minutes = int(minutes)
        seconds = int(seconds) if seconds else 0  # If no seconds provided, default to 0

        # Get current time and target time today
        now = datetime.now()
        target_time = now.replace(hour=hours, minute=minutes, second=seconds, microsecond=0)

        # If the target time has already passed today, schedule it for the next day
        if target_time <= now:
            target_time += timedelta(days=1)

        # Calculate the delay in seconds from now until the target time
        delay_seconds = (target_time - now).total_seconds()
        return delay_seconds
    
    elif delay.isdigit():
        # If the delay is in seconds
        return int(delay)
    
    else:
        raise ValueError("Invalid delay format. Use seconds or time format (HH:MM or HH:MM:SS).")

async def get_user(client, user, mode):   
    try:
        # Fetch the user entity based on the mode (user_id or username)
        if mode == 'user_id' and user['id']:
            return await client.get_entity(user['id'])
        elif mode == 'username' and user['username']:
            return await client.get_entity(user['username'])
        else:
            print(f"[!] Invalid user details: {user}. Skipping.")
            return False
    except Exception as e:
        print(f"Error fetching user: {e}")
        return False


async def fetch_messages(client, target_group, output_path, output_type='text', limit=None, pinned_only=False):
    
    print('Sorry, available only in binary version.')


async def dump(client, target_group, sqlite_db_path):
    
    print('Sorry, available only in binary version.')


async def send_messages(client, members_csv=None, source_group=None, text_file=None, mode='user_id'):
    
    print('Sorry, available only in binary version.')





async def main():
    # parser = argparse.ArgumentParser(description="Telegram Scraper and Adder")



    class CustomArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            sys.stderr.write(f"{self.prog}: error: {message}\n")
            self.print_help()
            sys.exit(2)

    # Create a custom argument parser object
    parser = CustomArgumentParser(
        description=text_bold + "Telegram Scraper and Adder" + color_reset,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )


    subparsers = parser.add_subparsers(dest="command")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Initial setup with data from https://my.telegram.org/apps")
    setup_parser.add_argument("-o", "--output", type=str, help="Output config name", default="config.data")
    setup_parser.add_argument("-p", "--phone", type=str, help="Phone in international format")   
    setup_parser.add_argument("-i", "--api_id", type=str, help="API ID")    
    setup_parser.add_argument("-k", "--api_hash", type=str, help="API hash")  

    # Users command
    users_parser = subparsers.add_parser("users", help="Scrape members from a group")
    users_parser.add_argument("-s", "--source", type=str, help="Source group ID or username", default=None)
    users_parser.add_argument("-o", "--output", type=str, help="Output CSV file", default=None)
    users_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add members to a group")
    add_parser.add_argument("-i", "--input", type=str, help="Input members CSV file", default=None)
    add_parser.add_argument("-s", "--source", type=str, help="Source group ID or username", default=None)
    add_parser.add_argument("-t", "--target", type=str, help="Target group ID or username", default=None)
    add_parser.add_argument("-m", "--mode", type=str, help="Mode of adding ('user_id' or 'username')", default="user_id")
    add_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")
    add_parser.add_argument("-d", "--delay", type=str, help="Delay before starting the task (seconds or HH:MM:SS)")
    
    # Posts command
    dump_parser = subparsers.add_parser("dump", help="Fetch messages and users from a group or channel into sqlite db")
    dump_parser.add_argument("-s", "--source", type=str, help="Source group ID or username")
    dump_parser.add_argument("-o", "--output", type=str, help="Output file", default=None)
    dump_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")

    # Posts command
    posts_parser = subparsers.add_parser("posts", help="Fetch messages from a group or channel")
    posts_parser.add_argument("-s", "--source", type=str, help="Source group ID or username")
    posts_parser.add_argument("-o", "--output", type=str, help="Output file", default=None)
    posts_parser.add_argument("-t", "--type", type=str, choices=['sqlite', 'text', 'json', 'all'], help="Output type", default='text')
    posts_parser.add_argument("-l", "--limit", type=int, help="Limit the number of messages to fetch", default=None)
    posts_parser.add_argument("-p", "--pinned", action="store_true", help="Fetch only pinned messages")
    posts_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")

    # Send command
    send_parser = subparsers.add_parser("send", help="Send messages to users")
    send_parser.add_argument("-i", "--input", type=str, help="Input members CSV file", default=None)
    send_parser.add_argument("-s", "--source", type=str, help="Source group ID or username", default=None)
    send_parser.add_argument("-t", "--text", type=str, help="Text file containing message to send", default=None)
    send_parser.add_argument("-m", "--mode", type=str, help="Mode of user list ('user_id' or 'username')", default="user_id")
    send_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")

    # License
    lic_parser = subparsers.add_parser("license", help="Check the license or create a license request")
    lic_parser.add_argument("-c", "--config", type=str, help="Config file", default="config.data")

    args = parser.parse_args()


    # Function to show detailed help for all subcommands
    def show_detailed_help():
        banner()
        print(f"{color_purple}{text_bold}Telegram Scraper and Adder" + color_reset)
        print(f"\n{text_bold}Usage:{color_reset} tgs.exe [command] [options]")
        print(f"\n{text_bold}Help on commands:{color_reset} tgs.py [command] -h\n")
        
        # Main parser help
        print(f"{text_bold}Commands:{color_reset}\n")
        print(f"{color_sun}{text_bold}setup{color_reset}{color_yellow}        Initial setup with data from {color_blue}https://my.telegram.org/apps{color_reset}")
        print(f"{color_sun}{text_bold}users{color_reset}{color_yellow}        Scrape members from a group{color_reset}")
        print(f"{color_sun}{text_bold}add{color_reset}{color_yellow}          Add members to a group{color_reset}")
        print(f"{color_sun}{text_bold}dump{color_reset}{color_yellow}         Fetch messages and users from a group or channel into sqlite db{color_reset}")
        print(f"{color_sun}{text_bold}posts{color_reset}{color_yellow}        Fetch messages from a group or channel{color_reset}")
        print(f"{color_sun}{text_bold}send{color_reset}{color_yellow}         Send messages to users{color_reset}")
        print(f"{color_sun}{text_bold}license{color_reset}{color_yellow}      Check the license or create a license request{color_reset}")
        
        

    if not args.command:
        print(f"{color_red}No command present!")
        print("")
        show_detailed_help()
        sys.exit(0)


    if args.command == "setup":
        print("Setup...")
        conf_name = "config.data" if not args.output else args.output
        conf_phone = args.phone
        conf_api_id = args.api_id
        conf_api_hash = args.api_hash
        await config_setup(conf_name, conf_phone, conf_api_id, conf_api_hash)
        print(color_yellow)
        parser.print_help()
        print(color_reset)
        sys.exit(0)

    client = await init_client(args.config)  # Ensure this is awaited


    if args.command == "users":
        if args.source is None:
            print(color_red + "[!] No source group ID or username provided. Please select from the list below:" + color_reset)
            groups = await get_groups(client)  # Await the groups
            target_group = await select_group(groups, "source")  # Await this
        else:
            target_group = await get_target_group(client, args.source)  # Await this
        
        output_file = args.output if args.output else f"users/members_{int(time.time())}.csv"
        await scrape_members(client, target_group, output_file)  # Await this

    if args.command == "posts":
        if args.source is None:
            print("[!] No source group ID or username provided.")
            groups = await get_groups(client)  # Await the groups
            target_group = await select_group(groups, "source")  # Await this
        else:
            target_group = await get_target_group(client, args.source)  # Await this

        # Handle the output path
        output_path = os.path.dirname(args.output) if args.output else 'posts'
        if not os.path.exists(output_path):
            os.makedirs(output_path, exist_ok=True)
        
        await fetch_messages(client, target_group, output_path, args.type, args.limit, args.pinned)  # Await this


    if args.command == "dump":
        if args.source is None:
            print("[!] No source group ID or username provided.")
            groups = await get_groups(client)  # Await the groups
            target_group = await select_group(groups, "source")  # Await this
        else:
            target_group = await get_target_group(client, args.source)  # Await this

        # Handle the output path
        output_path = os.path.dirname(args.output) if args.output else 'dump'
        if not os.path.exists(output_path):
            os.makedirs(output_path, exist_ok=True)
        
        await dump(client, target_group, output_path)  # Await this

    if args.command == "add":
        print(color_gray + f"[?] Mode: {args.mode}" + color_reset)
        tmp_delay = None
        
        if args.delay:
            tmp_delay = args.delay
            if tmp_delay.isdigit():
                delay_text = format_time(tmp_delay)
            else:
                delay_text = f"{color_yellow}at {color_cyan}{tmp_delay}"
            print(f"{color_yellow}The process will be executed with a delay {color_red}{delay_text}{color_yellow}.{color_reset}")
        
        if not args.input and not args.source:
            groups = await get_groups(client)  # Await the groups
            source_group = await select_group(groups, "source")  # Await this
            target_group = await select_group(groups, "target")  # Await this
            await add_users_with_delay(client, source_group=source_group, target_group=target_group, mode=args.mode, delay=tmp_delay)  # Await this
        else:        
            # Determine the target group
            target_group = args.target if args.target else None
            target_group = await get_target_group(client, target_group)  # Await this
            
            if args.input:
                await add_users_with_delay(client, members_csv=args.input, target_group=target_group, mode=args.mode, delay=tmp_delay)  # Await this
            elif args.source:
                await add_users_with_delay(client, source_group=args.source, target_group=target_group, mode=args.mode, delay=tmp_delay)  # Await this
    
    # Sending messages
    if args.command == "send":
        # Ensure a text file for the message is provided
        if not args.text:
            print(f"{color_red}[!] Error: No text file provided for the message.")
            return

        # If no source group or members CSV is provided, prompt for group selection
        if args.source is None and args.input is None:
            print(color_red + "[!] No source group ID or members CSV provided. Please select from the list below:" + color_reset)
            groups = await get_groups(client)  # Fetch and await groups
            args.source = await select_group(groups, "source")  # Await group selection

        # Call the send_messages function with the provided arguments
        await send_messages(
            client=client, 
            members_csv=args.input, 
            source_group=args.source, 
            text_file=args.text, 
            mode=args.mode
        )


if __name__ == "__main__":
    asyncio.run(main())