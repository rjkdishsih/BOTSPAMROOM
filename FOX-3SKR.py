import requests
import time
import socket
import os
import sys
import threading
import re
import random
import subprocess
import select
import json
import urllib3
import struct
website = "https://api-ghost.vercel.app/FFcrypto/{id}"
def fake_friend(client, id: str):
        if len(id) == 8:
            packet = "060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b20202020434f4445585b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201"
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:
            packet = "060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a4434f44455820205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221"
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)
def Encrypt_ID(id):
        api_url = website.format(id=id)
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.text
            else:
                print("&#1601;&#1588;&#1604; &#1601;&#1610; &#1580;&#1604;&#1576; &#1575;&#1604;&#1576;&#1610;&#1575;&#1606;&#1575;&#1578;. &#1585;&#1605;&#1586; &#1575;&#1604;&#1581;&#1575;&#1604;&#1577;:", response.status_code)
                return None
        except requests.RequestException as e:
            print("&#1601;&#1588;&#1604; &#1575;&#1604;&#1591;&#1604;&#1576;:", e)
            return None
####################################
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
####################################
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_UNDERLINE = "\033[4m" 
####################################
username = "bot"
password = "bot"
SOCKS5_VERSION = 5
server_list = []
op = None
clientC = None
spam_emote = False
spamm = False
back_normal = False
back_spam = False
yt = None
add_fake = False
comand = False
romcode = None
####################################
def get_random_color():
    color = random.choice([
        "[cُ][bَ][FF0000]",
        "[cُ][bَ][00FF00]",
        "[cُ][bَ][0000FF]",
        "[cُ][bَ][FFFF00]",
        "[cُ][bَ][FFA500]",
        "[cُ][bَ][800080]",
        "[cُ][bَ][808080]",
        "[cُ][bَ][FFD700]",
        "[cُ][bَ][00FFFF]",
        "[cُ][bَ][FF1493]",
        "[cُ][bَ][8A2BE2]",
        "[cُ][bَ][A52A2A]",
        "[cُ][bَ][DC143C]",
        "[cُ][bَ][00CED1]",
        "[cُ][bَ][FF4500]",
        "[cُ][bَ][2E8B57]",
        "[cُ][bَ][ADFF2F]",
        "[cُ][bَ][4682B4]",
        "[cُ][bَ][40E0D0]",
        "[cُ][bَ][DA70D6]",
        "[cُ][bَ][F4A460]",
        "[cُ][bَ][FF6347]",
        "[cُ][bَ][7FFF00]",
        "[cُ][bَ][BA55D3]",
        "[cُ][bَ][FF69B4]",
        "[cُ][bَ][E9967A]",
    ])
    return color
#####EDIT PACKET FOR SEND MESSAGEL#####
def send_msg_friends(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10]
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]
	pyloadbody2 = packet[34:60]
	pyloadlength = packet[60:62]
	pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
	Tipy = packet[int(int(len(pyloadtext))+62):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	Nepalh = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
	Nepylh = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
	st_pack = hd + Nepalh + paketBody + Nepylh + pyloadbody2 + NewTextLength + replay + Tipy
	return st_pack
def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"
        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))
def gen_msg4(packet, content):
        content = content.encode("utf-8")
        content = content.hex()
        header = packet[0:8]
        packetLength = packet[8:10]
        packetBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2 = packet[34:62]
        pyloadlength = packet[62:64]
        pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+64):]
        NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
        NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
        NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
        return str(NewMsgPacket)
def gen_msgv3(packet , replay):
        replay = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10] #
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2= packet[34:60]
        pyloadlength = packet[60:62]
        pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return str(finallyPacket)
def gen_msgv2_clan(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    else:
        pyloadlength = packet[64:66]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])    
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
def gen_msgv2(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:60]
    pyloadlength = packet[60:62]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+62):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
def send_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(gen_msg4(packet, content)))              
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                pass
def send_msg_clan(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]#
	pyloadbody2 = packet[34:64]
	if "googleusercontent" in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
	elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
		print(bytes.fromhex(pyloadlength))
	else:
		pyloadlength = packet[64:66]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+66):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
	st_pack = hd + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + Tipy
	return st_pack
def send_msg_clan(replay, packet):
	replay  = replay.encode('utf-8')
	replay = replay.hex()
	hd = packet[0:8]
	packetLength = packet[8:10] #
	paketBody = packet[10:32]
	pyloadbodyLength = packet[32:34]#
	pyloadbody2 = packet[34:64]
	if "googleusercontent" in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
	elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
		pyloadlength = packet[64:68]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+68):]
		print(bytes.fromhex(pyloadlength))
	else:
		pyloadlength = packet[64:66]#
		pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
		Tipy = packet[int(int(len(pyloadtext))+66):]
	NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
	if len(NewTextLength) ==1:
		NewTextLength = "0"+str(NewTextLength)
	NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
	NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
	st_pack = hd + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + Tipy
	return st_pack
##############DEF LIKES###############

###############DEF INFO##############
def get_status(user_id):
    try:
        r = requests.get(f'https://ff.garena.com/api/antihack/check_banned?lang=en&uid={user_id}')
        if "0" in r.text:
            return f"{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Clear!"
        else:
            return "{get_random_color()}▶PLAYER STATUS: {get_random_color()} Account Ban!"
    except Exception as e:
        return f"Error checking status: {e}"
def get_player_info(user_id):
    try:
        cookies = {
            '_ga': 'GA1.1.2123120599.1674510784',
            '_fbp': 'fb.1.1674510785537.363500115',
            '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
            'source': 'mb',
            'region': 'MA',
            'language': 'ar',
            '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
            'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
            'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
        }
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://shop2game.com',
            'Referer': 'https://shop2game.com/app/100067/idlogin',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'accept': 'application/json',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'x-datadome-clientid': '20ybNpB7Icy69F~RH~hbsvm6XFZADUC-2_--r5gBq49C8uqabutQ8DV_IZp0cw2y5Erk-KbiNZa-rTk1PKC900mf3lpvEP~95Pmut_FlHnIXqxqC4znsakWbqSX3gGlg',
        }
        json_data = {
            'app_id': 100067,
            'login_id': str(user_id),
            'app_server_id': 0,
        }
        response = requests.post(
            'https://shop2game.com/api/auth/player_id_login',
            cookies=cookies,
            headers=headers,
            json=json_data
        )

        if response.status_code == 200:
            player_info = response.json()
            if 'region' in player_info and 'nickname' in player_info:
                return {
                    "region": f"{get_random_color()}\n\n⏯PLAYER REGION: {player_info['region']}\n\n",
                    "nickname": f"{get_random_color()}\n\n⏭PLAYER NAME: {player_info['nickname']}\n\n"
                }
            else:
                return {"error": "Invalid response format"}
        else:
            return {"error": f"Failed to fetch player info: {response.status_code}"}

    except Exception as e:
        return {"error": f"Error fetching player info: {e}"}
##########DEF INFO REGION############
def getname(Id):    
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("ERROR")
    except:
        return("Name unknown??")
####################################
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
####################################
####################################
##########CLASS SOCKET!!!#############
def handle_client(connection):
    try:
        version, nmethods = connection.recv(2)
        methods = get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS5_VERSION, 2]))
        if not verify(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            domain = connection.recv(domain_length).decode('utf-8')
            address = socket.gethostbyname(domain)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.connect((address, port))
        except Exception as e:
            print(f"Failed to connect to remote: {e}")
            connection.close()
            return
        serverlog(address, port)
        bind_address = remote.getsockname()
        addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
        port = bind_address[1]
        reply = b"".join([
            SOCKS5_VERSION.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            int(1).to_bytes(1, 'big'),
            addr.to_bytes(4, 'big'),
            port.to_bytes(2, 'big')
        ])
        connection.sendall(reply)
        exchange_loop(connection, remote, port2)
    except Exception as e:
        print(f"ERROR IN handle_client: {e}")
def verify(connection):
    try:
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username_received = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password_received = connection.recv(password_len).decode('utf-8')
        if username_received == username and password_received == password:
            connection.sendall(bytes([version, 0]))
            return True
        connection.sendall(bytes([version, 0xFF]))
        connection.close()
        return False
    except Exception as e:
        print(f"ERROR IN verify: {e}")
        return False
def get_available_methods(nmethods, connection):
    try:
        return [connection.recv(1)[0] for _ in range(nmethods)]
    except Exception as e:
        print(f"ERROR IN get_available_methods: {e}")
        return []
def serverlog(address, port):
    server_info = f"{address}:{port}"
    if server_info not in server_list:
        server_list.append(server_info)
##########exchange_loop###############
def exchange_loop(client, remote, port):
    global codes, clientC, spamm, add_fake, back_normal, data_join, op,back_spam, romcode
    code_verified = False
    if port == 39699:
        clientC = client
        op = client
    try:
        while True:
            r, _, _ = select.select([client, remote], [], [])
            if client in r:
                dataC = client.recv(4096)
                if '0e15' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :
                    data_join=dataC
                if spamm and '0e15' in dataC.hex()[0:4]:
                    for _ in range(9999999999):
                        remote.send(dataC)
                        time.sleep(0.05)
                if remote.send(dataC) <= 0:
                    break
            if remote in r:
                dataS = remote.recv(4096)
                if b"3SKR" in dataS or b"VIP-CODE-CODEX-7DAY-BOT" in dataS:
                    code_verified = True
                    client.send(bytes.fromhex("120000013908c5aa88e626101220022aac0208c5aa88e6261092c4c5ee271802226a5b63d98f5d5b62d98e5d5b3030464646465de385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a44652454520434f444520332044415921212120e385a4e385a4e385a4e385a4e385a4e385a428f3eb91bd064a310a12434f4445583ae385a4e385a4464f58e298aa10bedd8dae0320c9014212e385a4e385a4434f444558e385a4424f54535202656e6a660a6068747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a446b484d6f41782d4253794755676e3671474f4d7a755077555673526e675f434a41717941644261797768317634773d7339362d63100118017200800180b09ad3f4fddd981a"))
                pack = dataS.hex()
                
                if "0f0000" in dataS.hex()[0:6] and "0f15" in dataC.hex()[0:4] and add_fake == True:
                	time.sleep(5)
                	id_add = dataS.hex()[-10:]
                	print(id_add)
                	op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b4642423131375d4344582be385a4464f58585b4642423131375d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                if "0f0000" in dataS.hex()[0:6] and len(dataS.hex()) == 52 and "0f15" in dataC.hex()[0:4] and add_fake == True:
                   time.sleep(5)
                   id_add = dataS.hex()[-10:]
                   op.send(bytes.fromhex(f"060000006808d4d7faba1d100620022a5c08{id_add}1a1b5b4642423131375d4344582be385a4464f58585b4642423131375d32024d45404db00113b801a528d801d4d8d0ad03e00101b801e807f00101f8019a018002fd98a8dd03900201d0020cd8022ee002b2e9f7b103"))
                if '0e00' in dataS.hex()[0:4]:
                    for i in range(10):
                        pattern = fr"x0{str(i)}(\d+)Z"
                        match = re.search(pattern, str(dataS))
                        if match:
                            number = match.group(1)
                            global romcode
                            romcode = number
                            print(romcode)
                if code_verified and b"/ROM-CODE" in dataS:
                    newdataS2 = dataS.hex()
                    getin = client
                    rom = f""
                    client.send(bytes.fromhex(send_msg_clan(f"{get_random_color()}\nROM CODE: {romcode}\n", dataS.hex())))
####################################
                elif code_verified and  b"/CHECK+" in dataS:
                             parts = dataS.split(b"/CHECK+")
                             user_id = parts[1].split(b"\x28")[0].decode("utf-8")
                             b = get_player_info(user_id)
                             bb = get_status(user_id)
                             if "error" in bb:
                                 print(bb["error"])
                             else:
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), bb, 0.2)).start()
                                 time.sleep(1)
                                 reg = b["region"]
                                 nick = b["nickname"]
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), reg, 0.2)).start()
                                 threading.Thread(target=send_msg, args=(client, dataS.hex(), nick, 0.2)).start()
####################################
                if b"@FOX-R" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d52(.*?)28', pack)[0])).decode('utf-8', errors='ignore')
                        ress = f"[cُ][bَ][FF0000]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-G" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d47(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][00FF00]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-Y" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d59(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FFFF00]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-V" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d56(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][2ECC71]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-B" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d42(.*?)28', pack)[0])).decode('utf-8') 
                        ress = f"[cُ][bَ][0000FF]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-O" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FFA500]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-GY" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4759(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][808080]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-GD" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4744(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FFD700]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-CY" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4359(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][00FFFF]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-PK" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d504b(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FF1493]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-DV" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4456(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][8A2BE2]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-BR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4252(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][A52A2A]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-CR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4352(.*?)28', pack)[0])).decode('utf-8')                   
                        ress = f"[cُ][bَ][DC143C]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-TQ" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d5451(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][00CED1]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-OR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f52(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][2ECC71]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-DG" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4447(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][2E8B57]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-LY" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4c59(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][ADFF2F]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-LB" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4c42(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][4682B4]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-TZ" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d545a(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][40E0D0]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-LV" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4c56(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][DA70D6]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-BGD" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4244(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][F4A460]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-TM" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d5450(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FF6347]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-LM" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4c4d(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][7FFF00]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-MV" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4d56(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][BA55D3]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-HK" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4854(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][FF69B4]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
                if b"@FOX-LOR" in dataS:
                        idd = (bytes.fromhex(re.findall(r'40464f582d4f52(.*?)28', pack)[0])).decode('utf-8')
                        ress = f"[cُ][bَ][E9967A]{idd}"
                        threading.Thread(target=send_msg, args=(client, dataS.hex(), ress, 0.2)).start()
####################################
                if code_verified and  b"/HELP" in dataS and '1200' in dataS.hex():
                                ewdataS2 = dataS.hex()
                                client.send(bytes.fromhex("12 00 00 01 32 08 C5 AA 88 E6 26 10 12 20 02 2A A5 02 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 63 5B 46 46 30 30 30 30 5D E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 57 65 6C 63 6F 6D 65 20 46 4F 58 20 42 4F 54 20 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 28 EE E8 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A B7 AC DE AE 98 1A"))
                                time.sleep(1)
                                client.send(bytes.fromhex( "12 00 00 01 30 08 C5 AA 88 E6 26 10 12 20 02 2A A3 02 08 C5 AA 88 E6 26 10 C0 C5 CE FB 18 18 02 22 61 5B 46 46 46 46 30 30 5D E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 43 4F 4D 4D 41 4E 44 53 20 42 4F 54 3A 20 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 28 D3 F5 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 87 9A A6 B0 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EF 08 9A E5 93 CF 28 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 32 45 43 43 37 31 5D 53 70 61 6D 20 4A 6F 69 6E 20 52 65 71 75 65 73 74 73 3A 20 2F 49 4E 56 28 E5 FA 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A AD C8 F6 B0 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex( "12 00 00 00 F8 08 C5 AA 88 E6 26 10 12 20 02 2A EB 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 29 5B 32 45 43 43 37 31 5D 41 64 64 20 59 6F 75 54 75 62 65 72 20 61 73 20 61 20 46 72 69 65 6E 64 3A 20 2F 46 4F 58 2D 59 54 28 E9 F9 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 8D B8 E7 B0 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex( "12 00 00 00 ED 08 C5 AA 88 E6 26 10 12 20 02 2A E0 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1E 5B 32 45 43 43 37 31 5D 46 61 6B 65 20 46 72 69 65 6E 64 3A 20 2F 46 4F 58 2D 46 41 4B 45 28 E7 FE 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A C5 9A B5 B1 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex( "12 00 00 00 ED 08 C5 AA 88 E6 26 10 12 20 02 2A E0 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1E 5B 32 45 43 43 37 31 5D 35 20 50 6C 61 79 65 72 73 20 69 6E 20 54 65 61 6D 3A 20 2F 35 73 28 A0 FD 8E BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 95 80 9D B1 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 FB 08 C5 AA 88 E6 26 10 12 20 02 2A EE 01 08 C5 AA 88 E6 26 10 C0 C5 CE FB 18 18 02 22 2C 5B 32 45 43 43 37 31 5D 52 61 72 65 20 53 70 65 63 69 61 6C 20 44 61 6E 63 65 73 3A 20 40 41 31 30 20 2D 2D 2D 2D 3E 20 40 41 32 30 28 B0 8F 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A AF 97 B8 B3 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F9 08 C5 AA 88 E6 26 10 12 20 02 2A EC 01 08 C5 AA 88 E6 26 10 C0 C5 CE FB 18 18 02 22 2A 5B 32 45 43 43 37 31 5D 52 61 72 65 20 53 70 65 63 69 61 6C 20 44 61 6E 63 65 73 3A 20 2F 41 31 20 2D 2D 2D 2D 3E 20 2F 41 39 28 9B 8D 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F5 AB 96 B3 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EC 08 C5 AA 88 E6 26 10 12 20 02 2A DF 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1D 5B 32 45 43 43 37 31 5D 47 65 74 20 50 43 20 42 61 64 67 65 3A 20 2F 70 63 5B 69 64 5D 28 D9 8A 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A C9 8A EF B2 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F3 08 9A E5 93 CF 28 10 12 20 02 2A E6 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 24 5B 32 45 43 43 37 31 5D 57 65 61 70 6F 6E 20 44 61 6E 63 65 73 3A 20 2F 45 31 20 2D 2D 2D 2D 3E 20 2F 45 38 28 CB 91 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A DD E3 DA B3 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F0 08 9A E5 93 CF 28 10 12 20 02 2A E3 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 21 5B 32 45 43 43 37 31 5D 4E 4F 52 4D 41 4C 20 42 41 43 4B 3A 20 2F 42 41 43 4B 2D 4E 4F 52 4D 41 4C 28 DB 9D 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 BE DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A CD 94 98 B5 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F3 08 9A E5 93 CF 28 10 12 20 02 2A E6 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 24 5B 32 45 43 43 37 31 5D 44 69 73 61 70 70 65 61 72 20 69 6E 20 53 71 75 61 64 3A 20 2F 46 4F 58 2D 53 50 59 28 AF 97 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 BE DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A CB 8B B5 B4 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EC 08 9A E5 93 CF 28 10 12 20 02 2A DF 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1D 5B 32 45 43 43 37 31 5D 53 50 41 4D 20 42 41 43 4B 3A 20 2F 42 41 43 4B 2D 53 50 41 4D 28 BC 9E 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 BE DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A AF 89 A4 B5 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F9 08 C5 AA 88 E6 26 10 12 20 02 2A EC 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 2A 5B 32 45 43 43 37 31 5D 53 50 41 4D 20 4D 45 53 53 41 47 45 20 46 41 4B 45 3A 2F 40 53 20 57 48 49 54 20 4D 45 53 53 41 47 45 28 9C A4 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A C1 E9 FD B5 98 1A"))
#                                time.sleep(0.5)
#                                client.send(bytes.fromhex("12 00 00 00 ED 08 9A E5 93 CF 28 10 12 20 02 2A E0 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1E 5B 32 45 43 43 37 31 5D 50 4C 41 59 45 52 20 49 4E 46 4F 3A 2F 49 4E 46 4F 2B 5B 69 64 5D 28 DE A5 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A C1 C6 95 B6 98 1A"))
#                                time.sleep(0.5)
#                                client.send(bytes.fromhex("12 00 00 00 EF 08 9A E5 93 CF 28 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 32 45 43 43 37 31 5D 41 44 44 20 31 30 30 20 4C 49 4B 45 53 3A 4C 49 4B 45 53 2B 5B 69 64 5D 28 DB A6 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F5 DF A4 B6 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EF 08 C5 AA 88 E6 26 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 32 45 43 43 37 31 5D 43 4F 4C 4F 52 20 59 4F 55 52 20 4D 45 53 53 41 47 45 3A 2F 53 48 4F 57 28 F6 B9 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F1 F9 D0 B8 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EA 08 9A E5 93 CF 28 10 12 20 02 2A DD 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1B 5B 32 45 43 43 37 31 5D 53 50 59 20 49 4E 20 52 4F 4D 3A 2F 52 4F 4D 2D 53 50 59 28 9F A9 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 87 AB CC B6 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F9 08 C5 AA 88 E6 26 10 12 20 02 2A EC 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 2A 5B 32 45 43 43 37 31 5D 43 48 45 43 4B 20 42 41 4E 20 49 44 20 41 4E 44 20 52 45 47 49 4F 4E 3A 43 48 45 43 4B 2B 5B 69 64 5D 28 E6 A7 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 81 C0 9A A9 E4 B5 B6 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12000000ef08c5aa88e626101220022ae20108c5aa88e62610c0c5cefb18180222205b3245434337315d47455420524f4d20434f44453a202f524f4d2d434f44452228aa989abd064a310a12434f4445583ae385a4e385a4464f58e298aa10bedd8dae0320c9014212e385a4e385a4434f444558e385a4424f54535202656e6a660a6068747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a446b484d6f41782d4253794755676e3671474f4d7a755077555673526e675f434a41717941644261797768317634773d7339362d63100118017200800180c09a8189b4e0991a"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F9 08 C5 AA 88 E6 26 10 12 20 02 2A EC 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 2A 5B 32 45 43 43 37 31 5D 43 48 45 43 4B 20 42 41 4E 20 49 44 20 41 4E 44 20 52 45 47 49 4F 4E 3A 43 48 45 43 4B 2B 5B 69 64 5D 28 E6 A7 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 81 C0 9A A9 E4 B5 B6 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12000000f308c5aa88e626101220022ae60108c5aa88e62610c0c5cefb18180222245b3245434337315d414444203130303030204449414d4f4e442046414b453a2f4449414d2893849bbd064a310a12434f4445583ae385a4e385a4464f58e298aa10bedd8dae0320c9014212e385a4e385a4434f444558e385a4424f54535202656e6a660a6068747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a446b484d6f41782d4253794755676e3671474f4d7a755077555673526e675f434a41717941644261797768317634773d7339362d63100118017200800180c09aa9dcc8ed991a"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12000000df08c5aa88e626101220022ad20108c5aa88e62610c0c5cefb18180222245b3245434337315d53544f50205350414d20496e7669746174696f6e733a202f2d494e562882849bbd064a1d0a12434f4445583ae385a4e385a4464f58e298aa10bedd8dae0320c9015202656e6a660a6068747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a446b484d6f41782d4253794755676e3671474f4d7a755077555673526e675f434a41717941644261797768317634773d7339362d63100118017200800180c09ac9dfc6ed991a"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12000000eb08c5aa88e626101220022ade0108c5aa88e62610c0c5cefb181802221c5b3245434337315d4144442046414b4520474f4c443a202f474f4c44288f849bbd064a310a12434f4445583ae385a4e385a4464f58e298aa10bedd8dae0320c9014212e385a4e385a4434f444558e385a4424f54535202656e6a660a6068747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634a446b484d6f41782d4253794755676e3671474f4d7a755077555673526e675f434a41717941644261797768317634773d7339362d63100118017200800180c09ad1a6c8ed991a"))
#                                time.sleep(0.5)
#                                client.send(bytes.fromhex("12 00 00 00 EF 08 9A E5 93 CF 28 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 32 45 43 43 37 31 5D 41 44 44 20 31 30 30 20 4C 49 4B 45 53 3A 4C 49 4B 45 53 2B 5B 69 64 5D 28 DB A6 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F5 DF A4 B6 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 01 3C 08 C5 AA 88 E6 26 10 12 20 02 2A AF 02 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 6D 5B 46 46 30 30 30 30 5D E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 42 4F 54 20 4D 41 44 45 20 42 59 20 46 4F 58 20 41 4E 44 20 53 4E 4F 50 49 20 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 28 F2 D2 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A E9 87 D7 BB 98 1A"))
                                time.sleep(0.5)
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 01 3A 08 C5 AA 88 E6 26 10 12 20 02 2A AD 02 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 6B 5B 46 46 30 30 30 30 5D E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 43 6F 44 65 58 20 4C 6F 56 20 55 20 47 75 79 73 20 E2 9D A4 EF B8 8F 20 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 E3 85 A4 28 C1 D3 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A E5 E0 E0 BB 98 1A"))
                                time.sleep(0.5) 
####################################
                elif code_verified and  b"/SHOW" in dataS:
                                client.send(bytes.fromhex("12 00 00 00 E9 08 9A E5 93 CF 28 10 12 20 02 2A DC 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1A 5B 46 42 42 31 31 37 5D 20 41 56 41 49 4C 41 42 4C 45 20 43 4F 4C 4F 52 53 3A 28 CF BA 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A D1 E6 DB B8 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F1 08 9A E5 93 CF 28 10 12 20 02 2A E4 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 22 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 6C 69 67 68 74 20 70 69 6E 6B 20 3A 2F 40 46 4F 58 2D 50 4B 28 F9 C3 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A C3 CA ED B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EE 08 9A E5 93 CF 28 10 12 20 02 2A E1 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1F 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 53 63 61 72 6C 65 74 20 3A 2F 40 46 4F 58 2D 43 52 28 BE C3 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A E3 B1 E6 B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F5 08 9A E5 93 CF 28 10 12 20 02 2A E8 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 26 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 72 65 64 64 69 73 68 20 6F 72 61 6E 67 65 20 3A 2F 40 46 4F 58 2D 4F 52 28 C6 C2 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A EF DA D7 B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F1 08 9A E5 93 CF 28 10 12 20 02 2A E4 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 22 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 44 61 72 6B 20 67 72 65 65 6E 20 3A 2F 40 46 4F 58 2D 44 47 28 DC BF 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 81 C0 9A F3 C4 AB B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F1 08 C5 AA 88 E6 26 10 12 20 02 2A E4 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 22 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 4C 69 67 68 74 20 62 6C 75 65 20 3A 2F 40 46 4F 58 2D 4C 42 28 E7 BE 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 95 A0 9D B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F3 08 C5 AA 88 E6 26 10 12 20 02 2A E6 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 24 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 6C 69 67 68 74 20 79 65 6C 6C 6F 77 20 3A 2F 40 46 4F 58 2D 4C 59 28 89 BE 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F9 E8 91 B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F0 08 C5 AA 88 E6 26 10 12 20 02 2A E3 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 21 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 54 75 72 71 75 6F 69 73 65 20 3A 2F 40 46 4F 58 2D 54 5A 28 93 BD 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A DF AB 83 B9 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F3 08 9A E5 93 CF 28 10 12 20 02 2A E6 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 24 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 4C 69 67 68 74 20 70 75 72 70 6C 65 20 3A 2F 40 46 4F 58 2D 4C 56 28 CE BB 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 81 C0 9A F5 A9 EB B8 98 1A"))
                                time.sleep(0.5)
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EC 08 C5 AA 88 E6 26 10 12 20 02 2A DF 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1D 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 59 65 6C 6C 6F 77 20 3A 2F 40 46 4F 58 2D 59 28 9C C7 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A A9 E2 A0 BA 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EF 08 C5 AA 88 E6 26 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 48 65 61 76 65 6E 6C 79 20 3A 2F 40 46 4F 58 2D 43 59 28 AA C5 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A CF 9A 83 BA 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EA 08 C5 AA 88 E6 26 10 12 20 02 2A DD 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1B 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 42 6C 75 65 20 3A 2F 40 46 4F 58 2D 42 28 DC C7 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A D7 CA A8 BA 98 1A"))
                                time.sleep(0.5)
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 ED 08 C5 AA 88 E6 26 10 12 20 02 2A E0 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1E 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 47 6F 6C 64 65 6E 20 3A 2F 40 46 4F 58 2D 47 44 28 E6 CA 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A F3 D3 D8 BA 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EB 08 9A E5 93 CF 28 10 12 20 02 2A DE 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1C 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 47 72 65 79 20 3A 2F 40 46 4F 58 2D 47 59 28 A3 CA 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A BD BD D0 BA 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EF 08 C5 AA 88 E6 26 10 12 20 02 2A E2 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 20 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 56 69 6F 6C 65 74 20 3A 2F 40 46 4F 58 2D 56 E3 85 A4 28 B5 C9 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 8B 89 C3 BA 98 1A"))
                                time.sleep(0.5)
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 EB 08 9A E5 93 CF 28 10 12 20 02 2A DE 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 1C 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 47 72 65 65 6E 20 3A 2F 40 46 4F 58 2D 47 28 E3 C8 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A D3 8A B9 BA 98 1A"))
                                time.sleep(0.5)
                                client.send(bytes.fromhex("12 00 00 00 F2 08 C5 AA 88 E6 26 10 12 20 02 2A E5 01 08 C5 AA 88 E6 26 10 9A E5 93 CF 28 18 02 22 23 5B 46 42 42 31 31 37 5D 43 4F 4C 4F 52 20 44 61 72 6B 20 70 75 72 70 6C 65 20 3A 2F 40 46 4F 58 2D 44 56 28 A9 CB 8F BD 06 4A 31 0A 12 43 4F 44 45 58 3A E3 85 A4 E3 85 A4 46 4F 58 E2 98 AA 10 B2 DD 8D AE 03 20 C9 01 42 12 E3 85 A4 E3 85 A4 43 4F 44 45 58 E3 85 A4 42 4F 54 53 52 02 65 6E 6A 66 0A 60 68 74 74 70 73 3A 2F 2F 6C 68 33 2E 67 6F 6F 67 6C 65 75 73 65 72 63 6F 6E 74 65 6E 74 2E 63 6F 6D 2F 61 2F 41 43 67 38 6F 63 4A 44 6B 48 4D 6F 41 78 2D 42 53 79 47 55 67 6E 36 71 47 4F 4D 7A 75 50 77 55 56 73 52 6E 67 5F 43 4A 41 71 79 41 64 42 61 79 77 68 31 76 34 77 3D 73 39 36 2D 63 10 01 18 01 72 00 80 01 80 C0 9A 9D E2 E0 BA 98 1A"))
####################################
                elif b"/FOX-SPY" in dataS:
            	    op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))
####################################
                elif code_verified and  b"/FOX-FAKE" in dataS:
                    i = re.split('/FOX-FAKE', str(dataS))[1]
                    if '***' in i:
                        i = i.replace('***', '106')
                    id = str(i).split('(\\x')[0]
                    id = Encrypt_ID(id)
                    fake_friend(op, id)
#                elif code_verified and  b"/FOX-FAKE" in dataS:
#                    add_fake = True
#                elif code_verified and  b"@FOX-FAKE" in dataS:
#                    add_fake = False
####################################
                elif code_verified and  b"/ROM-SPY" in dataS:
                    op.send(b"\x0e\x15\x00\x00\x00P\xd6\xd5\x19\x00+\xdc\xc6M\xe8\xa4,\x1a\xae\xdf\\:\xaa\xcf|\xe6\x94\xef\xbf\xc1\xf1\x1f\x02h\t\xb6%\xe7\x93aM\xd1?\xfa8\xee\xccUO\xf3 \xa6\x1b\x8a\xc6\x96\x99\xa8\xeb^\xda\xb7;9\xe9\xd9\x10zP\xd5\xe0\x83\xa2\xbc\x8c\x01\xfb\xadd\xdb\xcek\x85\x81\xcdP")
####################################
                elif code_verified and   b"/sp" in dataS and '1200' in dataS.hex()[0:4]:
                        spamm = True
                elif code_verified and   b"/-sp" in dataS and '1200' in dataS.hex()[0:4]:
                        spamm = False
####################################
                elif code_verified and  b"/A1" in dataS: 
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1088b3bbb1032a0608*"             
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and  b"/A2" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1098fbb8b1032a0608*"         
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and  b"/A3" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109bfbb8b1032a0608*"                            
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and  b"/A4" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d2c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and  b"/A5" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10dcc2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/A6" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10bbfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/A7" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109284bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))  
                elif code_verified and   b"/A8" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109cfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/A9" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10aefcbab1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E1" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10fffab8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E2" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ff8bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E3" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1095fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E4" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*108bfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E5" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10edbabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E6" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10a2fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"/E7" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1084fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A10" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10b9cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A11" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ca9bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A12" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109e84bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A13" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109684bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A14" in dataS:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d6c2bbb1032a0608*"
                            raks = dor.replace('*', id)                                 
                            clientC.send(bytes.fromhex(raks))              
                elif code_verified and   b"@A15" in dataS: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a1d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A16" in dataS: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a3d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and  b"@A17" in dataS: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a2d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))           
                elif code_verified and   b"@A18" in dataS: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a5d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                elif code_verified and   b"@A19" in dataS: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10d7c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))              
                elif code_verified and  b"@A20" in dataS: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10c1cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))              
                elif code_verified and  b"/E8" in dataS: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10d8c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
####################################
                elif code_verified and  b"/BACK-SPAM" in dataS:
                    back_spam= True
                    threading.Thread(target=fox_spam_back , args=(data_join,op)).start()
                elif code_verified and  b"/BACK-NORMAL" in dataS:
                    back_normal = True
                    threading.Thread(target=fox_back, args=(data_join, op)).start()
####################################
                elif code_verified and  b"/5s" in dataS:
                    id = dataS.hex()[12:22]
                    op.send(bytes.fromhex(f"05000001ff08{id}1005203a2af20308{id}12024d451801200432f70208{id}1209424c52585f4d6f642b1a024d4520d78aa5b40628023085cbd1303832421880c38566fa96e660c19de061d998a36180a89763aab9ce64480150c90158e80792010801090a12191a1e209801c901c00101e801018802039202029603aa0208080110e43218807daa0207080f10e4322001aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200ea0204100118018a03009203009803b7919db30ba20319c2b27854e19687e197a95fe191ade192aae197a95945e19687e20301523a011a403e50056801721e313732303237323231313638373535353930315f736f3278687a61366e347801820103303b30880180e0aecdacceba8e19a20100b00114ea010449444332fa011e313732303237323231313638373535383330335f71356f79736b3934716d"))
####################################
                elif code_verified and  b"@S " in dataS:
                    threading.Thread(target=spam_antiban, args=(client, dataS)).start()
####################################
                elif code_verified and  b"/pc" in dataS:
	                 	text = str(bytes.fromhex(dataS.hex()))
	                 	pattern = r'/pc(\d+)'
	                 	match = re.search(pattern, text)
	                 	number = match.group(1)
	                 	my_id = dataS.hex()[12:22]
	                 	id_admin = "d3858dd223"
	                 	if len(id_admin) > 8:
	                         name = getname(number)
	                         hex_name = name.encode('utf-8').hex()
	                         hex_name = adjust_text_length(hex_name)
	                         op.send(bytes.fromhex(f'05000003ff08{my_id}100520062af20708{id_admin}12024d451801200332cc0408{id_admin}12135b6564303930395d50454741e2808f535553201a024d4520a6e38baa0628443087cbd13038324218e0f38766e796a3618994e660f39ae061e5b7d064bfb8ce64480150ce01588e0c60f5d7d0ad0368c2dc8dae037a05d7d0cab00382012b08b3daf1eb041211d8b2d98ad988d98ad986d983d983e29cbf180620b687d4f0042a0808c49d85f30410038801ed89c5b00392010b0107090a0b1216191a20239801cd01a00111a80185fff5b103c00101c80101d001bace89af03e80101880203920207c20500a606e532aa020a080110c03e18f0602002aa0205080210b232aa0205080310e432aa020a080f10918a0118a09c01aa0205081710e750aa0205081810b768aa0205081a10da74aa0206081b10918a01aa0206081c10958c01aa02050820108b79aa0205082110eb7aaa0205082210a275aa0206082310dc8701aa0205082b10f476aa0205083110f476aa0206083910918a01aa0206083d10918a01aa0206084110918a01aa0205084910e432aa0205084d10e432aa0206083410918a01aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3237373631373532363237343633352f706963747572653f77696474683d313630266865696768743d31363010011801f202090887cab5ee0110870a8a030808021003180528019203009803f3e78ea30ba20315e298afd986d8a7d8acd988d986d98ae298afe29c9432d00208{my_id}120b{hex_name}1a024d452096ed8baa0628043089cbd13038324214fa96e660b599a361c19de061aab9ce64abb9ce64480150c90158e80792010601090a1219209801c901c00101c80101e80101880204920206ee07ce010000aa0208080110ff34188064aa020b080f10fd3218b086012001aa0205080210e432aa0205081810fd32aa0205081a10fd32aa0205081c10fd32aa0205082010fd32aa0205082210fd32aa0205082110fd32aa0205081710e432aa0205082310fd32aa0205082b10fd32aa0205083110fd32aa0205083910fd32aa0205083d10fd32aa0205084110fd32aa0205084910d836aa0205084d10e432aa0205081b10fd32aa0205083410fd32aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea0204100118018a03009203003a0101400150016801721e313639383838363035353130343733333939355f6a67386c37333431646688018090aefec3978fef17a20100b001e001ea010449444331'))
####################################
                elif code_verified and  b"/GOLD" in dataS:
            	    id = dataS.hex()[12:22]
            	    op.send(bytes.fromhex(f"080000001308{id}100820022a0708a6b10318fa01"))
                elif code_verified and  b"/DIAM" in dataS:
                	id = dataS.hex()[12:22]
                	dor = "080000001608a29b81aa22100820022a0a08e7be0110b24f18c801*"
                	raks = dor.replace('*', id)
                	op.send(bytes.fromhex(raks))
####################################
                elif code_verified and  b"/FOX-YT" in dataS:
                    yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[00ff00]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F"
                    yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![00ff00]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[00ff00]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [00ff00]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[00ff00]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
                    yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[00ff00]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[00ff00]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'
                    yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[00ff00]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[00ff00]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e"
                    yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[00ff00]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[00ff00]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03'
                    yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[00ff00]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[00ff00]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>"
                    yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[00ff00]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[00ff00]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026'
                    yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[00ff00]HEROSHIIMA1[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[00ff00]SH\xe3\x85\xa4SHIMA|M[00ff00]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[00ff00]2JZ\xe3\x85\xa4POWER[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
                    yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[00ff00]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
                    yout13 = b'\x06\x00\x00\x00`\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*T\x08\xd2\xbc\xae\x07\x1a%[00ff00]SYBLUS\xe3\x85\xa4\xe4\xba\x97\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@E\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[00ff00]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[00ff00]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03'
                    yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[00ff00]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
                    yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[00ff00]SVG.NINJA\xe2\xbc\xbd[00ff00]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
                    yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
                    yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[00ff00]FARAMAWY_1M.[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[00ff00]SH\xe3\x85\xa4SHIMA|M[00ff00]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout21 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[00ff00]2JZ\xe3\x85\xa4POWER[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
                    yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[00ff00]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
                    yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[00ff00]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[00ff00]AH\xe3\x85\xa4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
                    yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[00ff00]SVG.NINJA\xe2\xbc\xbd[00ff00]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
                    yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[00ff00]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
                    yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[00ff00]FARAMAWY_1M.[00ff00]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[00ff00]BM\xe3\x85\xa4ABDOU_YT[00ff00]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16"
                    yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[00ff00]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[00ff00]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [00ff00]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[00ff00]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03'
                    yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[00ff00]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[00ff00]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03"
                    yout32 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[00ff00]@EL9YSAR[00ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
                    yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[00ff00]@EL9YSAR[00ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
                    yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[ffff00]GRINGO\xe3\x85\xa4CRONA[00ff00]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01'
                    yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[00ff00]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[00ff00]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03'
                    yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[00ff00]ZAIN_YT_500K[00ffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02('
                    yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([00ff00]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[00ff00]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03'
                    yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([00ff00]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[00ff00]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q'
                    yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[00ff00]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[00ff00]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03'
                    yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[00ff00]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[00ff00]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03'
                    yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[00ff00]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[00ff00]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q'
                    yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[00ff00]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[00ff00]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03'
                    yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[00ff00]BT\xe3\x85\xa4BadroTV[00ff00]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!'
                    yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[00ff00]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[00ff00]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01"
                    yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[00ff00]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[00ff00]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k'
                    yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[00ff00]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[00ff00]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
                    yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [00ff00]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[00ff00]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
                    yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[00ff00]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
                    yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [00ff00]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[00ff00]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                    yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [00ff00]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[00ff00]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
                    yout51 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb8\xa6\x85\xc5\x01\x1a\x1b[00ff00]DARBKA\xe3\x85\xa41M[00ff00]2\x02ME@Q\xb0\x01\x13\xb8\x01\x90(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12LAST\xe2\x80\x8f\xe3\x85\xa4POWER\xe2\x9a\xa1\xf0\x01\x01\xf8\x01\x92\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
                    op.send(yout1)
                    op.send(yout2)
                    op.send(yout3)
                    op.send(yout4)
                    op.send(yout5)
                    op.send(yout6)
                    time.sleep(0.5)
                    op.send(yout7)
                    time.sleep(0.5)
                    op.send(yout8)
                    time.sleep(0.5)
                    op.send(yout9)
                    time.sleep(0.5)
                    op.send(yout10)
                    time.sleep(0.5)
                    op.send(yout11)
                    time.sleep(0.5)
                    op.send(yout12)
                    time.sleep(0.5)
                    op.send(yout13)
                    time.sleep(0.5)
                    op.send(yout14)
                    time.sleep(0.5)
                    op.send(yout15)
                    time.sleep(0.5)
                    op.send(yout16)
                    time.sleep(0.5)
                    op.send(yout17)
                    time.sleep(0.5)
                    op.send(yout18)
                    op.send(yout19)
                    op.send(yout20)
                    op.send(yout21)
                    op.send(yout22)
                    op.send(yout23)
                    op.send(yout24)
                    op.send(yout25)
                    op.send(yout26)
                    op.send(yout28)
                    op.send(yout29)
                    op.send(yout30)
                    op.send(yout31)
                    op.send(yout32)
                    op.send(yout33)
                    op.send(yout34)
                    op.send(yout35)
                    op.send(yout36)
                    op.send(yout37)
                    op.send(yout38)
                    op.send(yout39)
                    op.send(yout40)
                    op.send(yout41)
                    op.send(yout42)
                    op.send(yout43)
                    op.send(yout44)
                    op.send(yout45)
                    op.send(yout46)
                    op.send(yout47)
                    op.send(yout48)
                    op.send(yout49)
                    op.send(yout50)
                    op.send(yout51)
####################################
                if client.send(dataS) <= 0:
                    pass
    except Exception as e:
        print(f"ERROR IN exchange_loop: {e}")
####################################
def fox_spam_back(data_join, op):
        global back_spam
        while back_spam == True:
            for _ in range(50):
                op.send(data_join)
                time.sleep(2.5)               
def fox_back(data_join, op):
        global back_normal
        while back_normal  == True:
             op.send(data_join)
             time.sleep(999.0)
####################################
def spam_antiban(client, dataS):
        for _ in range(50):
            try:
                client.send(dataS)
                time.sleep(0.3)
            except Exception as e:
                print(f"Error in spam_antiban: {e}")
                break
#############START BOT###############
def run(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"Proxy running on ⟩⟩ : {host},{port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn,))
            t.start()
    except Exception as e:
        print(f"ERROR IN run: {e}")
def start_bot():
    run("127.0.0.1", 3000)
if __name__ == "__main__":
    start_bot()
