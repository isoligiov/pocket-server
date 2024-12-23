from scapy.all import sniff, ARP
from websockets.sync.client import connect
import ssl
import rel
import threading
import time

CHANNEL_ID = 149

ws = None
websocket_server_url = "wss://streamlineanalytics.net:10001"
last_event_id = None

# WebSocket initialization
def send_websocket_message(data):
    global ws
    try:
        ws.send(data)
    except Exception as e:
        print(f"Failed to send data via WebSocket: {e}")

# Packet handler function
def process_packet(packet):
    global last_event_id
    if ARP in packet and packet[ARP].op == 1:  # ARP request
        # Extract extra payload data
        arppayload = bytes(packet[ARP])[28:]  # Start after standard ARP payload
        if len(arppayload) < 2 or arppayload[0] != CHANNEL_ID:
            return
        event_id = arppayload[1]
        if last_event_id == event_id:
            return
        last_event_id = event_id
        extra_data = arppayload[2:].decode('utf-8', errors='ignore').strip('\x00')
        if len(extra_data) > 0:
            print(extra_data)
            send_websocket_message(extra_data)


def sniff_thread():
    print("Starting packet capture on ARP...")
    sniff(filter="arp", prn=process_packet, store=0)

if __name__ == "__main__":

    sniff_handler = threading.Thread(target=sniff_thread)
    sniff_handler.start()

    while True:
        try:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            with connect(websocket_server_url, ssl=ssl_context) as _ws:
                ws = _ws
                print('Opened connection')
                while True:
                    time.sleep(.1)
        except Exception as e:
            print('ERR', e)
        time.sleep(10)