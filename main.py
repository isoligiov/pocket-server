from scapy.all import sniff, ARP
from websockets.sync.client import connect
import threading
import time

CHANNEL_ID = 149

ws = None
websocket_server_url = "ws://5.133.9.244:10001"
last_event_id = None
stop_event = threading.Event()  # Event to signal stopping the main loop

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

def send_ping(ws):
    while not stop_event.is_set():
        try:
            ws.send("ping")
            print("Sent ping message")
        except Exception as e:
            print("Ping failed:", e)
            stop_event.set()  # Signal the main thread to stop
        time.sleep(30)  # Send ping every 30 seconds

if __name__ == "__main__":

    sniff_handler = threading.Thread(target=sniff_thread)
    sniff_handler.start()

    while True:
        try:
            with connect(websocket_server_url) as _ws:
                ws = _ws
                print('Opened connection')

                stop_event.clear()
                # Start a background thread for pinging
                ping_thread = threading.Thread(target=send_ping, args=(ws,), daemon=True)
                ping_thread.start()

                while not stop_event.is_set():
                    time.sleep(.1)
                ws.close()
                print('Closed connection')
        except Exception as e:
            print('ERR', e)
        time.sleep(10)