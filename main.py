from scapy.all import sniff, ARP
import websocket
import ssl
import rel
import threading

CHANNEL_ID = 149

# WebSocket server address
ws = None
websocket_server_url = "wss://streamlineanalytics.net:10001"  # Replace with your server URL
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

def on_error(ws, error):
    print(error)

def on_close(ws, close_status_code, close_msg):
    print("### closed ###")

def on_open(_ws):
    global ws
    print("Opened connection")
    ws = _ws

def sniff_thread():
    print("Starting packet capture on ARP...")
    sniff(filter="arp", prn=process_packet, store=0)

if __name__ == "__main__":
    websocket.enableTrace(False)
    ws = websocket.WebSocketApp(websocket_server_url,
                              on_error=on_error,
                              on_close=on_close,
                              on_open=on_open)

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, dispatcher=rel, reconnect=5, ping_interval=10, ping_timeout=9)

    sniff_handler = threading.Thread(target=sniff_thread)
    sniff_handler.start()

    rel.signal(2, rel.abort)  # Keyboard Interrupt
    rel.dispatch()
