from scapy.all import sniff, ARP
import websocket
import ssl
import rel
import time

CHANNEL_ID = 149

# WebSocket server address
ws = None
websocket_server_url = "wss://streamlineanalytics.net:10001"  # Replace with your server URL

# WebSocket initialization
def send_websocket_message(data):
    try:
        ws.send(data)
        print(f"Sent data to WebSocket server: {data}")
    except Exception as e:
        print(f"Failed to send data via WebSocket: {e}")

# Packet handler function
def process_packet(packet):
    if ARP in packet and packet[ARP].op == 1:  # ARP request
        # Extract extra payload data
        arppayload = bytes(packet[ARP])[28:]  # Start after standard ARP payload
        if len(arppayload) == 0 or arppayload[0] != CHANNEL_ID:
            return
        extra_data = arppayload[1:].decode('utf-8', errors='ignore').strip('\x00')
        print(extra_data)
        if extra_data:
            print(f"Extracted extra data: {extra_data}")
            send_websocket_message(extra_data)

def on_error(ws, error):
    print(error)
    time.sleep(5)
    reconnect()

def on_close(ws, close_status_code, close_msg):
    print("### closed ###")
    time.sleep(5)
    reconnect()

def reconnect():
    ws = websocket.WebSocketApp(f"wss://streamlineanalytics.net:10010",
                              on_error=on_error,
                              on_close=on_close)

    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, dispatcher=rel, reconnect=5)

if __name__ == "__main__":
    websocket.enableTrace(False)
    reconnect()

    print("Starting packet capture on ARP...")
    sniff(filter="arp", prn=process_packet, store=0)

    rel.signal(2, rel.abort)  # Keyboard Interrupt
    rel.dispatch()
