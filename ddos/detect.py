#!/usr/bin/env python3
import time
import numpy as np
import joblib
import tensorflow as tf
import subprocess
from scapy.all import sniff, TCP, UDP, ICMP, IP
from collections import deque, Counter
from threading import Thread, Timer

MODEL_PATH          = "/home/hex/Desktop/DDoS-AI-and-Crypto-Miner-protection/ddos/autoencoder_retrained.h5"
SCALER_PATH         = "/home/hex/Desktop/DDoS-AI-and-Crypto-Miner-protection/ddos/scaler_retrained.pkl"
THRESHOLD_PATH      = "/home/hex/Desktop/DDoS-AI-and-Crypto-Miner-protection/ddos/threshold_retrained.txt"
WINDOW_SIZE         = 10      
SLOT_INTERVAL       = 1       
BLOCK_DURATION      = 30      
BLOCK_MSE_THRESHOLD = 15000   

autoenc   = tf.keras.models.load_model(MODEL_PATH, compile=False)
scaler    = joblib.load(SCALER_PATH)
threshold = float(open(THRESHOLD_PATH).read())

buf_syn    = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
buf_udp    = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
buf_icmp   = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
buf_bytes  = deque([0]*WINDOW_SIZE, maxlen=WINDOW_SIZE)
ip_counts  = deque([Counter() for _ in range(WINDOW_SIZE)], maxlen=WINDOW_SIZE)
blocked_ips = {}

def block_ip(ip):
    if ip in blocked_ips:
        return
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
    print(f"[ACTION] Blocked {ip}", flush=True)
    t = Timer(BLOCK_DURATION, unblock_ip, args=(ip,))
    t.daemon = True
    blocked_ips[ip] = t
    t.start()

def packet_handler(pkt):
    src = pkt[IP].src if IP in pkt else None
    if src and src in blocked_ips:
        return
    if TCP in pkt and pkt[TCP].flags & 0x02:
        buf_syn[-1] += 1
    elif UDP in pkt:
        buf_udp[-1] += 1
    elif ICMP in pkt:
        buf_icmp[-1] += 1
    buf_bytes[-1] += len(pkt)
    if src:
        ip_counts[-1][src] += 1

def reporter():
    while True:
        time.sleep(SLOT_INTERVAL)
        buf_syn.append(0)
        buf_udp.append(0)
        buf_icmp.append(0)
        buf_bytes.append(0)
        ip_counts.append(Counter())

        syn   = sum(buf_syn)
        udp   = sum(buf_udp)
        icmp  = sum(buf_icmp)
        total = syn + udp + icmp
        bts   = sum(buf_bytes)
        feat  = np.array([[WINDOW_SIZE, total, bts,
                           total/WINDOW_SIZE, bts/WINDOW_SIZE,
                           bts/(total+1e-6), total/WINDOW_SIZE,
                           bts/(WINDOW_SIZE+1e-6), 0, syn, bts]])

        x     = scaler.transform(feat)
        recon = autoenc.predict(x, verbose=0)
        mse   = float(np.mean((x - recon)**2))

        if mse > threshold:
            agg = sum(ip_counts, Counter())
            for attacker_ip, _ in agg.most_common():
                if attacker_ip in blocked_ips:
                    continue  
                print(f"[ALERT] Flood from {attacker_ip} MSE={mse:.3f}", flush=True)
                if mse >= BLOCK_MSE_THRESHOLD:
                    block_ip(attacker_ip)
                break  

if __name__ == "__main__":
    print("Live DDoS detector with selective block starting…", flush=True)
    Thread(target=reporter, daemon=True).start()
    sniff(iface="wlan0", prn=packet_handler, store=False)
