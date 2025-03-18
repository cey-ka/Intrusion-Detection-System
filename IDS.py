import pandas as pd
import numpy as np
import streamlit as st
import scapy.all as scapy
import glob
import os
import time
import sqlite3  # Veritabanı için ekledik


DATASET_PATH = "/home/kali/Desktop/cicids"  #Veri Seti 
data_files = glob.glob(os.path.join(DATASET_PATH, "*.csv"))
if not data_files:
    st.error(f"No CSV files found in path: {DATASET_PATH}")
    st.stop()

data_list = [pd.read_csv(file) for file in data_files]
data = pd.concat(data_list, ignore_index=True)
data.columns = data.columns.str.strip()


features = ["Destination Port", "Total Fwd Packets"]
data = data[features + ["Label"]]
data = data.dropna()


Q1 = data.groupby("Destination Port")["Total Fwd Packets"].quantile(0.25)
Q3 = data.groupby("Destination Port")["Total Fwd Packets"].quantile(0.75)
IQR = Q3 - Q1
port_thresholds = Q3 + 2 * IQR


attack_records = {}


traffic_running = False


last_attack_time = time.time()
last_alert_time = time.time()


conn = sqlite3.connect("saldirilar.db", check_same_thread=False)
cursor = conn.cursor()


cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    dst_port TEXT,
    packet_count INTEGER,
    timestamp TEXT
)
""")
conn.commit()

def get_port_name(port):
    port_services = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP",
        53: "DNS", 25: "SMTP", 110: "POP3", 143: "IMAP",
        3306: "MySQL", 8080: "HTTP Proxy", 50088: "Custom Port"
    }
    return port_services.get(port, f"Port {port} (Bilinmeyen)")


def detect_attack(packet):
    global last_attack_time, last_alert_time

    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_port = packet[scapy.TCP].dport
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))

        key = (src_ip, dst_port)
        attack_records[key] = attack_records.get(key, 0) + 1
        packet_count = attack_records[key]

        threshold = port_thresholds.get(dst_port, 100)  # *Varsayılan eşik 100*

        if packet_count > threshold and (time.time() - last_alert_time > 5):
            last_attack_time = time.time()
            port_name = get_port_name(dst_port)


            cursor.execute("INSERT INTO attacks (src_ip, dst_port, packet_count, timestamp) VALUES (?, ?, ?, ?)",
                           (src_ip, port_name, packet_count, timestamp))
            conn.commit()  # *Veritabanına kaydet*


            st.warning(f"⚠ Saldırı Tespit Edildi! Kaynak IP: {src_ip}, "
                       f"Hedef Port: {port_name}, Paket Sayısı: {packet_count}, Zaman: {timestamp}")


            df_attack = pd.DataFrame([{
                "Kaynak IP": src_ip,
                "Hedef Port": port_name,
                "Paket Sayısı": packet_count,
                "Zaman": timestamp
            }])

            st.experimental_data_editor(df_attack, height=150)

            last_alert_time = time.time()


st.title("Gerçek Zamanlı Ağ Trafiği Saldırı Tespiti")

col1, col2 = st.columns(2)


with col1:
    if st.button("🟢 Trafiği İzlemeye Başla"):
        traffic_running = True
        st.success("✅ Trafik izleme başladı!")

        def traffic_monitor():
            global last_attack_time, traffic_running
            while traffic_running:
                scapy.sniff(prn=detect_attack, store=False, count=1)
                current_time = time.time()

                if current_time - last_attack_time > 10:
                    st.success("✅ 10 saniyedir saldırı tespit edilmedi. Ağ trafiği normal görünüyor.")
                    last_attack_time = current_time

        traffic_monitor()


with col2:
    if st.button("🔴 Trafiği Durdur"):
        traffic_running = False
        st.error("❌ Trafik izleme durduruldu!")

        # *Veritabanına kaydedilen saldırıları göster*
        st.subheader("📂 Kaydedilen Saldırılar")
        attack_data = pd.read_sql_query("SELECT * FROM attacks", conn)
        if not attack_data.empty:
            st.dataframe(attack_data)
            st.success("📁 Saldırılar veritabanına kaydedildi!")
        else:
            st.warning("🚨 Şu ana kadar kaydedilmiş saldırı yok!")


conn.close()