#!/usr/bin/env python3

# Импортируем все необходимые функции из scapy
from scapy.all import sniff, ARP, Ether

# Словарь для хранения "правильных" пар MAC-адрес: IP-адрес
IP_MAC_Map = {}

def processPacket(packet):
    # Убедимся, что в пакете есть Ethernet и ARP слои
    if packet.haslayer(Ether) and packet.haslayer(ARP):
        
        # Извлекаем MAC и IP из пакета
        src_MAC = packet[Ether].src
        src_IP = packet[ARP].psrc

        # 1. Проверяем, видели ли мы этот MAC-адрес раньше
        if src_MAC in IP_MAC_Map:
            
            # 2. Если да, проверяем, не изменился ли связанный с ним IP-адрес
            if IP_MAC_Map[src_MAC] != src_IP:
                
                # Если IP изменился — это признак атаки!
                old_IP = IP_MAC_Map[src_MAC]
                message = (
                    f"\n[!] ОБНАРУЖЕНА ВОЗМОЖНАЯ ARP-АТАКА!\n"
                    f"    MAC-адрес: {src_MAC}\n"
                    f"    Ранее был связан с IP: {old_IP}\n"
                    f"    Теперь объявляет себя как: {src_IP}\n"
                )
                print(message)
            
            # Если MAC и IP совпали, все в порядке, ничего не делаем

        else:
            # 3. Если мы видим этот MAC-адрес впервые,
            #    просто добавляем его в нашу "доверенную" базу
            print(f"[*] Добавлена новая пара в карту: {src_MAC} -> {src_IP}")
            IP_MAC_Map[src_MAC] = src_IP

# --- Главная часть программы ---
# (Обрати внимание, этот код БЕЗ отступов)

print("[*] Запуск детектора ARP-спуфинга...")
print("[*] Нажмите Ctrl+C для остановки...")

# Запускаем сниффер
sniff(count=0, filter="arp", store=0, prn=processPacket)
