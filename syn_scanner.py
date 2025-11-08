#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import IP, ICMP, TCP, sr1, send
import sys
import logging

# Отключаем надоедливые сообщения об IPv6 от Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def icmp_probe(ip):
    """
    Отправляет ICMP (ping) пакет, чтобы проверить, доступен ли хост.
    """
    print(f"[*] Проверка доступности {ip} (ICMP)...")
    icmp_packet = IP(dst=ip) / ICMP()
    
    # sr1() - Отправляет пакет и ждет 1 ответ
    # timeout=1 - Ждать ответ 1 секунду
    resp_packet = sr1(icmp_packet, timeout=1, verbose=0)
    
    # Если ответ не пришел (None), хост недоступен
    return resp_packet is not None

def syn_scan(ip, port):
    """
    Выполняет SYN-сканирование одного порта.
    """
    # 1. Создаем SYN-пакет. Флаг 'S' - это SYN.
    syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
    
    # 2. Отправляем пакет и ждем ответа
    resp_packet = sr1(syn_packet, timeout=0.5, verbose=0)
    
    # 3. Анализируем ответ
    if resp_packet is None:
        # Нет ответа - порт фильтруется
        return "Filtered"
        
    elif resp_packet.haslayer(TCP):
        # Получаем флаги из TCP-слоя
        tcp_flags = resp_packet.getlayer(TCP).flags
        
        # 0x12 - это SYN+ACK (16 + 2)
        if tcp_flags == 0x12:
            # Порт открыт! Отправляем RST, чтобы закрыть соединение
            rst_packet = IP(dst=ip) / TCP(dport=port, flags='R')
            send(rst_packet, verbose=0)
            return "Open"
            
        # 0x14 - это RST+ACK (16 + 4)
        elif tcp_flags == 0x14:
            # Порт закрыт
            return "Closed"
            
    return "Unknown"

# --- Главная часть программы ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: sudo python3 syn_scanner.py <IP-адрес_цели>")
        sys.exit(1)

    ip = sys.argv[1]
    
    # Определяем диапазон портов для сканирования (стандартные "известные" порты)
    ports_to_scan = range(1, 1025)
    
    if icmp_probe(ip):
        print(f"[+] Хост {ip} доступен. Начинаю сканирование портов 1-1024...")
        
        for port in ports_to_scan:
            status = syn_scan(ip, port)
            
            # Печатаем только интересные результаты (не "Closed" или "Filtered")
            if status == "Open":
                print(f"Порт {port:<5} | \033[92mОТКРЫТ\033[0m") # \033[...m - для цветного вывода
            elif status == "Filtered":
                 # Раскомментируй, если хочешь видеть и фильтруемые порты
                 # print(f"Порт {port:<5} | \033[93mФильтруется\033[0m")
                 pass
                 
        print("[*] Сканирование завершено.")
        
    else:
        print(f"[-] Хост {ip} не отвечает на ICMP (ping).")
