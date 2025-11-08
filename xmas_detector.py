#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import IP, TCP, sniff
import sys
import logging

# Отключаем лишние сообщения Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Определяем "фирменные" флаги XMas-сканирования
# FIN = 0x01
# PSH = 0x08
# URG = 0x20
# Итого: 0x01 + 0x08 + 0x20 = 0x29 (в шестнадцатеричном) или 41 (в десятичном)
XMAS_FLAGS = 0x29

def packet_handler(packet):
    """
    Эта функция будет вызываться для каждого перехваченного пакета.
    """
    # Проверяем, что это IP-пакет и внутри него есть TCP
    if packet.haslayer(IP) and packet.haslayer(TCP):
        
        # Извлекаем IP и TCP слои
        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        
        # --- Вот ядро нашего детектора ---
        # Сравниваем флаги в пакете с нашей "сигнатурой" XMas-атаки
        if tcp_layer.flags == XMAS_FLAGS:
            
            # Если совпало - бьем тревогу!
            print(
                f"\n[!] ОБНАРУЖЕНО XMAS-СКАНИРОВАНИЕ!\n"
                f"    От: {ip_layer.src}\n"
                f"    На порт: {tcp_layer.dport}\n"
            )

# --- Главная часть программы ---
if __name__ == "__main__":
    print("[*] Запуск детектора XMas-сканирования...")
    print("[*] Нажмите Ctrl+C для остановки.")
    
    try:
        # Запускаем сниффер
        # filter="tcp" - Scapy будет перехватывать только TCP-пакеты
        # prn=packet_handler - для каждого пакета вызывать нашу функцию
        # store=0 - не хранить пакеты в памяти, чтобы экономить ресурсы
        sniff(filter="tcp", prn=packet_handler, store=0)
        
    except KeyboardInterrupt:
        print("\n[*] Остановка детектора.")
