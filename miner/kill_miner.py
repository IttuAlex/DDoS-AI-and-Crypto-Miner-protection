#!/usr/bin/env python3
"""
miner_detector.py

Script Python pentru Raspberry Pi care monitorizeaza procesele in cautare de mineri de criptomonede,
procesele cu consum de CPU excesiv si conexiunile de retea spre porturi suspecte, le semnalizeaza si le opreste automat daca sunt detectate.

Necesita psutil: pip3 install psutil
Ruleaza cu sudo pentru a putea elimina procese
"""
import psutil
import time
import logging
import os
import signal
from collections import defaultdict

MINER_KEYWORDS = [
    'xmrig', 'minerd', 'ccminer', 'cgminer', 'ethminer', 'bfgminer'
]
CPU_THRESHOLD = 50.0    
DURATION_THRESHOLD = 30  
INTERVAL = 10            
COUNT_THRESHOLD = DURATION_THRESHOLD // INTERVAL
SUSPICIOUS_PORTS = {3333, 4444, 5555}

LOG_FILE = '/var/log/miner_detector.log'


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )


def is_miner(proc):

    try:
        name = proc.name().lower()
        cmdline = ' '.join(proc.cmdline()).lower()
        for keyword in MINER_KEYWORDS:
            if keyword in name or keyword in cmdline:
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return False


def kill_process(proc, reason):
    
    try:
        pid = proc.pid
        os.kill(pid, signal.SIGTERM)
        logging.info(f'Oprit proces: PID={pid}, name={proc.name()}, motiv: {reason}')
    except Exception as e:
        logging.error(f'Eroare la oprirea procesului {pid}: {e}')


def check_network_connections():
   
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
            pid = conn.pid
            if pid:
                try:
                    proc = psutil.Process(pid)
                    kill_process(proc, f'conexiune suspecta pe port {conn.raddr.port}')
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue


def main():
    
    if os.geteuid() != 0:
        print("Ruleaza scriptul ca root/sudo pentru a putea opri procese.")
        return

    setup_logging()
    logging.info('Pornire miner_detector cu detectie avansata')

    high_usage = defaultdict(int)
   
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    
    while True:
       
        for proc in psutil.process_iter(['pid', 'name']):
            try:
               
                if is_miner(proc):
                    kill_process(proc, 'miner detectat (keyword)')
                    continue
               
                usage = proc.cpu_percent(None)
                if usage > CPU_THRESHOLD:
                    high_usage[proc.pid] += 1
                else:
                    high_usage.pop(proc.pid, None)

                if high_usage.get(proc.pid, 0) >= COUNT_THRESHOLD:
                    kill_process(proc, f'consum CPU > {CPU_THRESHOLD}% pentru {DURATION_THRESHOLD}s')
                    high_usage.pop(proc.pid, None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

      
        check_network_connections()

        
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
