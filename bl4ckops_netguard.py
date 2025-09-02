import logging
import logging.handlers
import multiprocessing
import threading
import time
import yaml
from datetime import datetime
from collections import deque, defaultdict
import subprocess
from scapy.all import sniff, IP, TCP, UDP
import numpy as np
from river import anomaly, preprocessing
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Dict, Deque, List


class ConfigLoader:
    @staticmethod
    def load_config(path: str) -> Dict:
        try:
            with open(path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            raise RuntimeError(f"Failed loading config: {e}")


def setup_logging(log_file: str):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class FirewallManager:
    def __init__(self, forward_chain: str):
        self.forward_chain = forward_chain

    def _get_rules(self) -> str:
        result = subprocess.run(['iptables-save'], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error("Failed to get iptables rules")
            return ''
        return result.stdout

    def rule_exists(self, rule: List[str]) -> bool:
        rules = self._get_rules()
        return ' '.join(rule) in rules

    def add_rule(self, rule: List[str]):
        if self.rule_exists(rule):
            logging.info(f"Rule {rule} already exists, skipping")
            return
        snapshot = self._get_rules()
        try:
            subprocess.run(['iptables'] + rule, check=True)
            logging.info(f"Added iptables rule: {rule}")
        except subprocess.CalledProcessError:
            logging.warning(f"Failed adding iptables rule: {rule}, attempting rollback")
            subprocess.run(['iptables-restore'], input=snapshot, text=True)

    def delete_rule(self, rule: List[str]):
        if not self.rule_exists(rule):
            logging.info(f"Rule {rule} not found, skipping deletion")
            return
        try:
            subprocess.run(['iptables'] + rule, check=True)
            logging.info(f"Deleted iptables rule: {rule}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error deleting iptables rule: {e}")


class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, isolate_host_func):
        self.isolate_host = isolate_host_func

    def on_modified(self, event):
        if not event.is_directory:
            ext = event.src_path.rsplit('.', 1)[-1].lower()
            if ext in ['encrypted', 'lock', 'crypted']:
                logging.warning(f"[RANSOMWARE ALERT] Possible ransomware file: {event.src_path}")
                self.isolate_host(event.src_path)


class SecurityMonitor:
    def __init__(self, config: Dict):
        self.config = config
        self.ip_packet_times: Dict[str, Deque[float]] = defaultdict(deque)
        self.blocked_ips: Dict[str, datetime] = {}
        self.lock = threading.Lock()

        self.ml_model = anomaly.HalfSpaceTrees(seed=42, n_trees=25, depth=10)
        self.scaler = preprocessing.StandardScaler()
        self.training_samples = 0

        self.firewall = FirewallManager(config['forward_chain'])

    def update_rate_limits(self, src_ip: str) -> int:
        now = time.time()
        times = self.ip_packet_times[src_ip]
        while times and times[0] < now - self.config['rate_limit_window']:
            times.popleft()
        times.append(now)
        return len(times)

    def block_ip(self, ip: str):
        with self.lock:
            if ip in self.blocked_ips:
                logging.info(f"IP {ip} already blocked.")
                return
            rule = ["-I", self.config['forward_chain'], "-s", ip, "-j", "DROP"]
            self.firewall.add_rule(rule)
            self.blocked_ips[ip] = datetime.now()
            logging.warning(f"Blocked IP {ip} for {self.config['block_time_sec']}s")

    def unblock_expired_ips(self):
        while True:
            with self.lock:
                now = datetime.now()
                expired_ips = [ip for ip, ts in self.blocked_ips.items() if (now - ts).total_seconds() > self.config['block_time_sec']]
                for ip in expired_ips:
                    rule = ["-D", self.config['forward_chain'], "-s", ip, "-j", "DROP"]
                    self.firewall.delete_rule(rule)
                    del self.blocked_ips[ip]
                    self.ip_packet_times[ip].clear()
                    logging.info(f"Unblocked IP {ip} after timeout.")
            time.sleep(30)

    def redirect_to_scrubbing(self, ip: str):
        rules = [
            ["-I", self.config['forward_chain'], "-s", ip, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", self.config['scrubbing_center_ip']],
            ["-I", self.config['forward_chain'], "-s", ip, "-j", "DROP"]
        ]
        for rule in rules:
            self.firewall.add_rule(rule)
        logging.info(f"Redirected IP {ip} traffic to scrubbing center")

    def isolate_host(self, identifier: str):
        logging.warning(f"Isolating host or resource {identifier}")
        try:
            rule_src = ["-I", self.config['forward_chain'], "-s", identifier, "-j", "DROP"]
            rule_dst = ["-I", self.config['forward_chain'], "-d", identifier, "-j", "DROP"]
            self.firewall.add_rule(rule_src)
            self.firewall.add_rule(rule_dst)
            logging.info(f"Isolated {identifier}")
        except Exception as e:
            logging.error(f"Isolation failure: {e}")

    def recovery_forensic(self, identifier: str):
        logging.info(f"Initiating recovery for {identifier}")
        try:
            subprocess.run(["rsync", "-a", self.config['backup_source'], self.config['backup_target']], check=True)
            logging.info(f"Recovery successful for {identifier}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Recovery failed for {identifier}: {e.stderr}")

    def analyze_ddos_pattern(self, pkt) -> str:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x02:
                return "SYN Flood"
            elif flags & 0x10:
                return "ACK Flood"
            elif flags & 0x04:
                return "RST Flood"
            else:
                return "TCP Flood"
        elif pkt.haslayer(UDP):
            return "UDP Flood"
        return "Unknown"

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip_layer = pkt[IP]
        src_ip = ip_layer.src

        pkt_count = self.update_rate_limits(src_ip)

        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            ddos_type = self.analyze_ddos_pattern(pkt)
            logging.info(f"Traffic from {src_ip} detected as {ddos_type}")

            length = len(pkt)
            tcp_flags = pkt[TCP].flags if pkt.haslayer(TCP) else 0

            features = {'length': length, 'packet_count': pkt_count, 'tcp_flags': tcp_flags}

            scaled = self.scaler.learn_one(features).transform_one(features)
            anomaly_score = self.ml_model.predict_one(scaled)

            if self.training_samples < self.config['ml_training_samples']:
                self.training_samples += 1
                return

            if anomaly_score == 1:  # Normal traffic
                return

            logging.warning(f"Anomaly detected from {src_ip} ({ddos_type}) with packet count {pkt_count}")
            self.block_ip(src_ip)
            self.redirect_to_scrubbing(src_ip)
            self.isolate_host(src_ip)
            self.recovery_forensic(src_ip)

    def start_filesystem_monitor(self):
        event_handler = RansomwareHandler(self.isolate_host)
        observer = Observer()
        for path in self.config['monitored_dirs']:
            observer.schedule(event_handler, path, recursive=True)
        observer.start()
        logging.info("Started filesystem monitoring for ransomware")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    def backup_worker(self):
        while True:
            logging.info("Running scheduled backup")
            try:
                subprocess.run(["rsync", "-a", self.config['backup_source'], self.config['backup_target']], check=True)
                logging.info("Backup completed successfully")
            except subprocess.CalledProcessError as e:
                logging.error(f"Backup failed: {e.stderr}")
            time.sleep(self.config.get('backup_interval', 3600))

    def unblock_worker(self):
        self.unblock_expired_ips()

    def packet_worker(self, pkt_queue, stop_event):
        while not stop_event.is_set():
            try:
                pkt = pkt_queue.get(timeout=1)
                self.process_packet(pkt)
            except Exception:
                continue

    def start_sniffer(self, pkt_queue, stop_event):
        def enqueue(pkt):
            if pkt.haslayer(IP):
                pkt_queue.put(pkt)

        sniff(iface=self.config['interface'], prn=enqueue, store=0, stop_filter=lambda x: stop_event.is_set())

    def start_all(self):
        pkt_queue = multiprocessing.Queue()
        stop_event = multiprocessing.Event()

        workers = [multiprocessing.Process(target=self.packet_worker, args=(pkt_queue, stop_event)) for _ in range(self.config.get('worker_process_count', 4))]
        for w in workers:
            w.start()

        multiprocessing.Process(target=self.start_sniffer, args=(pkt_queue, stop_event), daemon=True).start()
        threading.Thread(target=self.backup_worker, daemon=True).start()
        threading.Thread(target=self.unblock_worker, daemon=True).start()
        threading.Thread(target=self.start_filesystem_monitor, daemon=True).start()

        logging.info("Security monitor started, all components active.")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()
            for w in workers:
                w.join()


if __name__ == "__main__":
    config_path = "config.yaml"
    config = ConfigLoader.load_config(config_path)
    setup_logging(config['log_file'])
    monitor = SecurityMonitor(config)
    monitor.start_all()
