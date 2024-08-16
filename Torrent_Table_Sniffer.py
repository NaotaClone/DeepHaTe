import os
import re
import sys
import signal
import csv
import time
import libtorrent as lt # type: ignore
from rich.console import Console
from rich.table import Table
from rich.live import Live
from collections import defaultdict
import socket
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class DHTLiveTable:
    def __init__(self):
        self.session = None
        self.node_data = defaultdict(lambda: {
            "ip": None, "port": None, "node_id": None, 
            "hostname": "Resolving...", "country": "Resolving...", 
            "query_count": 0, "response_count": 0, "open_ports": "Scanning..."
        })
        self.console = Console()
        self.hostname_cache = {}
        self.country_cache = {}
        self.port_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.running = True
        self.handle = None
        self.ports_to_check = [
            20, 21, 22, 23, 25, 53, 69, 80, 110, 143, 161, 162, 
            389, 443, 445, 465, 514, 993, 995, 1025, 1080, 1194, 
            1433, 1521, 2049, 2121, 3306, 3389, 3690, 4444, 5060, 
            5061, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9200, 
            9306, 11211, 27017
        ]

    def initialize(self, port=6881, target=None, download=False):
        self.setup_logging_directory()
        self.setup_session(port)
        self.add_known_dht_routers()

        info_hash = self.get_info_hash(target)

        if info_hash:
            self.add_info_hash(info_hash)

        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)

        asyncio.run(self.run_tasks(info_hash, download))

    def setup_logging_directory(self):
        if not os.path.exists('logs'):
            os.makedirs('logs')

    def setup_session(self, port):
        self.session = lt.session({'alert_mask': lt.alert.category_t.dht_notification |
                                                lt.alert.category_t.dht_log_notification})

        self.session.apply_settings({
            'listen_interfaces': f'0.0.0.0:{port}',
            'enable_dht': True,
            'enable_lsd': False,
            'enable_upnp': False,
            'enable_natpmp': False,
        })

    def add_known_dht_routers(self):
        routers = [
            ("router.bittorrent.com", 6881),
            ("dht.transmissionbt.com", 6881),
            ("router.utorrent.com", 6881)
        ]

        for router in routers:
            try:
                self.session.add_dht_bootstrap_node(f"{router[0]}:{router[1]}")
            except Exception:
                pass

    def get_info_hash(self, target):
        if target.endswith('.torrent') and os.path.isfile(target):
            return self.get_info_hash_from_torrent(target)
        else:
            return target

    def get_info_hash_from_torrent(self, torrent_file):
        try:
            info = lt.torrent_info(torrent_file)
            return str(info.info_hash())
        except Exception as e:
            print(f"Failed to load torrent file: {e}", file=sys.stderr)
            sys.exit(1)

    def add_info_hash(self, info_hash):
        sha1_hash = lt.sha1_hash(bytes.fromhex(info_hash))
        self.session.dht_get_peers(sha1_hash)

    async def run_tasks(self, info_hash, download):
        tasks = [self.monitor_dht_packets()]
        if download:
            tasks.append(self.download_file(info_hash))
        await asyncio.gather(*tasks)

    async def monitor_dht_packets(self):
        with Live(self.render_table(), refresh_per_second=2, console=self.console) as live:
            try:
                while self.running:
                    alerts = self.session.pop_alerts()
                    for alert in alerts:
                        await self.process_alert(alert)
                    live.update(self.render_table())
                    await asyncio.sleep(0.5)
            except Exception as e:
                print(f"An error occurred: {e}")
            finally:
                self.save_to_csv()
                print("DHT sniffer stopped. Data saved to dht_data.csv.")

    async def download_file(self, info_hash):
        params = {
            'save_path': './downloads/',
            'storage_mode': lt.storage_mode_t.storage_mode_sparse,
        }

        magnet_link = f"magnet:?xt=urn:btih:{info_hash}"
        self.handle = lt.add_magnet_uri(self.session, magnet_link, params)

        print("Starting torrent download...")

        while not self.handle.has_metadata():
            await asyncio.sleep(1)

        print(f"Downloading {self.handle.name()}...")

        while self.handle.status().state != lt.torrent_status.seeding:
            status = self.handle.status()
            self.console.print(f"[bold green]Progress:[/bold green] {status.progress * 100:.2f}% complete", end="\r")
            await asyncio.sleep(5)

        print(f"\nDownload complete: {self.handle.name()}")

    async def process_alert(self, alert):
        alert_type = type(alert).__name__

        if alert_type == 'dht_pkt_alert':
            message = alert.message()

            if "'y': 'q'" in message:
                await self.process_query(message)
            elif "'y': 'r'" in message:
                await self.process_response(message)

    async def process_query(self, message):
        ip_port = self.extract_ip_port(message)
        if not ip_port:
            return

        ip_address, port = ip_port
        node_key = f"{ip_address}:{port}"
        self.node_data[node_key]["ip"] = ip_address
        self.node_data[node_key]["port"] = port
        self.node_data[node_key]["query_count"] += 1

        asyncio.create_task(self.resolve_hostname(ip_address, node_key))
        asyncio.create_task(self.resolve_country(ip_address, node_key))
        asyncio.create_task(self.check_open_ports(ip_address, node_key))

    async def process_response(self, message):
        ip_port = self.extract_ip_port(message)
        if not ip_port:
            return

        ip_address, port = ip_port
        node_id_match = re.search(r"'id':\s'(\w+)'", message)
        node_id = node_id_match.group(1) if node_id_match else 'N/A'

        node_key = f"{ip_address}:{port}"
        self.node_data[node_key]["ip"] = ip_address
        self.node_data[node_key]["port"] = port
        self.node_data[node_key]["node_id"] = node_id
        self.node_data[node_key]["response_count"] += 1

        asyncio.create_task(self.resolve_hostname(ip_address, node_key))
        asyncio.create_task(self.resolve_country(ip_address, node_key))
        asyncio.create_task(self.check_open_ports(ip_address, node_key))

    def extract_ip_port(self, message):
        ip_port_match = re.search(r'\[\d+\.\d+\.\d+\.\d+:\d+\]', message)
        if not ip_port_match:
            return None

        ip_port = ip_port_match.group().strip('[]').split(':')
        return ip_port[0], ip_port[1]

    async def resolve_hostname(self, ip_address, node_key):
        if ip_address in self.hostname_cache:
            self.node_data[node_key]["hostname"] = self.hostname_cache[ip_address]
            return

        loop = asyncio.get_running_loop()
        hostname = await loop.run_in_executor(self.executor, self.get_hostname, ip_address)
        self.hostname_cache[ip_address] = hostname
        self.node_data[node_key]["hostname"] = hostname

    def get_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            hostname = "N/A"
        return hostname

    async def resolve_country(self, ip_address, node_key, retries=3):
        if ip_address in self.country_cache:
            self.node_data[node_key]["country"] = self.country_cache[ip_address]
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://ipinfo.io/{ip_address}/json', timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        country = data.get("country", "N/A")
                        self.country_cache[ip_address] = country
                        self.node_data[node_key]["country"] = country
                    else:
                        self.node_data[node_key]["country"] = "N/A"
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if retries > 0:
                await self.resolve_country(ip_address, node_key, retries - 1)
            else:
                self.node_data[node_key]["country"] = "N/A"

    async def check_open_ports(self, ip_address, node_key):
        if ip_address in self.port_cache:
            self.node_data[node_key]["open_ports"] = self.port_cache[ip_address]
            return

        loop = asyncio.get_running_loop()
        open_ports = await loop.run_in_executor(self.executor, self.scan_ports, ip_address)
        self.port_cache[ip_address] = open_ports
        self.node_data[node_key]["open_ports"] = open_ports

    def scan_ports(self, ip_address):
        open_ports = []
        for port in self.ports_to_check:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(str(port))
        return ', '.join(open_ports) if open_ports else "None"

    def render_table(self):
        table = Table(title="DHT Packet Information")
        table.add_column("IP Address", justify="left")
        table.add_column("Port", justify="center")
        table.add_column("Node ID", justify="center")
        table.add_column("Hostname", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Query", justify="center")
        table.add_column("Response", justify="center")
        table.add_column("Open Ports", justify="center")

        for node in self.node_data.values():
            if node["response_count"] > 0:
                table.add_row(
                    node["ip"],
                    node["port"],
                    node.get("node_id", "N/A"),
                    node.get("hostname", "Resolving..."),
                    node.get("country", "Resolving..."),
                    str(node["query_count"]),
                    str(node["response_count"]),
                    node.get("open_ports", "Scanning...")
                )

        return table

    def handle_exit(self, signum, frame):
        print("Exiting gracefully...")
        self.running = False

    def save_to_csv(self):
        filename = "dht_data.csv"
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP Address", "Port", "Node ID", "Hostname", "Country", "Query", "Response", "Open Ports"])
            for node in self.node_data.values():
                writer.writerow([
                    node["ip"],
                    node["port"],
                    node.get("node_id", "N/A"),
                    node.get("hostname", "Resolving..."),
                    node.get("country", "Resolving..."),
                    str(node["query_count"]),
                    str(node["response_count"]),
                    node.get("open_ports", "Scanning...")
                ])

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else None
    download = '--Download' in sys.argv
    dht_sniffer = DHTLiveTable()
    dht_sniffer.initialize(target=target, download=download)