#!/usr/bin/env python
import os
import sys
import time
import libtorrent as lt
import re
import logging
from logging.handlers import SysLogHandler
from rich.console import Console
from rich.text import Text
import asyncio

class DHTSniffer:
    def __init__(self):
        self.ses = None
        self.console = Console()
        self.handle = None
        self.logger = self.setup_logger()

    def setup_logger(self):
        logger = logging.getLogger('DHTSniffer')
        logger.setLevel(logging.INFO)

        handler = SysLogHandler(address='/dev/log')  #Linux
        formatter = logging.Formatter('%(asctime)s DHTSniffer: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        file_handler = logging.FileHandler('DHT.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def start(self, port=6881, target=None, download=False):
        self.ses = lt.session({'alert_mask': lt.alert.category_t.dht_notification |
                                              lt.alert.category_t.dht_log_notification})

        self.ses.apply_settings({
            'listen_interfaces': f'0.0.0.0:{port}',
            'enable_dht': True,
            'enable_lsd': False,
            'enable_upnp': False,
            'enable_natpmp': False,
        })

        routers = [
            ("router.bittorrent.com", 6881),
            ("dht.transmissionbt.com", 6881),
            ("router.utorrent.com", 6881)
        ]

        for router in routers:
            try:
                self.ses.add_dht_router(router[0], router[1])
            except Exception as e:
                self.console.print(f"[bold red]Error adding DHT router {router[0]}: {e}[/bold red]")
                self.logger.error(f"Error adding DHT router {router[0]}: {e}")

        info_hash = self.get_info_hash(target)

        if download and info_hash:
            asyncio.run(self.download_file(info_hash))

        self.listen_to_dht()

    def get_info_hash(self, target):
        if not target:
            return None

        if target.endswith('.torrent') and os.path.isfile(target):
            return self.get_info_hash_from_torrent(target)
        else:
            return target

    def get_info_hash_from_torrent(self, torrent_file):
        try:
            info = lt.torrent_info(torrent_file)
            return str(info.info_hash())
        except Exception as e:
            self.console.print(f"[bold red]Failed to load torrent file: {e}[/bold red]")
            self.logger.error(f"Failed to load torrent file: {e}")
            sys.exit(1)

    async def download_file(self, info_hash):
        params = {
            'save_path': './downloads/',
            'storage_mode': lt.storage_mode_t.storage_mode_sparse,
        }

        magnet_link = f"magnet:?xt=urn:btih:{info_hash}"
        self.handle = lt.add_magnet_uri(self.ses, magnet_link, params)

        self.console.print("[bold green]Starting torrent download...[/bold green]")
        self.logger.info("Starting torrent download...")

        while not self.handle.has_metadata():
            await asyncio.sleep(1)

        self.console.print(f"[bold green]Downloading {self.handle.name()}...[/bold green]")
        self.logger.info(f"Downloading {self.handle.name()}...")

        while self.handle.status().state != lt.torrent_status.seeding:
            status = self.handle.status()
            progress_message = f"Progress: {status.progress * 100:.2f}% complete"
            self.console.print(f"[bold green]{progress_message}[/bold green]", end="\r")
            self.logger.info(progress_message)
            await asyncio.sleep(5)

        complete_message = f"Download complete: {self.handle.name()}"
        self.console.print(f"\n[bold green]{complete_message}[/bold green]")
        self.logger.info(complete_message)

    def listen_to_dht(self):
        try:
            while True:
                alerts = self.ses.pop_alerts()
                for alert in alerts:
                    self.handle_alert(alert)
                time.sleep(1)
        except KeyboardInterrupt:
            self.console.print("[bold red]\nStopping DHT Sniffer...[/bold red]")
            self.logger.info("Stopping DHT Sniffer...")

    def handle_alert(self, alert):
        alert_type = type(alert).__name__
        if alert_type == 'dht_pkt_alert':
            self.display_dht_packet(alert.message())
        else:
            log_message = f"[{alert_type}] {alert.message()}"
            self.console.print(log_message)
            self.logger.info(log_message)

    def display_dht_packet(self, message):
        text = Text(message)
        text.highlight_regex(r'\d+\.\d+\.\d+\.\d+', "bold cyan")
        text.highlight_regex(r':\d+', "bold magenta")
        text.highlight_regex(r"'id': '(\w+)'", "bold yellow")
        text.highlight_regex(r"'info_hash': '(\w+)'", "bold red")
        text.highlight_regex(r"'token': '(\w+)'", "bold green")

        formatted_message = text.plain
        self.console.print(text)
        self.logger.info(formatted_message)

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else None
    download = '--Download' in sys.argv
    dht_sniffer = DHTSniffer()
    dht_sniffer.initialize(target=target, download=download)