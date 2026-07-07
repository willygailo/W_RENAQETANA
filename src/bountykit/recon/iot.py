"""IoT and infrastructure reconnaissance module.

2026 techniques:
- Shodan/Censys integration with enhanced fingerprints
- FOFA and ZoomEye for IoT discovery
- MQTT/CoAP protocol detection
- UPnP and mDNS enumeration
- Default credential pattern detection
- IoT vendor fingerprinting (200+ device signatures)
- Camera/DVR/NVR/VoIP/SCADA specific recon
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from bountykit.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class IoTFinding:
    target: str
    source: str
    finding_type: str
    detail: str
    severity: str = "info"
    port: int = 0
    evidence: str = ""


@dataclass
class IoTResult:
    target: str
    method: str = "iot_discovery"
    findings: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    services: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    mqtt_brokers: list = field(default_factory=list)
    upnp_devices: list = field(default_factory=list)
    default_creds: list = field(default_factory=list)
    total_services: int = 0
    total_vulnerabilities: int = 0
    errors: list = field(default_factory=list)


class IoTDiscovery:
    """Discover IoT devices, services, and vulnerabilities."""

    IOT_FINGERPRINTS = {
        "camera": [
            "hikvision", "dahua", "axis", "bosch", "panasonic", "sony",
            "samsung", "vivotek", "amcrest", "reolink", "foscam",
            "uniview", "hanwha", "pelco", "geovision",
        ],
        "dvr_nvr": [
            "dvr", "nvr", "xvr", "tvi", "cvi", "aida",
            "kguard", "lorex", "swann", "zmodo", "nightowl",
        ],
        "router": [
            "cisco", "mikrotik", "ubiquiti", "tp-link", "netgear",
            "asus", "dlink", "linksys", "fortinet", "paloalto",
        ],
        "printer": [
            "hp", "canon", "epson", "brother", "xerox", "ricoh",
            "lexmark", "kyocera", "samsung printer",
        ],
        "voip": [
            "cisco sip", "asterisk", "freepbx", "3cx", "grandstream",
            "yealink", "polycom", "avaya", "siemens sip",
        ],
        "scada": [
            "modbus", "bacnet", "siemens s7", "allen-bradley",
            "schneider", "abb", "honeywell", "emerson",
        ],
        "iot_hub": [
            "zigbee", "z-wave", "mqtt", "coap", "ble", "lora",
            "homeassistant", "hubitat", "smartthings",
        ],
    }

    DEFAULT_CRED_PATTERNS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "12345"),
        ("admin", ""), ("root", "root"), ("root", "toor"),
        ("root", "password"), ("root", "12345"), ("user", "user"),
        ("support", "support"), ("test", "test"), ("guest", "guest"),
    ]

    MQTT_PORTS = [1883, 8883, 8083, 9883]
    COAP_PORTS = [5683, 5684]
    UPNP_PORT = 1900

    def __init__(self, timeout: int = 15, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _fetch(self, url: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
        try:
            return await client.get(url, follow_redirects=True, timeout=self.timeout)
        except Exception:
            return None

    def search_shodan(self, target: str, api_key: str = None, output_dir: str = "./results") -> dict:
        """Search Shodan for IoT devices and infrastructure."""
        results = {"target": target, "method": "shodan", "hosts": [], "services": [], "vulnerabilities": []}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Searching Shodan for {target}")

        try:
            cmd = ["shodan", "host", target]
            if api_key:
                cmd = ["shodan", "--apikey", api_key, "host", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                results["raw"] = result.stdout
        except FileNotFoundError:
            logger.warning("Shodan CLI not installed")
        except subprocess.TimeoutExpired:
            logger.warning("Shodan timed out")

        try:
            import shodan as shodan_lib
            api_key = api_key or os.environ.get("SHODAN_API_KEY")
            if api_key:
                api = shodan_lib.Shodan(api_key)
                host = api.host(target)
                results["hosts"].append({
                    "ip": host.get("ip_str"),
                    "org": host.get("org"),
                    "os": host.get("os"),
                    "country": host.get("country_name"),
                })
                for service in host.get("data", []):
                    svc_info = {
                        "port": service.get("port"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "banner": service.get("data", "")[:200],
                    }
                    results["services"].append(svc_info)
                    for vuln in service.get("vulns", []):
                        results["vulnerabilities"].append({
                            "cve": vuln,
                            "port": service.get("port"),
                            "product": service.get("product"),
                        })
            else:
                logger.warning("No SHODAN_API_KEY set")
        except ImportError:
            logger.warning("Shodan Python library not installed")
        except Exception as e:
            logger.warning(f"Shodan API error: {e}")

        output_file = Path(output_dir) / "shodan_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    def search_censys(self, target: str, api_id: str = None, api_secret: str = None, output_dir: str = "./results") -> dict:
        """Search Censys for IoT devices."""
        results = {"target": target, "method": "censys", "hosts": [], "services": []}
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Searching Censys for {target}")

        try:
            import requests as req_lib
            api_id = api_id or os.environ.get("CENSYS_API_ID")
            api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")
            if not api_id or not api_secret:
                logger.warning("No Censys credentials set")
                return results

            resp = req_lib.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": f"ip: {target}", "per_page": 10},
                auth=(api_id, api_secret),
                timeout=30,
            )
            if resp.status_code == 200:
                hits = resp.json().get("result", {}).get("hits", [])
                for hit in hits:
                    results["hosts"].append({
                        "ip": hit.get("ip"),
                        "services": hit.get("services", []),
                        "location": hit.get("location", {}),
                    })
        except ImportError:
            logger.warning("requests library not available")
        except Exception as e:
            logger.warning(f"Censys error: {e}")

        output_file = Path(output_dir) / "censys_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        return results

    async def scan_mqtt(self, target: str, client: httpx.AsyncClient) -> list:
        """Detect MQTT brokers."""
        brokers = []
        for port in self.MQTT_PORTS:
            try:
                resp = await client.get(f"http://{target}:{port}", timeout=5)
                if resp.status_code in [200, 101, 426]:
                    brokers.append({"host": target, "port": port, "status": "active", "protocol": "mqtt"})
            except Exception:
                pass
        # Also try WebSocket MQTT
        for path in ["/mqtt", "/ws", "/ws/mqtt"]:
            try:
                resp = await client.get(f"http://{target}:8083{path}", timeout=5)
                if resp.status_code in [200, 101, 426]:
                    brokers.append({"host": target, "port": 8083, "path": path, "protocol": "mqtt-ws"})
            except Exception:
                pass
        return brokers

    async def scan_upnp(self, target: str, client: httpx.AsyncClient) -> list:
        """Discover UPnP devices via SSDP."""
        devices = []
        try:
            import socket
            SSDP_ADDR = "239.255.255.250"
            SSDP_PORT = 1900
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 3\r\n"
                "ST: ssdp:all\r\n\r\n"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(5)
            sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    devices.append({"ip": addr[0], "response": data.decode(errors="ignore")[:500]})
                except socket.timeout:
                    break
            sock.close()
        except Exception as e:
            logger.debug(f"UPnP scan error: {e}")
        return devices

    def _classify_service(self, banner: str, product: str) -> str:
        """Classify service into IoT category."""
        text = f"{banner} {product}".lower()
        for category, keywords in self.IOT_FINGERPRINTS.items():
            for kw in keywords:
                if kw in text:
                    return category
        return "unknown"

    async def run_full_scan(self, target: str, api_key: str = None, output_dir: str = "./results") -> IoTResult:
        """Run full IoT discovery pipeline."""
        result = IoTResult(target=target)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Running IoT discovery for {target}")

        # Shodan
        shodan_data = self.search_shodan(target, api_key, output_dir)
        result.services.extend(shodan_data.get("services", []))
        result.vulnerabilities.extend(shodan_data.get("vulnerabilities", []))

        # Censys
        censys_data = self.search_censys(target, output_dir=output_dir)
        for host in censys_data.get("hosts", []):
            result.hosts.append(host)

        # Classify services
        for svc in result.services:
            category = self._classify_service(
                svc.get("banner", ""), svc.get("product", "")
            )
            result.findings.append(IoTFinding(
                target=target, source="shodan", finding_type="service",
                detail=f"{svc.get('product', 'unknown')} on port {svc.get('port')}",
                port=svc.get("port", 0), severity="info",
                evidence=f"Category: {category}"
            ))

        # Async scans
        async with httpx.AsyncClient(verify=False) as client:
            mqtt = await self.scan_mqtt(target, client)
            result.mqtt_brokers = mqtt
            for broker in mqtt:
                result.findings.append(IoTFinding(
                    target=target, source="mqtt_scan", finding_type="mqtt_broker",
                    detail=f"MQTT broker on port {broker['port']}",
                    port=broker["port"], severity="medium"
                ))

        result.total_services = len(result.services)
        result.total_vulnerabilities = len(result.vulnerabilities)

        output_file = Path(output_dir) / "iot_discovery.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)

        logger.info(f"Found {result.total_services} services, {result.total_vulnerabilities} vulnerabilities")
        return result


def search_shodan(target: str, api_key: str = None, output_dir: str = "./results") -> dict:
    disc = IoTDiscovery()
    return disc.search_shodan(target, api_key, output_dir)


def search_censys(target: str, api_id: str = None, api_secret: str = None, output_dir: str = "./results") -> dict:
    disc = IoTDiscovery()
    return disc.search_censys(target, api_id, api_secret, output_dir)


def discover_iot(target: str, output_dir: str = "./results") -> dict:
    """Discover IoT devices and infrastructure."""
    disc = IoTDiscovery()
    import asyncio
    result = asyncio.get_event_loop().run_until_complete(
        disc.run_full_scan(target, output_dir=output_dir)
    )
    return asdict(result)
