import argparse
import base64
import json
import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network

from faker import Faker
from kafka import KafkaProducer

fake = Faker()

DEMO_MALICIOUS_IPS = [
    "45.155.205.233",
    "185.220.101.42",
    "194.26.192.64",
    "89.248.165.74",
    "193.32.162.149",
]

EXFIL_DOMAINS = [
    "backup-sync-cloud.example",
    "cdn-upload-gateway.example",
    "fileshare-update.example",
]

MALICIOUS_DOMAINS = [
    "update-checker-cloud.example",
    "cdn-telemetry-sync.example",
    "secure-file-gateway.example",
]


class CorelightLogGenerator:
    """Generate Corelight/Zeek-style conn, dns, and http logs for one segment."""

    def __init__(
        self,
        segment_name,
        cidr,
        kafka_topic,
        producer,
        malicious_ips=None,
        malicious_ip_rate=0.0,
    ):
        """Create a generator for one network segment and Kafka destination."""
        self.segment_name = segment_name
        self.network = ip_network(cidr)
        self.kafka_topic = kafka_topic
        self.producer = producer
        self.malicious_ips = malicious_ips or []
        self.malicious_ip_rate = malicious_ip_rate

    def generate_conn_log(self, flow=None):
        """Build one Corelight conn log record for the provided or generated flow."""
        flow = flow or self._flow_context()
        proto = flow["proto"]
        service = flow["service"]
        duration = round(random.uniform(0.005, 45.0), 6)
        orig_bytes = random.randint(40, 25000)
        resp_bytes = random.randint(0, 150000)
        conn_state = random.choices(
            ["SF", "S0", "S1", "REJ", "RSTO", "RSTR"],
            weights=[88, 3, 2, 4, 2, 1],
        )[0]

        return {
            "@path": "conn",
            "sensor_name": self.segment_name,
            "ts": self._timestamp(),
            "uid": flow["uid"],
            "id.orig_h": flow["orig_h"],
            "id.orig_p": flow["orig_p"],
            "id.resp_h": flow["resp_h"],
            "id.resp_p": flow["resp_p"],
            "proto": proto,
            "service": service,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "local_orig": self._is_local_ip(flow["orig_h"]),
            "local_resp": False,
            "missed_bytes": 0,
            "history": random.choice(["ShADadFf", "S", "Dd", "ShADad"]),
            "orig_pkts": random.randint(1, 120),
            "orig_ip_bytes": orig_bytes + random.randint(40, 2000),
            "resp_pkts": random.randint(0, 300),
            "resp_ip_bytes": resp_bytes + random.randint(0, 4000),
            "tunnel_parents": [self._uid()] if random.random() < 0.05 else [],
            "orig_l2_addr": fake.mac_address(),
            "resp_l2_addr": fake.mac_address(),
            "orig_cc": fake.country_code(),
            "resp_cc": fake.country_code(),
            "community_id": self._community_id(),
        }

    def generate_dns_log(self):
        """Build one Corelight dns log record with a possible malicious answer IP."""
        query = fake.domain_name()

        return {
            "@path": "dns",
            "sensor_name": self.segment_name,
            "ts": self._timestamp(),
            "uid": self._uid(),
            "id.orig_h": self._random_host(),
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": self._external_ip(),
            "id.resp_p": 53,
            "proto": random.choice(["udp", "tcp"]),
            "trans_id": random.randint(1, 65535),
            "rtt": round(random.uniform(0.001, 0.250), 6),
            "query": query,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": random.choice([1, 28, 5]),
            "qtype_name": random.choice(["A", "AAAA", "CNAME"]),
            "rcode": 0,
            "rcode_name": "NOERROR",
            "AA": False,
            "TC": False,
            "RD": True,
            "RA": True,
            "Z": 0,
            "answers": [self._external_ip()],
            "TTLs": [random.randint(60, 3600)],
            "rejected": False,
        }

    def generate_http_log(self, flow=None):
        """Build one Corelight http log record for the provided or generated flow."""
        flow = flow or self._flow_context(service="http")
        host = fake.domain_name()
        method = random.choice(["GET", "POST", "PUT"])
        uri = fake.uri_path(deep=random.randint(0, 3)) or "/"
        status_code = random.choices(
            [200, 201, 204, 301, 302, 400, 401, 403, 404, 500],
            weights=[76, 4, 4, 6, 4, 1, 1, 1, 2, 1],
        )[0]
        response_body_len = random.randint(0, 250000)
        resp_fuid = self._file_uid()

        return {
            "@path": "http",
            "sensor_name": self.segment_name,
            "ts": self._timestamp(),
            "uid": flow["uid"],
            "id.orig_h": flow["orig_h"],
            "id.orig_p": flow["orig_p"],
            "id.resp_h": flow["resp_h"],
            "id.resp_p": flow["resp_p"],
            "trans_depth": random.randint(1, 3),
            "method": method,
            "host": host,
            "uri": uri,
            "referrer": fake.uri() if random.random() < 0.35 else "-",
            "version": "1.1",
            "user_agent": fake.user_agent(),
            "request_body_len": random.randint(0, 4096) if method in {"POST", "PUT"} else 0,
            "response_body_len": response_body_len,
            "status_code": status_code,
            "status_msg": self._status_message(status_code),
            "tags": [],
            "proxied": [],
            "orig_fuids": [],
            "orig_filenames": [],
            "orig_mime_types": [],
            "resp_fuids": [resp_fuid] if response_body_len > 0 else [],
            "resp_filenames": [],
            "resp_mime_types": [fake.mime_type()] if response_body_len > 0 else [],
        }

    def send_log(self, log_record):
        """Send a generated Corelight log record to the configured Kafka topic."""
        self.producer.send(self.kafka_topic, value=log_record)

    def send_sample_batch(self):
        """Send a small batch with linked conn/http records plus one dns record."""
        http_flow = self._flow_context(service="http")
        for generator in (
            lambda: self.generate_conn_log(http_flow),
            self.generate_dns_log,
            lambda: self.generate_http_log(http_flow),
        ):
            self.send_log(generator())

    def send_reach_malicious_ip_demo(self, source_ip=None, destination_ip=None):
        """Send fake logs for one internal host reaching a malicious IP."""
        orig_h = source_ip or self._random_host()
        resp_h = destination_ip or random.choice(self.malicious_ips or DEMO_MALICIOUS_IPS)
        domain = random.choice(MALICIOUS_DOMAINS)
        uid = self._uid()
        orig_p = random.randint(49152, 65535)

        dns_log = self._dns_resolution_log(orig_h, domain, resp_h, uid=uid)
        conn_log = {
            "@path": "conn",
            "sensor_name": self.segment_name,
            "ts": self._timestamp(),
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(random.uniform(0.2, 8.0), 6),
            "orig_bytes": random.randint(400, 4_000),
            "resp_bytes": random.randint(250, 20_000),
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": random.randint(4, 30),
            "orig_ip_bytes": random.randint(800, 6_000),
            "resp_pkts": random.randint(3, 80),
            "resp_ip_bytes": random.randint(500, 25_000),
            "tunnel_parents": [],
            "orig_l2_addr": fake.mac_address(),
            "resp_l2_addr": fake.mac_address(),
            "orig_cc": fake.country_code(),
            "resp_cc": fake.country_code(),
            "community_id": self._community_id(),
            "notice": "demo_reach_malicious_ip",
        }
        http_log = {
            "@path": "http",
            "sensor_name": self.segment_name,
            "ts": self._timestamp(),
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": 443,
            "trans_depth": 1,
            "method": "GET",
            "host": domain,
            "uri": f"/api/v1/{fake.word()}",
            "referrer": "-",
            "version": "1.1",
            "user_agent": fake.user_agent(),
            "request_body_len": 0,
            "response_body_len": random.randint(500, 20_000),
            "status_code": 200,
            "status_msg": "OK",
            "tags": ["demo", "malicious_ip_contact"],
            "proxied": [],
            "orig_fuids": [],
            "orig_filenames": [],
            "orig_mime_types": [],
            "resp_fuids": [],
            "resp_filenames": [],
            "resp_mime_types": [],
        }

        for log_record in (dns_log, conn_log, http_log):
            self.send_log(log_record)

    def send_port_scan_demo(self, source_ip=None, target_ip=None, scan_count=None):
        """Send fake logs for one source scanning many ports in a short time window."""
        orig_h = source_ip or fake.ipv4_public()
        resp_h = target_ip or self._random_host()
        ports = random.sample(
            [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080],
            k=scan_count or random.randint(8, 14),
        )
        base_time = datetime.now(timezone.utc)

        for index, port in enumerate(ports):
            uid = self._uid()
            ts = self._format_timestamp(base_time + timedelta(milliseconds=index * 200))
            conn_state = random.choices(["REJ", "S0", "SF"], weights=[70, 25, 5])[0]
            self.send_log(
                {
                    "@path": "conn",
                    "sensor_name": self.segment_name,
                    "ts": ts,
                    "uid": uid,
                    "id.orig_h": orig_h,
                    "id.orig_p": random.randint(40000, 65535),
                    "id.resp_h": resp_h,
                    "id.resp_p": port,
                    "proto": "tcp",
                    "service": self._service_name_for_port(port),
                    "duration": round(random.uniform(0.001, 0.08), 6),
                    "orig_bytes": random.randint(0, 80),
                    "resp_bytes": 0 if conn_state != "SF" else random.randint(40, 500),
                    "conn_state": conn_state,
                    "local_orig": self._is_local_ip(orig_h),
                    "local_resp": self._is_local_ip(resp_h),
                    "missed_bytes": 0,
                    "history": "S" if conn_state != "SF" else "ShADadFf",
                    "orig_pkts": random.randint(1, 3),
                    "orig_ip_bytes": random.randint(40, 240),
                    "resp_pkts": 0 if conn_state != "SF" else random.randint(1, 4),
                    "resp_ip_bytes": 0 if conn_state != "SF" else random.randint(40, 600),
                    "tunnel_parents": [],
                    "orig_l2_addr": fake.mac_address(),
                    "resp_l2_addr": fake.mac_address(),
                    "orig_cc": fake.country_code(),
                    "resp_cc": fake.country_code(),
                    "community_id": self._community_id(),
                    "notice": "demo_port_scan_short_window",
                }
            )

    def send_data_exfiltration_demo(self, source_ip=None, destination_ip=None, chunk_count=None):
        """Send fake logs for one source exfiltrating data in a short time window."""
        orig_h = source_ip or self._random_host()
        resp_h = destination_ip or random.choice(self.malicious_ips or DEMO_MALICIOUS_IPS)
        domain = random.choice(EXFIL_DOMAINS)
        chunks = chunk_count or random.randint(3, 6)
        base_time = datetime.now(timezone.utc)

        self.send_log(
            self._dns_resolution_log(
                orig_h,
                domain,
                resp_h,
                ts=self._format_timestamp(base_time),
            )
        )

        for index in range(chunks):
            self._send_data_exfiltration_chunk(
                orig_h,
                resp_h,
                domain,
                self._format_timestamp(base_time + timedelta(seconds=index * 2)),
            )

    def _send_data_exfiltration_chunk(self, orig_h, resp_h, domain, ts):
        """Send one fake upload chunk for a data exfiltration scenario."""
        uid = self._uid()
        orig_p = random.randint(49152, 65535)
        exfil_bytes = random.randint(15_000_000, 120_000_000)
        request_fuid = self._file_uid()

        conn_log = {
            "@path": "conn",
            "sensor_name": self.segment_name,
            "ts": ts,
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(random.uniform(120.0, 900.0), 6),
            "orig_bytes": exfil_bytes,
            "resp_bytes": random.randint(1_000, 25_000),
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": random.randint(45_000, 650_000),
            "orig_ip_bytes": exfil_bytes + random.randint(20_000, 200_000),
            "resp_pkts": random.randint(20, 300),
            "resp_ip_bytes": random.randint(2_000, 35_000),
            "tunnel_parents": [],
            "orig_l2_addr": fake.mac_address(),
            "resp_l2_addr": fake.mac_address(),
            "orig_cc": fake.country_code(),
            "resp_cc": fake.country_code(),
            "community_id": self._community_id(),
            "notice": "demo_data_exfiltration",
        }
        http_log = {
            "@path": "http",
            "sensor_name": self.segment_name,
            "ts": ts,
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": 443,
            "trans_depth": 1,
            "method": "POST",
            "host": domain,
            "uri": f"/upload/{uuid.uuid4().hex}.zip",
            "referrer": "-",
            "version": "1.1",
            "user_agent": "corelight-demo-exfil-simulator/1.0",
            "request_body_len": exfil_bytes,
            "response_body_len": random.randint(250, 2_500),
            "status_code": 200,
            "status_msg": "OK",
            "tags": ["demo", "possible_exfiltration"],
            "proxied": [],
            "orig_fuids": [request_fuid],
            "orig_filenames": ["customer_export.zip"],
            "orig_mime_types": ["application/zip"],
            "resp_fuids": [],
            "resp_filenames": [],
            "resp_mime_types": [],
        }

        for log_record in (conn_log, http_log):
            self.send_log(log_record)

    def _dns_resolution_log(self, orig_h, domain, answer_ip, uid=None, ts=None):
        """Build a DNS log that resolves a domain to a selected IP."""
        return {
            "@path": "dns",
            "sensor_name": self.segment_name,
            "ts": ts or self._timestamp(),
            "uid": uid or self._uid(),
            "id.orig_h": orig_h,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": fake.ipv4_public(),
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": random.randint(1, 65535),
            "rtt": round(random.uniform(0.001, 0.050), 6),
            "query": domain,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": 1,
            "qtype_name": "A",
            "rcode": 0,
            "rcode_name": "NOERROR",
            "AA": False,
            "TC": False,
            "RD": True,
            "RA": True,
            "Z": 0,
            "answers": [answer_ip],
            "TTLs": [random.randint(60, 300)],
            "rejected": False,
        }

    def _flow_context(self, service=None):
        """Create shared flow fields so related logs can be correlated by uid."""
        service = service or random.choice(["dns", "http", "ssl", "ssh", "-"])
        proto = "udp" if service == "dns" and random.random() < 0.8 else "tcp"

        return {
            "uid": self._uid(),
            "orig_h": self._random_host(),
            "orig_p": random.randint(1024, 65535),
            "resp_h": self._external_ip(),
            "resp_p": self._service_port(service, proto),
            "proto": proto,
            "service": service,
        }

    def _random_host(self):
        """Return a random host IP from this segment CIDR."""
        hosts = list(self.network.hosts())
        return str(random.choice(hosts))

    def _external_ip(self):
        """Return a public IP, occasionally from the malicious IP pool."""
        if self.malicious_ips and random.random() < self.malicious_ip_rate:
            return random.choice(self.malicious_ips)
        return fake.ipv4_public()

    def _is_local_ip(self, ip_value):
        """Check whether an IP address belongs to this segment."""
        return ip_address(ip_value) in self.network

    @staticmethod
    def _timestamp():
        """Return a Corelight-style UTC timestamp string."""
        return CorelightLogGenerator._format_timestamp(datetime.now(timezone.utc))

    @staticmethod
    def _format_timestamp(timestamp):
        """Format a timezone-aware datetime as a Corelight-style UTC timestamp."""
        return timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _uid():
        """Return a Zeek-style connection UID."""
        return f"C{uuid.uuid4().hex[:17]}"

    @staticmethod
    def _file_uid():
        """Return a Zeek-style file UID."""
        return f"F{uuid.uuid4().hex[:17]}"

    @staticmethod
    def _community_id():
        """Return a demo Community ID value for flow correlation."""
        digest = base64.b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("=")
        return f"1:{digest}"

    @staticmethod
    def _service_port(service, proto):
        """Choose a destination port that fits the generated service."""
        if service == "dns":
            return 53
        if service == "http":
            return 80
        if service == "ssl":
            return 443
        if service == "ssh":
            return 22
        return random.randint(1, 65535) if proto == "udp" else random.choice([80, 443, 8080])

    @staticmethod
    def _service_name_for_port(port):
        """Return a Zeek service name for common ports."""
        return {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "ssl",
        }.get(port, "-")

    @staticmethod
    def _status_message(status_code):
        """Map an HTTP status code to its reason phrase."""
        return {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }[status_code]


def build_producer(bootstrap_servers):
    """Create a Kafka producer that serializes log records as JSON bytes."""
    return KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        value_serializer=lambda record: json.dumps(record).encode("utf-8")
    )


def parse_args():
    """Parse command-line options for Kafka and log generation settings."""
    parser = argparse.ArgumentParser(description="Generate demo Corelight logs to Kafka.")
    parser.add_argument("--bootstrap-servers", default=["localhost:9092"])
    parser.add_argument("--topic", default="network-logs")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument(
        "--malicious-ip-rate",
        type=float,
        default=0.1,
        help="Probability that an external IP field uses a malicious IP.",
    )
    parser.add_argument(
        "--attack-probability",
        type=float,
        default=0.1,
        help="Chance to emit one fake malicious scenario on each loop.",
    )
    parser.add_argument(
        "--max-attack-events",
        type=int,
        default=3,
        help="Maximum fake malicious scenarios to emit before returning to background only.",
    )
    return parser.parse_args()


def send_random_attack_scenario(segments):
    """Emit one fake malicious scenario from the available playbooks."""
    segment = random.choice(segments)
    scenario = random.choice(
        [
            segment.send_reach_malicious_ip_demo,
            segment.send_port_scan_demo,
            segment.send_data_exfiltration_demo,
        ]
    )
    scenario()



def main():
    """Create three segment generators and stream sample logs to Kafka."""
    print("Starting Corelight Kafka demo log generator...")
    args = parse_args()
    print("Using Kafka bootstrap servers:", args.bootstrap_servers)
    producer = build_producer(args.bootstrap_servers)
    print("Kafka producer created. Beginning to send logs...")
    

    segments = [
        CorelightLogGenerator(
            "corp-users",
            "10.10.10.0/24",
            args.topic,
            producer,
            DEMO_MALICIOUS_IPS,
            args.malicious_ip_rate,
        ),
        CorelightLogGenerator(
            "datacenter",
            "10.20.20.0/24",
            args.topic,
            producer,
            DEMO_MALICIOUS_IPS,
            args.malicious_ip_rate,
        ),
        CorelightLogGenerator(
            "dmz",
            "10.30.30.0/24",
            args.topic,
            producer,
            DEMO_MALICIOUS_IPS,
            args.malicious_ip_rate,
        ),
    ]
    try:
        attack_events_sent = 0
        while True:
            for segment in segments:
                segment.send_sample_batch()
            if (
                attack_events_sent < args.max_attack_events
                and random.random() < args.attack_probability
            ):
                send_random_attack_scenario(segments)
                attack_events_sent += 1
            producer.flush()
            time.sleep(args.interval)
    finally:
        producer.close()


if __name__ == "__main__":
    # python3 corelight_kafka_demo.py --topic network-logs --interval 0.5
    main()
    
