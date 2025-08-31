import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
import string


class DataGenerator:
    def __init__(self):
        # Network identifiers with labels
        self.normal_ips = {
            "10.0.1.10": "CORP-WEB-01",
            "10.0.1.11": "CORP-DB-01", 
            "10.0.1.12": "CORP-APP-01",
            "192.168.1.100": "OFFICE-PC-100",
            "192.168.1.101": "OFFICE-PC-101",
            "172.16.0.50": "DEV-SERVER-01",
            "172.16.0.51": "DEV-SERVER-02"
        }
        self.suspicious_ips = {
            "185.220.101.45": "TOR-EXIT-NODE",
            "45.155.205.233": "KNOWN-C2-SERVER",
            "199.195.253.156": "SUSPICIOUS-VPN",
            "192.241.220.147": "SCANNER-BOT",
            "104.248.144.120": "CRYPTO-MINER"
        }
        # User profiles with details
        self.users = {
            "ram.katakam": {"name": "Ram Katakam", "role": "Director", "dept": "Engineering"},
            "pavan.katakam": {"name": "Pavan Katakam", "role": "Senior Developer", "dept": "Engineering"},
            "kittu.katakam": {"name": "Kittu Katakam", "role": "Manager", "dept": "Operations"},
            "jyothi.katakam": {"name": "Jyothi Katakam", "role": "Lead Analyst", "dept": "Finance"},
            "mani.katakam": {"name": "Mani Katakam", "role": "Admin", "dept": "IT"},
            "venkat.bezawada": {"name": "Venkat Bezawada", "role": "Security Engineer", "dept": "Security"},
            "ramakrishna.katakam": {"name": "Ramakrishna Katakam", "role": "DevOps Lead", "dept": "DevOps"}
        }
        self.resources = [
            "/data/reports/sales.xlsx", "/admin/config.json", "/logs/system.log",
            "/home/documents/project.doc", "/sensitive/financial.db",
            "/public/readme.txt", "/backup/database.sql"
        ]
        self.locations = ["Office", "Home", "Coffee Shop", "Airport", "Hotel", "Unknown"]
        self.protocols = {
            "TCP": ["HTTP", "HTTPS", "SSH", "FTP", "SMTP"],
            "UDP": ["DNS", "DHCP", "SNMP", "NTP"]
        }
        
    def generate_event(self) -> Dict[str, Any]:
        """Generate a random event (network or behavior) with low anomaly rate"""
        if random.random() < 0.5:
            if random.random() < 0.95:  # 95% normal events
                return self.generate_normal_network_event()
            else:
                return self.generate_suspicious_network_event()
        else:
            if random.random() < 0.95:  # 95% normal events
                return self.generate_normal_behavior_event()
            else:
                return self.generate_suspicious_behavior_event()
    
    def generate_normal_network_event(self) -> Dict[str, Any]:
        source_ip = random.choice(list(self.normal_ips.keys()))
        dest_ip = random.choice(list(self.normal_ips.keys()))
        protocol = random.choice(['TCP', 'UDP'])
        
        return {
            'type': 'network',
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'source_host': self.normal_ips[source_ip],
            'destination_ip': dest_ip,
            'destination_host': self.normal_ips[dest_ip],
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice([80, 443, 22, 3306, 5432]),
            'protocol': protocol,
            'service': random.choice(self.protocols[protocol]),
            'bytes_sent': random.randint(100, 50000),
            'bytes_received': random.randint(100, 50000),
            'duration': random.uniform(0.1, 300),
            'packet_count': random.randint(10, 1000),
            'flags': None
        }
    
    def generate_suspicious_network_event(self) -> Dict[str, Any]:
        pattern_type = random.choice(['external_attack', 'data_exfil', 'backdoor'])
        
        if pattern_type == 'external_attack':
            source_ip = random.choice(list(self.suspicious_ips.keys()))
            dest_ip = random.choice(list(self.normal_ips.keys()))
            event = {
                'source_ip': source_ip,
                'source_host': self.suspicious_ips[source_ip],
                'destination_ip': dest_ip,
                'destination_host': self.normal_ips[dest_ip],
                'destination_port': random.choice([22, 3389, 445]),
                'bytes_sent': random.randint(5000000, 50000000),
                'duration': random.uniform(3600, 7200),
                'service': 'ATTACK-SCAN'
            }
        elif pattern_type == 'data_exfil':
            source_ip = random.choice(list(self.normal_ips.keys()))
            dest_ip = random.choice(list(self.suspicious_ips.keys()))
            event = {
                'source_ip': source_ip,
                'source_host': self.normal_ips[source_ip],
                'destination_ip': dest_ip,
                'destination_host': self.suspicious_ips[dest_ip],
                'bytes_sent': random.randint(10000000, 100000000),
                'duration': random.uniform(1800, 3600),
                'service': 'DATA-EXFILTRATION'
            }
        else:  # backdoor
            event = {
                'destination_port': 4444,
                'protocol': 'TCP',
                'bytes_sent': random.randint(1000000, 10000000),
                'packet_count': random.randint(5000, 50000),
                'service': 'BACKDOOR-C2'
            }
        
        base_event = self.generate_normal_network_event()
        base_event.update(event)
        return base_event
    
    def generate_normal_behavior_event(self) -> Dict[str, Any]:
        user_id = random.choice(list(self.users.keys()))
        user_info = self.users[user_id]
        hour = random.choice([9, 10, 11, 14, 15, 16])
        
        return {
            'type': 'behavior',
            'timestamp': datetime.now().replace(hour=hour).isoformat(),
            'user_id': user_id,
            'user_name': user_info['name'],
            'user_role': user_info['role'],
            'department': user_info['dept'],
            'entity_id': f"WORKSTATION-{random.randint(100, 999)}",
            'event_type': random.choice(['login', 'file_access', 'api_call']),
            'action': random.choice(['read', 'write', 'execute', 'download']),
            'resource': random.choice(self.resources),
            'location': random.choice(['Office', 'Home']),
            'device_id': f"DEV-{random.randint(1000, 9999)}",
            'session_id': f"SES-{''.join(random.choices(string.ascii_uppercase, k=8))}",
            'metadata': {'ip_address': random.choice(list(self.normal_ips.keys()))}
        }
    
    def generate_suspicious_behavior_event(self) -> Dict[str, Any]:
        suspicious_patterns = [
            {
                'timestamp': datetime.now().replace(hour=random.choice([2, 3, 4, 23])).isoformat(),
                'event_type': 'login',
                'location': 'Unknown'
            },
            {
                'event_type': 'privilege_escalation',
                'action': 'elevate',
                'resource': '/admin/system'
            },
            {
                'event_type': 'file_access',
                'action': 'download',
                'resource': random.choice(['/sensitive/financial.db', '/backup/database.sql']),
                'location': random.choice(['Coffee Shop', 'Unknown'])
            }
        ]
        
        base_event = self.generate_normal_behavior_event()
        suspicious_pattern = random.choice(suspicious_patterns)
        base_event.update(suspicious_pattern)
        return base_event
    
    def generate_event_stream(self, count: int = 100, anomaly_rate: float = 0.1) -> List[Dict[str, Any]]:
        events = []
        
        for _ in range(count):
            if random.random() < anomaly_rate:
                if random.random() < 0.5:
                    events.append(self.generate_suspicious_network_event())
                else:
                    events.append(self.generate_suspicious_behavior_event())
            else:
                if random.random() < 0.5:
                    events.append(self.generate_normal_network_event())
                else:
                    events.append(self.generate_normal_behavior_event())
                    
        return events
    
    def generate_critical_threat_event(self) -> Dict[str, Any]:
        """Generate a single critical threat event that will trigger maximum threat level"""
        source_ip = random.choice(list(self.suspicious_ips.keys()))
        dest_ip = random.choice(list(self.normal_ips.keys()))
        
        threat_patterns = [
            {
                'type': 'network',
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'source_host': self.suspicious_ips[source_ip],
                'destination_ip': dest_ip,
                'destination_host': self.normal_ips[dest_ip],
                'source_port': 4444,
                'destination_port': 22,
                'protocol': 'TCP',
                'service': 'CRITICAL-ATTACK',
                'bytes_sent': 100000000,  # 100MB - massive data transfer
                'bytes_received': 1000,
                'duration': 7200,  # 2 hours - very long connection
                'packet_count': 100000,
                'flags': 'PSH,ACK,URG'  # Suspicious flags
            },
            {
                'type': 'behavior',
                'timestamp': datetime.now().replace(hour=3).isoformat(),  # 3 AM
                'user_id': 'mani.katakam',  # IT Admin - compromised account
                'user_name': 'Mani Katakam',
                'user_role': 'Admin',
                'department': 'IT',
                'entity_id': 'SERVER-CRITICAL',
                'event_type': 'privilege_escalation',
                'action': 'elevate_to_root',
                'resource': '/etc/shadow',  # Critical system file
                'location': 'Unknown',
                'device_id': 'DEV-SUSPICIOUS',
                'session_id': 'SES-CRITICAL',
                'metadata': {'severity': 'critical', 'bypass_auth': True, 'ip_address': source_ip}
            },
            {
                'type': 'behavior',
                'timestamp': datetime.now().replace(hour=2).isoformat(),
                'user_id': 'ram.katakam',  # Director - highly suspicious
                'user_name': 'Ram Katakam',
                'user_role': 'Director',
                'department': 'Engineering',
                'entity_id': 'DATABASE-PROD',
                'event_type': 'file_access',
                'action': 'mass_download',
                'resource': '/sensitive/customer_database.db',
                'location': 'Foreign Country',
                'device_id': 'DEV-UNKNOWN',
                'session_id': 'SES-MALICIOUS',
                'metadata': {'files_accessed': 10000, 'data_size_gb': 50, 'ip_address': source_ip}
            }
        ]
        return random.choice(threat_patterns)
    
    def generate_network_attack_scenario(self) -> List[Dict[str, Any]]:
        """Generate network-specific attack scenario"""
        events = []
        attacker_ip = random.choice(list(self.suspicious_ips.keys()))
        target_ip = random.choice(list(self.normal_ips.keys()))
        
        # Port scanning
        for port in [22, 80, 443, 3306, 3389, 445]:
            events.append({
                'type': 'network',
                'timestamp': datetime.now().isoformat(),
                'source_ip': attacker_ip,
                'source_host': self.suspicious_ips[attacker_ip],
                'destination_ip': target_ip,
                'destination_host': self.normal_ips[target_ip],
                'source_port': random.randint(40000, 65535),
                'destination_port': port,
                'protocol': 'TCP',
                'service': 'PORT-SCAN',
                'bytes_sent': random.randint(100, 1000),
                'bytes_received': random.randint(0, 100),
                'duration': 0.1,
                'packet_count': 3,
                'flags': 'SYN'
            })
        
        # DDoS attempt
        for _ in range(3):
            events.append({
                'type': 'network',
                'timestamp': datetime.now().isoformat(),
                'source_ip': attacker_ip,
                'source_host': self.suspicious_ips[attacker_ip],
                'destination_ip': target_ip,
                'destination_host': self.normal_ips[target_ip],
                'source_port': random.randint(1024, 65535),
                'destination_port': 80,
                'protocol': 'TCP',
                'service': 'DDOS-FLOOD',
                'bytes_sent': random.randint(1000000, 5000000),
                'bytes_received': 0,
                'duration': 0.01,
                'packet_count': random.randint(10000, 50000),
                'flags': 'SYN'
            })
        
        return events
    
    def generate_ueba_attack_scenario(self) -> List[Dict[str, Any]]:
        """Generate UEBA-specific attack scenario"""
        events = []
        compromised_user = random.choice(list(self.users.keys()))
        user_info = self.users[compromised_user]
        
        # Impossible travel - login from multiple locations quickly
        locations = ['New York', 'London', 'Tokyo', 'Moscow']
        for i, location in enumerate(locations):
            events.append({
                'type': 'behavior',
                'timestamp': (datetime.now() + timedelta(minutes=i*5)).isoformat(),
                'user_id': compromised_user,
                'user_name': user_info['name'],
                'user_role': user_info['role'],
                'department': user_info['dept'],
                'entity_id': f'WORKSTATION-{random.randint(100, 999)}',
                'event_type': 'login',
                'action': 'authenticate',
                'resource': '/login',
                'location': location,
                'device_id': f'DEV-{location.upper()}',
                'session_id': f'SES-TRAVEL-{i}',
                'metadata': {'impossible_travel': True}
            })
        
        # Mass data access
        sensitive_files = [
            '/hr/employee_records.db',
            '/finance/payroll.xlsx',
            '/legal/contracts.pdf',
            '/customer/credit_cards.csv'
        ]
        
        for file in sensitive_files:
            events.append({
                'type': 'behavior',
                'timestamp': datetime.now().isoformat(),
                'user_id': compromised_user,
                'user_name': user_info['name'],
                'user_role': user_info['role'],
                'department': user_info['dept'],
                'entity_id': 'FILE-SERVER',
                'event_type': 'file_access',
                'action': 'download',
                'resource': file,
                'location': 'Unknown',
                'device_id': 'DEV-SUSPICIOUS',
                'session_id': 'SES-MASS-ACCESS',
                'metadata': {'bulk_download': True}
            })
        
        return events
    
    def generate_attack_pattern(self, attack_type: str = 'ddos') -> List[Dict[str, Any]]:
        """Generate attack pattern events based on type"""
        if attack_type == 'ddos':
            return self.generate_network_attack_scenario()
        elif attack_type == 'privilege_escalation':
            return self.generate_ueba_attack_scenario()
        elif attack_type == 'data_exfiltration':
            return self.generate_attack_scenario('data_exfiltration')
        elif attack_type == 'brute_force':
            return self.generate_attack_scenario('brute_force')
        else:
            # Default to network attack
            return self.generate_network_attack_scenario()
    
    def generate_attack_scenario(self, scenario_type: str = 'data_exfiltration') -> List[Dict[str, Any]]:
        events = []
        attacker_ip = random.choice(list(self.suspicious_ips.keys()))
        victim_user = random.choice(list(self.users.keys()))
        timestamp = datetime.now()
        
        if scenario_type == 'data_exfiltration':
            events.append({
                'type': 'behavior',
                'timestamp': timestamp.isoformat(),
                'user_id': victim_user,
                'entity_id': 'WORKSTATION-501',
                'event_type': 'login',
                'action': 'authenticate',
                'resource': '/login',
                'location': 'Unknown',
                'device_id': 'DEV-9999',
                'session_id': 'SES-SUSPICIOUS',
                'metadata': {}
            })
            
            timestamp += timedelta(minutes=2)
            events.append({
                'type': 'behavior',
                'timestamp': timestamp.isoformat(),
                'user_id': victim_user,
                'entity_id': 'WORKSTATION-501',
                'event_type': 'privilege_escalation',
                'action': 'elevate',
                'resource': '/admin/system',
                'location': 'Unknown',
                'device_id': 'DEV-9999',
                'session_id': 'SES-SUSPICIOUS',
                'metadata': {}
            })
            
            timestamp += timedelta(minutes=5)
            for resource in ['/sensitive/financial.db', '/backup/database.sql', '/admin/config.json']:
                events.append({
                    'type': 'behavior',
                    'timestamp': timestamp.isoformat(),
                    'user_id': victim_user,
                    'entity_id': 'WORKSTATION-501',
                    'event_type': 'file_access',
                    'action': 'download',
                    'resource': resource,
                    'location': 'Unknown',
                    'device_id': 'DEV-9999',
                    'session_id': 'SES-SUSPICIOUS',
                    'metadata': {}
                })
                timestamp += timedelta(seconds=30)
            
            events.append({
                'type': 'network',
                'timestamp': timestamp.isoformat(),
                'source_ip': '10.0.1.10',
                'destination_ip': attacker_ip,
                'source_port': random.randint(1024, 65535),
                'destination_port': 443,
                'protocol': 'TCP',
                'bytes_sent': 50000000,
                'bytes_received': 1000,
                'duration': 600,
                'packet_count': 50000,
                'flags': 'PSH,ACK'
            })
            
        elif scenario_type == 'brute_force':
            for i in range(10):
                events.append({
                    'type': 'behavior',
                    'timestamp': timestamp.isoformat(),
                    'user_id': victim_user,
                    'entity_id': f'WORKSTATION-{random.randint(100, 999)}',
                    'event_type': 'login',
                    'action': 'failed_authenticate',
                    'resource': '/login',
                    'location': 'Unknown',
                    'device_id': f'DEV-{random.randint(1000, 9999)}',
                    'session_id': f'SES-BRUTE-{i}',
                    'metadata': {'attempt': i + 1}
                })
                timestamp += timedelta(seconds=2)
                
        elif scenario_type == 'critical_multi_stage':
            # Multi-stage critical attack with maximum threat indicators
            # Stage 1: Multiple privilege escalations
            attacker_user = 'mani.katakam'  # Compromised admin account
            user_info = self.users[attacker_user]
            
            for i in range(5):
                events.append({
                    'type': 'behavior',
                    'timestamp': timestamp.isoformat(),
                    'user_id': attacker_user,
                    'user_name': user_info['name'],
                    'user_role': user_info['role'],
                    'department': user_info['dept'],
                    'entity_id': f'SERVER-{i}',
                    'event_type': 'privilege_escalation',
                    'action': 'elevate',
                    'resource': '/root/access',
                    'location': 'Unknown',
                    'device_id': 'DEV-COMPROMISED',
                    'session_id': 'SES-ATTACK',
                    'metadata': {'stage': i+1, 'ip_address': attacker_ip}
                })
                timestamp += timedelta(seconds=10)
            
            # Stage 2: Massive data exfiltration
            source_ip = '10.0.1.10'
            events.append({
                'type': 'network',
                'timestamp': timestamp.isoformat(),
                'source_ip': source_ip,
                'source_host': self.normal_ips.get(source_ip, 'CORP-WEB-01'),
                'destination_ip': attacker_ip,
                'destination_host': self.suspicious_ips.get(attacker_ip, 'UNKNOWN-C2'),
                'source_port': random.randint(1024, 65535),
                'destination_port': 443,
                'protocol': 'TCP',
                'service': 'MASSIVE-EXFILTRATION',
                'bytes_sent': 500000000,  # 500MB
                'bytes_received': 1000,
                'duration': 10800,  # 3 hours
                'packet_count': 500000,
                'flags': 'PSH,ACK,URG,FIN'
            })
            
            # Stage 3: Critical system file access
            for _ in range(3):
                events.append(self.generate_critical_threat_event())
                
        return events