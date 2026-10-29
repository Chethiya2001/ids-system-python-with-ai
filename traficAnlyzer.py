from collections import defaultdict
from scapy.all import sniff,IP, TCP
from threading import Lock

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None
        })
        self.lock = Lock()

    def analyze_traffic(self,packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, port_src, ip_dst, port_dst)

            with self.lock:
                stat = self.flow_stats[flow_key]
                stat['packet_count'] += 1
                stat['byte_count'] += len(packet)
                current_time = packet.time
                if not stat['start_time']:
                    stat['start_time'] = current_time
                stat['end_time'] = current_time

            return self.extract_flow_info(packet, stat)

    def get_flow_summary(self, limit=50):
        with self.lock:
            flows = [
                (flow_key, dict(stat))
                for flow_key, stat in self.flow_stats.items()
            ]

        flows.sort(key=lambda flow: flow[1]['packet_count'], reverse=True)
        return [
            {
                'source_ip': flow_key[0],
                'source_port': flow_key[1],
                'destination_ip': flow_key[2],
                'destination_port': flow_key[3],
                'packet_count': stat['packet_count'],
                'byte_count': stat['byte_count'],
                'start_time': float(stat['start_time'] or 0),
                'end_time': float(stat['end_time'] or 0),
            }
            for flow_key, stat in flows[:limit]
        ]

    def flow_count(self):
        with self.lock:
            return len(self.flow_stats)

    def extract_flow_info(self, packet, stat):
        flow_duration = max(stat['end_time'] - stat['start_time'], 1e-6)
        return {
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': stat['packet_count'] / flow_duration,
            'byte_rate': stat['byte_count'] / flow_duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }
