import logging
import json
import threading
from collections import Counter, deque
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", max_recent_alerts=1000):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # In-memory history so the REST API can serve recent alerts
        self.recent_alerts = deque(maxlen=max_recent_alerts)
        self.alert_counts = Counter()
        self.total_alerts = 0
        self.next_alert_id = 1
        self.lock = threading.Lock()

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'rule': threat.get('rule'),
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'source_port': packet_info.get('source_port'),
            'destination_port': packet_info.get('destination_port'),
            'confidence': float(threat.get('confidence', 0.0)),
            'details': threat
        }

        with self.lock:
            alert['id'] = self.next_alert_id
            self.next_alert_id += 1
            self.recent_alerts.append(alert)
            self.alert_counts[alert['rule'] or alert['threat_type']] += 1
            self.total_alerts += 1

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # (e.g., email, Slack, SIEM integration)

        return alert

    def get_alerts(self, limit=100, threat_type=None, rule=None,
                   min_confidence=0.0, since_id=None):
        with self.lock:
            alerts = list(self.recent_alerts)

        filtered = [
            alert for alert in alerts
            if (threat_type is None or alert['threat_type'] == threat_type)
            and (rule is None or alert['rule'] == rule)
            and alert['confidence'] >= min_confidence
            and (since_id is None or alert['id'] > since_id)
        ]
        # Newest first
        return filtered[::-1][:limit]

    def get_alert(self, alert_id):
        with self.lock:
            for alert in self.recent_alerts:
                if alert['id'] == alert_id:
                    return alert
        return None

    def get_stats(self):
        with self.lock:
            return {
                'total_alerts': self.total_alerts,
                'alerts_in_memory': len(self.recent_alerts),
                'by_rule': dict(self.alert_counts),
                'last_alert_at': (
                    self.recent_alerts[-1]['timestamp']
                    if self.recent_alerts else None
                ),
            }
