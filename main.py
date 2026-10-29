import argparse
import queue
import threading
from datetime import datetime
from alertSystem import AlertSystem
from detector import DetectorEngine
from packetCapture import PacketCapture
from traficAnlyzer import TrafficAnalyzer
from scapy.all import sniff,IP, TCP


class IntrusionDetectionSystem:
    def __init__(self, interface=None):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectorEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

        # Runtime state exposed through the REST API
        self.stop_event = threading.Event()
        self.ids_thread = None
        self.started_at = None
        self.packets_processed = 0
        self.last_error = None

    @property
    def is_running(self):
        return self.ids_thread is not None and self.ids_thread.is_alive()

    def start(self):
        interface_name = self.interface or "all available interfaces"
        print(f"Starting IDS on {interface_name}")
        self.stop_event.clear()
        self.last_error = None
        try:
            self.packet_capture.start_capture(self.interface)
        except (RuntimeError, ValueError) as error:
            print(f"Unable to start packet capture: {error}")
            self.last_error = str(error)
            return

        self.started_at = datetime.now()

        while not self.stop_event.is_set():
            try:
                if self.packet_capture.capture_error is not None:
                    print(
                        f"Packet capture stopped: "
                        f"{self.packet_capture.capture_error}"
                    )
                    self.last_error = str(self.packet_capture.capture_error)
                    break

                packet = self.packet_capture.packet_queue.get(timeout=1)
                self.packets_processed += 1
                features = self.traffic_analyzer.analyze_traffic(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                break

        self.packet_capture.stop()
        self.started_at = None

    def start_in_background(self):
        if self.is_running:
            return False

        self.ids_thread = threading.Thread(target=self.start, daemon=True)
        self.ids_thread.start()
        return True

    def stop(self):
        self.stop_event.set()
        if self.ids_thread is not None and self.ids_thread is not threading.current_thread():
            self.ids_thread.join(timeout=5)

    def get_status(self):
        uptime = None
        if self.started_at is not None:
            uptime = (datetime.now() - self.started_at).total_seconds()

        return {
            'running': self.is_running,
            'interface': self.interface or "all",
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'uptime_seconds': uptime,
            'packets_processed': self.packets_processed,
            'packet_queue_size': self.packet_capture.packet_queue.qsize(),
            'active_flows': self.traffic_analyzer.flow_count(),
            'anomaly_detector_trained': self.detection_engine.is_anomaly_detector_trained,
            'last_error': self.last_error,
        }


def parse_args():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("--interface", "-i", help="Network interface to sniff on")
    parser.add_argument("--api", action="store_true", help="Enable the REST API for remote monitoring")
    parser.add_argument("--host", default="127.0.0.1", help="REST API bind address")
    parser.add_argument("--port", type=int, default=8000, help="REST API port")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    ids = IntrusionDetectionSystem(interface=args.interface)

    if args.api:
        from api import run_api

        ids.start_in_background()
        try:
            run_api(ids, host=args.host, port=args.port)
        finally:
            ids.stop()
    else:
        ids.start()
