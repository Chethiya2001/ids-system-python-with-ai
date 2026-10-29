import queue
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

    def start(self):
        interface_name = self.interface or "all available interfaces"
        print(f"Starting IDS on {interface_name}")
        try:
            self.packet_capture.start_capture(self.interface)
        except RuntimeError as error:
            print(f"Unable to start packet capture: {error}")
            return

        while True:
            try:
                if self.packet_capture.capture_error is not None:
                    print(
                        f"Packet capture stopped: "
                        f"{self.packet_capture.capture_error}"
                    )
                    break

                packet = self.packet_capture.packet_queue.get(timeout=1)
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
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()