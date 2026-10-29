from scapy.all import conf, get_if_list, sniff, IP, TCP
import threading
import queue


class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.capture_thread = None
        self.capture_error = None

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface=None):
        if conf.L2socket is None:
            raise RuntimeError(
                "Layer-2 packet capture is unavailable. Install Npcap from "
                "https://npcap.com/ and enable WinPcap API-compatible mode."
            )

        if interface is not None:
            available_interfaces = get_if_list()
            if interface not in available_interfaces:
                available = ", ".join(available_interfaces)
                raise ValueError(
                    f"Interface '{interface}' not found. "
                    f"Available interfaces: {available}"
                )

        def capture():
            try:
                sniff(
                    iface=interface,
                    filter="ip and tcp",
                    prn=self.packet_callback,
                    store=False,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
            except (OSError, RuntimeError, ValueError) as error:
                self.capture_error = error

        self.stop_event.clear()
        self.capture_error = None
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.capture_thread is not None:
            self.capture_thread.join(timeout=2)
        
