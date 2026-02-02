from PySide6.QtCore import QThread, Signal
from scapy.all import sniff
from core.pcap_manager import PCAPManager

class ScapySniffer(QThread):
    packet_signal = Signal(object)  # send Scapy pkt
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = True
        self.packets = []             # store packets for PCAP
        self.pcap_manager = PCAPManager()

    def run(self):
        sniff(prn=self.process, store=False,
              stop_filter=lambda x: not self.running,
              iface=self.iface)

    def process(self, pkt):
        self.packets.append(pkt)
        self.packet_signal.emit(pkt)

    def stop(self):
        self.running = False

    # --- NEW METHODS FOR PCAP ---
    def export_pcap(self, filename):
        return self.pcap_manager.export_pcap(self.packets, filename)

    def import_pcap(self, filename):
        pkts = self.pcap_manager.import_pcap(filename)
        for pkt in pkts:
            self.packets.append(pkt)
            self.packet_signal.emit(pkt)
        return pkts
