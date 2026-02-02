from scapy.all import wrpcap, rdpcap
from utils.logger import log

class PCAPManager:
    """
    Handles PCAP import/export functionality
    Compatible with Wireshark
    """

    def export_pcap(self, packets, filename):
        """
        Export captured packets to PCAP file
        packets: list of Scapy packets
        """
        if not packets:
            log("PCAP export failed: No packets")
            return False
        try:
            wrpcap(filename, packets)
            log(f"PCAP exported successfully: {filename}")
            return True
        except Exception as e:
            log(f"PCAP export error: {e}")
            return False

    def import_pcap(self, filename):
        """
        Import PCAP file and return list of packets
        """
        try:
            packets = rdpcap(filename)
            log(f"PCAP imported: {filename}")
            return packets
        except Exception as e:
            log(f"PCAP import error: {e}")
            return []
