#include <pcap.h>
#include <iostream>
#include <cstring>
#include <unordered_map>
struct arp_header {
    u_int16_t hw_type;
    u_int16_t proto_type;
    u_int8_t hw_size;
    u_int8_t proto_size;
    u_int16_t opcode;
    u_char sender_mac[6];
    u_int32_t sender_ip;
    u_char target_mac[6];
    u_int32_t target_ip;
};
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct arp_header *arp = (struct arp_header*)(packet + 14); // Skip Ethernet header

    if (ntohs(arp->opcode) == 0x0001) { 
        std::cout << "Received ARP request from " 
                  << std::hex << (int)arp->sender_mac[0] << ":" 
                  << (int)arp->sender_mac[1] << ":" 
                  << (int)arp->sender_mac[2] << ":" 
                  << (int)arp->sender_mac[3] << ":" 
                  << (int)arp->sender_mac[4] << ":" 
                  << (int)arp->sender_mac[5] 
                  << " for IP " 
                  << ntohl(arp->sender_ip) << std::endl;
    } else if (ntohs(arp->opcode) == 0x0002) { 
        std::cout << "Received ARP reply from "
                  << std::hex << (int)arp->sender_mac[0] << ":" 
                  << (int)arp->sender_mac[1] << ":" 
                  << (int)arp->sender_mac[2] << ":" 
                  << (int)arp->sender_mac[3] << ":" 
                  << (int)arp->sender_mac[4] << ":" 
                  << (int)arp->sender_mac[5] 
                  << " for IP " 
                  << ntohl(arp->sender_ip) << std::endl;
                  
    }
}
int main() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        std::cerr << "Device not found: " << errbuf << std::endl;
        return 1;
    }
    
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return 1;
    }
    
    std::cout << "Listening on device: " << dev << std::endl;
    
    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle); // Close the session
    return 0;
}