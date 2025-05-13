from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, tcp
from ryu.lib.packet import ether_types
import logging
import struct

class LearningSwitchController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(LearningSwitchController, self).__init__(*args, **kwargs)
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.mac_to_port = {}
        self.arp_table = {}  # IP to MAC mapping
        
        # Router port information
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",  # 10.0.1.1
            2: "00:00:00:00:01:02",  # 10.0.2.1
            3: "00:00:00:00:01:03"   # 192.168.1.1
        }
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        self.subnet_to_port = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "192.168.1.0/24": 3
        }
        
        # Server information
        self.server_ip = "10.0.2.2"
        self.server_subnet = "10.0.2.0/24"
        self.external_subnet = "192.168.1.0/24"
        
        self.logger.info("Controller initialized")

    def add_flow(self, datapath, match, actions, priority=0, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        self.logger.debug(f"Adding flow: {match} -> {actions}")
        datapath.send_msg(mod)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _send_icmp_reply(self, datapath, ip_pkt, icmp_pkt, in_port, eth_pkt):
        # Build ICMP reply
        icmp_reply = icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data
        )
        
        # Build IP packet
        ip_reply = ipv4.ipv4(
            proto=ip_pkt.proto,
            src=ip_pkt.dst,
            dst=ip_pkt.src,
            ttl=64
        )
        
        # Build Ethernet frame
        eth_reply = ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_IP,
            dst=eth_pkt.src,
            src=self.port_to_own_mac[in_port]
        )
        
        # Construct full packet
        pkt = packet.Packet()
        pkt.add_protocol(eth_reply)
        pkt.add_protocol(ip_reply)
        pkt.add_protocol(icmp_reply)
        
        self._send_packet(datapath, in_port, pkt)
        self.logger.info(f"Sent ICMP reply from {ip_reply.src} to {ip_reply.dst}")

    def _get_subnet(self, ip):
        for subnet in self.subnet_to_port:
            net, mask = subnet.split('/')
            if self.ip_in_subnet(ip, net, int(mask)):
                return subnet
        return None

    def _install_tcp_flow(self, datapath, in_port, out_port, eth_pkt, ip_pkt):
        # Check if this is external to server TCP connection
        if ((in_port == 3 and ip_pkt.dst == self.server_ip) or
            (ip_pkt.src == self.server_ip and self._get_subnet(ip_pkt.dst) == self.external_subnet)):
            self.logger.info(f"Blocking TCP connection: {ip_pkt.src}->{ip_pkt.dst}")
            return
            
        parser = datapath.ofproto_parser
        try:
            dst_mac = self.arp_table[ip_pkt.dst]
        except KeyError:
            dst_mac = "ff:ff:ff:ff:ff:ff"
        
        actions = [
            parser.OFPActionSetField(eth_src=self.port_to_own_mac[out_port]),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=(ip_pkt.src, '255.255.255.255'),
            ipv4_dst=(ip_pkt.dst, '255.255.255.255'),
            ip_proto=6  # TCP
        )
        self.add_flow(datapath, match, actions, priority=3, idle_timeout=5)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info(f"Switch connected: dpid={datapath.id}")
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions)

        # If this is the router, install blocking rules for external to server TCP
        if self.is_router(datapath):
            # Block external to server TCP
            match = parser.OFPMatch(
                in_port=3,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=self.server_ip,
                ip_proto=6  # TCP
            )
            self.add_flow(datapath, match, [], priority=10)
            
            # Block server to external TCP
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=self.server_ip,
                ipv4_dst=('192.168.1.0', '255.255.255.0'),
                ip_proto=6  # TCP
            )
            self.add_flow(datapath, match, [], priority=10)

    def is_router(self, datapath):
        return datapath.id == 3  # Router is dpid=3 (s3)
    
    def handle_arp(self, datapath, port, eth_pkt, arp_pkt):
        self.logger.debug(f"ARP: op={arp_pkt.opcode}, src_ip={arp_pkt.src_ip}, dst_ip={arp_pkt.dst_ip}")
        
        # Learn the source MAC
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if not self.is_router(datapath):
                return False  # Let switches flood ARP
            
            for p, ip in self.port_to_own_ip.items():
                if arp_pkt.dst_ip == ip:
                    self.logger.info(f"Generating ARP reply for {ip}")
                    
                    arp_reply = packet.Packet()
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth_pkt.ethertype,
                        dst=eth_pkt.src,
                        src=self.port_to_own_mac[p]
                    ))
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.port_to_own_mac[p],
                        src_ip=arp_pkt.dst_ip,
                        dst_mac=arp_pkt.src_mac,
                        dst_ip=arp_pkt.src_ip
                    ))
                    
                    self._send_packet(datapath, port, arp_reply)
                    return True
        return False
    
    def handle_switch_packet(self, msg, eth_pkt):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        
        # Learn MAC address
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth_pkt.src] = in_port
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if eth_pkt.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth_pkt.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst)
            self.add_flow(datapath, match, actions, priority=1, idle_timeout=10)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data
        )
        datapath.send_msg(out)
    
    def handle_router_packet(self, msg, eth_pkt):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # Handle ARP first
        if arp_pkt:
            if self.handle_arp(datapath, in_port, eth_pkt, arp_pkt):
                return
        
        # Handle ICMP (ping)
        if ip_pkt and ip_pkt.proto == 1:  # ICMP
            if ip_pkt.dst in self.port_to_own_ip.values():
                dst_port = [p for p,ip in self.port_to_own_ip.items() if ip == ip_pkt.dst][0]
                src_subnet = self._get_subnet(ip_pkt.src)
                
                # Only allow pinging gateway from same subnet
                if src_subnet != self._get_subnet(ip_pkt.dst):
                    self.logger.info(f"Blocking cross-subnet ping: {ip_pkt.src}->{ip_pkt.dst}")
                    return
                    
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    self._send_icmp_reply(datapath, ip_pkt, icmp_pkt, dst_port, eth_pkt)
                    return
        
        # Handle TCP packets
        if ip_pkt and ip_pkt.proto == 6 and tcp_pkt:  # TCP
            # Check if this is external to server TCP connection
            if ((in_port == 3 and ip_pkt.dst == self.server_ip) or
                (ip_pkt.src == self.server_ip and self._get_subnet(ip_pkt.dst) == self.external_subnet)):
                self.logger.info(f"Blocking TCP connection: {ip_pkt.src}->{ip_pkt.dst}")
                return
                
            out_port = None
            for subnet, port in self.subnet_to_port.items():
                net_addr, mask = subnet.split('/')
                if self.ip_in_subnet(ip_pkt.dst, net_addr, int(mask)):
                    out_port = port
                    break
            
            if out_port and out_port != in_port:
                self._install_tcp_flow(datapath, in_port, out_port, eth_pkt, ip_pkt)
                return
        
        # Handle other IP forwarding
        if ip_pkt:
            # Security rules
            if in_port == 3 and ip_pkt.dst.startswith(('10.0.1.', '10.0.2.')):
                self.logger.info(f"Dropping external to internal: {ip_pkt.src}->{ip_pkt.dst}")
                return
            
            if (in_port == 3 and ip_pkt.dst == self.server_ip) or \
               (ip_pkt.src == self.server_ip and ip_pkt.dst.startswith('192.168.1.')):
                self.logger.info(f"Dropping restricted traffic: {ip_pkt.src}->{ip_pkt.dst}")
                return
            
            # Find output port
            out_port = None
            for subnet, port in self.subnet_to_port.items():
                net_addr, mask = subnet.split('/')
                if self.ip_in_subnet(ip_pkt.dst, net_addr, int(mask)):
                    out_port = port
                    break
            
            if out_port and out_port != in_port:
                try:
                    dst_mac = self.arp_table[ip_pkt.dst]
                except KeyError:
                    dst_mac = "ff:ff:ff:ff:ff:ff"
                
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                actions = [
                    parser.OFPActionSetField(eth_src=self.port_to_own_mac[out_port]),
                    parser.OFPActionSetField(eth_dst=dst_mac),
                    parser.OFPActionOutput(out_port)
                ]
                
                # Install flow
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth_pkt.ethertype,
                    ipv4_dst=(ip_pkt.dst, '255.255.255.255')
                )
                self.add_flow(datapath, match, actions, priority=2, idle_timeout=20)
                
                # Send packet
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                    actions=actions, data=data
                )
                datapath.send_msg(out)
    
    def ip_in_subnet(self, ip, subnet, mask):
        ip_num = self.ip_to_int(ip)
        subnet_num = self.ip_to_int(subnet)
        return (ip_num & ((1 << 32) - (1 << (32 - mask)))) == subnet_num
    
    def ip_to_int(self, ip):
        parts = list(map(int, ip.split('.')))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            
            if not eth_pkt:
                return
            
            if self.is_router(datapath):
                self.handle_router_packet(msg, eth_pkt)
            else:
                self.handle_switch_packet(msg, eth_pkt)
        except Exception as e:
            self.logger.error(f"PacketIn error: {str(e)}", exc_info=True)
