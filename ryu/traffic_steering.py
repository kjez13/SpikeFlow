from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, ipv4
from ryu.ofproto import ofproto_v1_3
from datetime import datetime

class TrafficSteering(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Identyfikatory prze³¹czników (DPID)
    ROUTER1_ID = 0x1
    ROUTER2_ID = 0x2
    ROUTER3_ID = 0x3
    ROUTER4_ID = 0x4

    # Czas zmiany œcie¿ki w sekundach
    t = 4

    def __init__(self, *args, **kwargs):
        super(TrafficSteering, self).__init__(*args, **kwargs)
        self.flag = True
        self.last_change = datetime.now().timestamp()
        self.datapaths = {}  # S³ownik przechowuj¹cy aktywne datapathy

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Obs³uga zdarzenia po po³¹czeniu siê prze³¹cznika z kontrolerem
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath  # Rejestracja datapatha
        self.logger.info(f"Switch {dpid} connected.")

        # Instalacja regu³y table-miss
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, timeout=0):
        # Funkcja dodaj¹ca przep³ywy do prze³¹cznika
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                hard_timeout=timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Obs³uga pakietów przychodz¹cych do kontrolera
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Sprawdzanie czasu i aktualizacja flagi
        current_time = datetime.now().timestamp()
        if current_time - self.last_change >= self.t:
            self.flag = not self.flag
            self.last_change = current_time
            self.logger.info(f"Path changed to: {'Router3' if self.flag else 'Router2'}")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignorowanie pakietów LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Pobranie adresu IP docelowego
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            dst_ip = ip_pkt.dst
        else:
            dst_ip = None

        in_port = msg.match['in_port']

        # Implementacja logiki dla ka¿dego prze³¹cznika
        if dpid == self.ROUTER1_ID:
            self.handle_router1(datapath, parser)
        elif dpid == self.ROUTER2_ID:
            self.handle_router2(datapath, parser, in_port)
        elif dpid == self.ROUTER3_ID:
            self.handle_router3(datapath, parser, in_port)
        elif dpid == self.ROUTER4_ID:
            self.handle_router4(datapath, parser)
        else:
            self.logger.warning(f"Unknown DPID: {dpid}")

    def handle_router1(self, datapath, parser):
        # Regu³y dla Routera 1 (DPID=1)
        # 1. dst_ip=192.168.30.1 › out_port=3 lub 4 (zmiana œcie¿ki)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst='192.168.30.1')
        out_port = 3 if self.flag else 4  # Alternatywnie: port3 (Switch2) lub port4 (Switch3)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions, timeout=self.t)

        # 2. dst_ip=192.168.30.3 › out_port=5 (Host2)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst='192.168.30.3')
        actions = [parser.OFPActionOutput(5)]
        self.add_flow(datapath, 1, match, actions)

    def handle_router2(self, datapath, parser, in_port):
        # Regu³y dla Routera 2 (DPID=2)
        if in_port == 4:
            # Pakiet przychodz¹cy z Routera 1 › wysy³anie do Routera 4
            out_port = 3
        elif in_port == 3:
            # Pakiet przychodz¹cy z Routera 4 › wysy³anie do Routera 1
            out_port = 4
        else:
            return  # Nie obs³ugujemy innych portów
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port)
        self.add_flow(datapath, 1, match, actions)

    def handle_router3(self, datapath, parser, in_port):
        # Regu³y dla Routera 3 (DPID=3) - takie same jak dla Routera 2
        self.handle_router2(datapath, parser, in_port)

    def handle_router4(self, datapath, parser):
        # Regu³y dla Routera 4 (DPID=4)
        # 1. dst_ip=192.168.30.1 › out_port=2 (Host1)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst='192.168.30.1')
        actions = [parser.OFPActionOutput(2)]
        self.add_flow(datapath, 1, match, actions, timeout=self.t)

        # 2. Nie ma potrzeby obs³ugi dst_ip=192.168.30.3, poniewa¿ Host2 jest bezpoœrednio pod³¹czony do Routera 1
        # Jeœli potrzebujesz obs³ugi dodatkowych adresów IP, dodaj odpowiednie regu³y tutaj
