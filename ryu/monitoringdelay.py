# monitoringdelay.py

from ryu.base import app_manager
from ryu.controller import ofp_event, event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
import time
import functools
import logging

def timestamp_ms():
    return time.time() * 1000

class Monitoring(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    CUSTOM_ETHERTYPE = 0x88B5  # Zmieniona wartość EtherType na niestandardową

    def __init__(self, *args, **kwargs):
        super(Monitoring, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger('Monitoring')

        # Pobranie odniesienia do aplikacji SimpleSwitch13
        self.simple_switch_app = app_manager.lookup_service_brick('SimpleSwitch13')

        if self.simple_switch_app is None:
            self.logger.error("Cannot find the SimpleSwitch13 application")
            return

        # Dostęp do danych z SimpleSwitch13
        self.stats_data = self.simple_switch_app.stats_data
        self.topology_data = self.simple_switch_app.topology_data
        self.datapaths = self.simple_switch_app.datapaths

        self.send_times = {}      # klucz: (src_dpid, dst_dpid, seq_num)
        self.receive_times = {}   # klucz: (src_dpid, dst_dpid, seq_num)

        self.sequence_number = 0  # Inicjalizacja numeru sekwencyjnego

        self.t_control = {}        # Opóźnienia kontroler-przełącznik
        self.echo_sent_time = {}   # Czasy wysłania Echo Request
        self.echo_delay_thread = hub.spawn(self._measure_control_delay)

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        # Obsługa zmian stanu datapath
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Register datapath: %s", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            pass
        else:
            if datapath.id in self.datapaths:
                self.logger.info("Unregister datapath: %s", datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        # Instalacja reguł przepływu do wysyłania pakietów sondy do kontrolera
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Dopasowanie pakietów z niestandardowym EtherType
        match = parser.OFPMatch(eth_type=self.CUSTOM_ETHERTYPE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=50000, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # Metoda dodawania wpisów przepływu
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _monitor(self):
        # Okresowe wysyłanie pakietów sondy i przetwarzanie danych opóźnień
        while True:
            self.send_probe_packets()
            hub.sleep(1)
            self.assemble_delay_data()
            # Czyszczenie czasów po przetworzeniu
            self.send_times.clear()
            self.receive_times.clear()
            hub.sleep(1)

    def send_probe_packets(self):
        # Wysyłanie pakietów sondy przez wszystkie łącza
        processed_links = set()
        for link in self.topology_data.get('edges', []):
            src_dpid = link['source']
            dst_dpid = link['target']
            link_key = tuple(sorted((src_dpid, dst_dpid)))
            if link_key in processed_links:
                continue
            processed_links.add(link_key)
            src_dp = self.datapaths.get(src_dpid)
            dst_dp = self.datapaths.get(dst_dpid)

            if src_dp is None or dst_dp is None:
                continue

            src_port_no = self._get_port_no(src_dpid, dst_dpid)
            if src_port_no is None:
                continue

            self.sequence_number += 1  # Zwiększenie numeru sekwencyjnego
            seq_num = self.sequence_number

            key = (src_dpid, dst_dpid, seq_num)
            self.send_times[key] = timestamp_ms()
            probe_packet = self._assemble_probe_packet(src_dpid, seq_num)
            actions = [src_dp.ofproto_parser.OFPActionOutput(src_port_no)]
            out = src_dp.ofproto_parser.OFPPacketOut(
                datapath=src_dp,
                buffer_id=src_dp.ofproto.OFP_NO_BUFFER,
                in_port=src_dp.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=probe_packet.data
            )
            src_dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Obsługa przychodzących pakietów
        msg = ev.msg
        datapath = msg.datapath
        dpid_dst = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == self.CUSTOM_ETHERTYPE:
            # Przetwarzanie pakietu sondy
            src_mac_no_colon = eth.src.replace(':', '')
            src_dpid = int(src_mac_no_colon, 16)
            # Odczytanie numeru sekwencyjnego z surowego payloadu
            eth_length = ethernet.ethernet._MIN_LEN  # Długość nagłówka Ethernet (14 bajtów)
            payload = msg.data[eth_length:]
            if len(payload) >= 4:
                seq_num = int.from_bytes(payload[:4], byteorder='big')
                key = (src_dpid, dpid_dst, seq_num)
                self.receive_times[key] = timestamp_ms()
            else:
                self.logger.warning("Received probe packet without sequence number")
            # Oznaczenie pakietu jako obsłużonego
            ev.msg._handled = True
        else:
            # Pozwól innym handlerom przetworzyć pakiet
            pass

    def assemble_delay_data(self):
        # Obliczanie opóźnień i aktualizacja danych w controller1.py
        for key, time_recv in self.receive_times.items():
            src_dpid, dst_dpid, seq_num = key
            time_send = self.send_times.get(key)
            if time_send:
                total_delay = time_recv - time_send
                t_control_src = self.t_control.get(src_dpid, 0)
                t_control_dst = self.t_control.get(dst_dpid, 0)
                link_delay = total_delay - t_control_src - t_control_dst
                link_delay = max(link_delay, 0)
                connection = f"{src_dpid}-{dst_dpid}"
                timestamp = int(time.time())
                data_point = {
                    'connection': connection,
                    'timestamp': timestamp,
                    'delay_ms': link_delay
                }
                # Aktualizacja danych w controler.py
                self.simple_switch_app.update_delay_data(data_point)

    def _get_port_no(self, src_dpid, dst_dpid):
        # Znalezienie portu na src_dpid prowadzącego do dst_dpid
        for link in self.simple_switch_app.links:
            if link.src.dpid == src_dpid and link.dst.dpid == dst_dpid:
                return link.src.port_no
        return None

    @functools.lru_cache(maxsize=None)
    def _assemble_probe_packet(self, src_dpid, seq_num):
        # Tworzenie pakietu sondy z niestandardowym EtherType i numerem sekwencyjnym
        src_mac = ':'.join(format(src_dpid, '012x')[i:i+2] for i in range(0, 12, 2))
        e = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src_mac, ethertype=self.CUSTOM_ETHERTYPE)
        p = packet.Packet()
        p.add_protocol(e)
        # Dodanie numeru sekwencyjnego jako payload
        p.add_protocol(seq_num.to_bytes(4, byteorder='big'))
        p.serialize()
        return p

    def _measure_control_delay(self):
        # Pomiar opóźnienia komunikacji kontroler-przełącznik
        while True:
            for datapath in self.datapaths.values():
                self.send_echo_request(datapath)
            hub.sleep(1)

    def send_echo_request(self, datapath):
        # Wysyłanie Echo Request do przełącznika
        parser = datapath.ofproto_parser
        echo_req = parser.OFPEchoRequest(datapath, data=b'ping')
        datapath.send_msg(echo_req)
        self.echo_sent_time[datapath.id] = timestamp_ms()

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        # Obsługa Echo Reply i obliczanie t_control
        datapath = ev.msg.datapath
        dpid = datapath.id
        time_sent = self.echo_sent_time.get(dpid)
        if time_sent:
            rtt = timestamp_ms() - time_sent
            t_control = rtt / 2  # Zakładamy symetryczne opóźnienie
            self.t_control[dpid] = t_control
            self.logger.debug("Measured t_control for switch %s: %.3f ms", dpid, t_control)
        else:
            self.logger.warning("Received Echo Reply from %s without matching Echo Request", dpid)