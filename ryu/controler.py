# controler.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.app.wsgi import WSGIApplication, ControllerBase, Response, route
from ryu.lib import hub
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
import time
import json
import threading
from collections import deque

# --- API classes ---------------------------------------
class StatsAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsAPI, self).__init__(req, link, data, **config)
        self.stats_data = data

    @route('stats', '/v1/stats', methods=['GET'])
    def list_stats(self, req, **kwargs):
        body = json.dumps(self.stats_data)
        return Response(content_type='application/json', body=body)

class TopologyAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyAPI, self).__init__(req, link, data, **config)
        self.topology_data = data

    @route('topology', '/v1/topology', methods=['GET'])
    def list_topology(self, req, **kwargs):
        body = json.dumps(self.topology_data)
        return Response(content_type='application/json', body=body)

class GrafanaStatsAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GrafanaStatsAPI, self).__init__(req, link, data, **config)
        self.grafana_stats_data = data['grafana_stats_data']
        self.grafana_stats_lock = data['grafana_stats_lock']

    @route('grafanastats', '/v1/grafanastats', methods=['GET'])
    def list_grafana_stats(self, req, **kwargs):
        with self.grafana_stats_lock:
            data_list = list(self.grafana_stats_data)
        body = json.dumps(data_list)
        return Response(content_type='application/json', body=body)

class SecStatsAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SecStatsAPI, self).__init__(req, link, data, **config)
        self.sec_stats_data = data['sec_stats_data']
        self.sec_stats_lock = data['sec_stats_lock']

    @route('secstats', '/v1/secstats', methods=['GET'])
    def list_sec_stats(self, req, **kwargs):
        with self.sec_stats_lock:
            data_list = list(self.sec_stats_data)
        body = json.dumps(data_list)
        return Response(content_type='application/json', body=body)

# -------------------------------------------------------------------


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'switches': switches.Switches,
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']

        self.topology_data = {'nodes': [], 'edges': [], 'hosts': []}
        self.stats_data = {
            'port_stats': {},
            'link_stats': {},
            'flow_stats': {},
            'queue_stats': {},
            'delay_stats': {}
        }

        self.last_seen = {}

        self.grafana_stats_data = deque(maxlen=2000)
        self.grafana_stats_lock = threading.Lock()
        self.sec_stats_data = deque(maxlen=3000)
        self.sec_stats_lock = threading.Lock()
        self.prev_port_stats = {}
        self.port_rates = {}

        # Mapowanie adresów IP hostów i przełączników
        self.hosts_ip = {}     # MAC -> IP hosta
        self.switches_ip = {}  # DPID -> IP przełącznika

        # Rejestracja REST API
        wsgi.register(TopologyAPI, {'topology_data': self.topology_data})
        wsgi.register(StatsAPI, {'stats_data': self.stats_data})
        wsgi.register(GrafanaStatsAPI, {
            'grafana_stats_data': self.grafana_stats_data,
            'grafana_stats_lock': self.grafana_stats_lock
        })
        wsgi.register(SecStatsAPI, {
            'sec_stats_data': self.sec_stats_data,
            'sec_stats_lock': self.sec_stats_lock
        })

        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    def update_delay_data(self, data_point):
        with self.grafana_stats_lock:
            self.grafana_stats_data.append(data_point)
            connection = data_point['connection']
            delay_ms = data_point['delay_ms']
            self.stats_data['delay_stats'][connection] = delay_ms

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        # --- Instalujemy podstawowe reguły (table-miss i ARP->controller). ---

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        # ARP->kontroler
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=10,
                      match=match_arp,
                      actions=actions_arp,
                      idle_timeout=0)

        # Zapamiętujemy datapath
        self.datapaths[datapath.id] = datapath
        # Adres IP przełącznika
        address = datapath.address  # (ip, port)
        self.switches_ip[datapath.id] = address[0]

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventSwitchLeave)
    def get_switches(self, ev):
        
        # --- Aktualizacja listy switchy w self.topology_data. ---
        
        switch_list = get_switch(self)
        self.topology_data['nodes'] = []
        for sw in switch_list:
            dpid = sw.dp.id
            ip = self.switches_ip.get(dpid, None)
            node_info = {
                'id': dpid,
                'ip': ip
            }
            self.topology_data['nodes'].append(node_info)

    @set_ev_cls(event.EventLinkAdd)
    @set_ev_cls(event.EventLinkDelete)
    def get_links(self, ev):
        
        # --- Aktualizacja listy połączeń (linków) między switchami. ---
        
        link_list = get_link(self)
        self.links = link_list
        self.topology_data['edges'] = [
            {
                'source': link.src.dpid,
                'target': link.dst.dpid,
                'src_port': link.src.port_no,
                'dst_port': link.dst.port_no
            }
            for link in link_list
        ]

    @set_ev_cls(event.EventHostAdd)
    @set_ev_cls(event.EventHostDelete)
    def get_hosts(self, ev):
        
        # --- Aktualizacja listy hostów w self.topology_data. ---
        # ---Jeśli Ryu straci host (EventHostDelete) albo host nie jest widoczny ---
        # ---w get_host(self), nie pojawi się on w 'hosts_list'. ---
        
        hosts_list = get_host(self)

        # --- Usuwamy z self.hosts_ip MAC-i, których nie ma w bieżącej liście ---
        current_macs = {h.mac for h in hosts_list}
        for known_mac in list(self.hosts_ip.keys()):
            if known_mac not in current_macs:
                del self.hosts_ip[known_mac]

        # --- Budujemy od nowa listę hostów w topologii ---
        self.topology_data['hosts'] = []

        for host in hosts_list:
            mac = host.mac
            ip = self.hosts_ip.get(mac, None)  # IP z naszego słownika (jeśli znamy)
            host_info = {
                'mac': mac,
                'port': host.port.port_no,
                'dpid': host.port.dpid,
                'ip': ip
            }
            self.topology_data['hosts'].append(host_info)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        
        # --- Obsługa pakietów wpadających do kontrolera (ARP/IPv4). ---
        # --- Po wykryciu (ARP lub IP) instalujemy przepływy do hosta z timeoutem. ---
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return  # ignorujemy LLDP
        

        # ------------------------------
        # 1) Obsługa ARP
        # ------------------------------
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_mac = eth.src
            src_ip = arp_pkt.src_ip
            self.hosts_ip[src_mac] = src_ip
            self.logger.info("ARP: %s -> %s (dpid=%s, port=%s)",
                             src_mac, src_ip, datapath.id, in_port)

            match = parser.OFPMatch(
                eth_type=0x0800,   # IPv4
                ipv4_dst=src_ip
            )
            actions = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, priority=20, match=match, actions=actions,
                          idle_timeout=600)

            return  

        # ------------------------------
        # 2) Obsługa IPv4
        # ------------------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_mac = eth.src
            src_ip = ip_pkt.src
            self.hosts_ip[src_mac] = src_ip
            self.logger.info("IPv4: %s -> %s (dpid=%s, port=%s)",
                             src_mac, src_ip, datapath.id, in_port)

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=src_ip
            )
            actions = [parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, priority=20, match=match, actions=actions,
                          idle_timeout=600)

    # ----------------------------------------------------------------
    #  Poniżej: metody monitorujące statystyki 
    # ----------------------------------------------------------------

    def _monitor(self):
        while True:
            self.get_port_stats()
            self.get_link_stats()
            self.get_flow_stats()
            self.get_queue_stats()
            self.send_echo_request()
            hub.sleep(10)
            self.flatten_stats_data()

    def send_echo_request(self):
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            req = parser.OFPEchoRequest(dp, data=b'')
            dp.send_msg(req)

    def get_queue_stats(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            queue_id = ofproto.OFPQ_ALL
            req = parser.OFPQueueStatsRequest(dp, 0, ofproto.OFPP_ANY, queue_id)
            dp.send_msg(req)
            if 'queue_stats' not in self.stats_data:
                self.stats_data['queue_stats'] = {}
            self.stats_data['queue_stats'][dp.id] = {}

    def get_port_stats(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            req = parser.OFPPortStatsRequest(dp, 0)
            dp.send_msg(req)
            self.stats_data['port_stats'][dp.id] = {}

    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats_data['queue_stats'][dpid] = []
        for stat in body:
            queue_stat = {
                'queue_id': stat.queue_id,
                'port_no': stat.port_no,
                'tx_bytes': stat.tx_bytes,
                'tx_packets': stat.tx_packets,
                'tx_errors': stat.tx_errors,
            }
            self.stats_data['queue_stats'][dpid].append(queue_stat)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        current_timestamp = time.time()

        if dpid not in self.prev_port_stats:
            self.prev_port_stats[dpid] = {}
        if dpid not in self.port_rates:
            self.port_rates[dpid] = {}

        for stat in body:
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                rx_packets = stat.rx_packets
                tx_packets = stat.tx_packets
                rx_bytes = stat.rx_bytes
                tx_bytes = stat.tx_bytes

                self.stats_data['port_stats'][dpid][port_no] = {
                    'rx_packets': rx_packets,
                    'tx_packets': tx_packets,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes
                }

                prev_entry = self.prev_port_stats[dpid].get(port_no)
                if prev_entry is not None:
                    prev_timestamp = prev_entry['timestamp']
                    time_diff = current_timestamp - prev_timestamp
                    if time_diff > 0:
                        delta_rx_packets = rx_packets - prev_entry['rx_packets']
                        delta_tx_packets = tx_packets - prev_entry['tx_packets']
                        delta_rx_bytes = rx_bytes - prev_entry['rx_bytes']
                        delta_tx_bytes = tx_bytes - prev_entry['tx_bytes']

                        rx_packets_per_sec = delta_rx_packets / time_diff
                        tx_packets_per_sec = delta_tx_packets / time_diff
                        rx_bytes_per_sec = delta_rx_bytes / time_diff
                        tx_bytes_per_sec = delta_tx_bytes / time_diff

                        dpidportcombo = f"DPID: {dpid} - Port: {port_no}"
                        self.port_rates[dpid][port_no] = {
                            'rx_packets_per_sec': rx_packets_per_sec,
                            'tx_packets_per_sec': tx_packets_per_sec,
                            'rx_bytes_per_sec': rx_bytes_per_sec,
                            'tx_bytes_per_sec': tx_bytes_per_sec
                        }

                        data_point = {
                            'timestamp': int(current_timestamp),
                            'dpid': dpid,
                            'port_no': port_no,
                            'dpid_port_no': dpidportcombo,
                            'rx_packets_per_sec': rx_packets_per_sec,
                            'tx_packets_per_sec': tx_packets_per_sec,
                            'rx_bytes_per_sec': rx_bytes_per_sec,
                            'tx_bytes_per_sec': tx_bytes_per_sec
                        }
                        with self.sec_stats_lock:
                            self.sec_stats_data.append(data_point)

                self.prev_port_stats[dpid][port_no] = {
                    'timestamp': current_timestamp,
                    'rx_packets': rx_packets,
                    'tx_packets': tx_packets,
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes
                }

    def get_flow_stats(self):
        for dp in self.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            req = parser.OFPFlowStatsRequest(dp)
            dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats_data['flow_stats'][dpid] = []
        ethertypes = set()

        for stat in body:
            match = stat.match
            flow_stat = {
                'priority': stat.priority,
                'cookie': stat.cookie,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'duration_nsec': stat.duration_nsec,
                'idle_timeout': stat.idle_timeout,
                'hard_timeout': stat.hard_timeout,
                'table_id': stat.table_id,
                'flags': stat.flags,
                'match_fields': self._parse_match(match),
                'actions': self._parse_actions(stat.instructions),
            }
            self.stats_data['flow_stats'][dpid].append(flow_stat)

            match_fields = flow_stat['match_fields']
            if 'eth_type' in match_fields:
                ethertypes.add(match_fields['eth_type'])

        num_flows = len(self.stats_data['flow_stats'][dpid])
        if 'flow_counts' not in self.stats_data:
            self.stats_data['flow_counts'] = {}

        self.stats_data['flow_counts'][dpid] = {
            'num_flows': num_flows,
            'ethertypes': list(ethertypes)
        }

    def _parse_match(self, match):
        match_dict = {}
        for field, value in match.items():
            if field == 'in_port':
                match_dict['in_port'] = value
            elif field == 'eth_type':
                match_dict['eth_type'] = hex(value)
            elif field == 'vlan_vid':
                match_dict['vlan_id'] = value & 0x0FFF
            elif field == 'eth_src':
                match_dict['eth_src'] = value
            elif field == 'eth_dst':
                match_dict['eth_dst'] = value
            elif field == 'ipv4_src':
                match_dict['ipv4_src'] = value
            elif field == 'ipv4_dst':
                match_dict['ipv4_dst'] = value
            elif field == 'ip_proto':
                match_dict['ip_proto'] = value
            elif field == 'tcp_src':
                match_dict['tcp_src'] = value
            elif field == 'udp_src':
                match_dict['udp_src'] = value
            elif field == 'tcp_dst':
                match_dict['tcp_dst'] = value
            elif field == 'udp_dst':
                match_dict['udp_dst'] = value
            elif field == 'ipv6_src':
                match_dict['ipv6_src'] = value
            elif field == 'ipv6_dst':
                match_dict['ipv6_dst'] = value
            else:
                self.logger.debug("Nieznane pole dopasowania: %s = %s", field, value)
        return match_dict

    def _parse_actions(self, instructions):
        actions = []
        for inst in instructions:
            if isinstance(inst, ofproto_v1_3_parser.OFPInstructionActions):
                if inst.type == ofproto_v1_3.OFPIT_APPLY_ACTIONS:
                    for action in inst.actions:
                        action_dict = {}
                        if isinstance(action, ofproto_v1_3_parser.OFPActionOutput):
                            action_dict['type'] = 'OUTPUT'
                            action_dict['port'] = action.port
                        elif isinstance(action, ofproto_v1_3_parser.OFPActionSetField):
                            field = action.key
                            value = action.value
                            action_dict['type'] = 'SET_FIELD'
                            action_dict['field'] = field
                            action_dict['value'] = value
                            if field == 'vlan_vid':
                                action_dict['type'] = 'SET_VLAN_VID'
                                action_dict['vlan_vid'] = value & 0x0FFF
                            elif field == 'eth_src':
                                action_dict['type'] = 'SET_DL_SRC'
                                action_dict['dl_src'] = value
                            elif field == 'eth_dst':
                                action_dict['type'] = 'SET_DL_DST'
                                action_dict['dl_dst'] = value
                            elif field == 'ipv4_src':
                                action_dict['type'] = 'SET_NW_SRC'
                                action_dict['nw_src'] = value
                            elif field == 'ipv4_dst':
                                action_dict['type'] = 'SET_NW_DST'
                                action_dict['nw_dst'] = value
                        elif isinstance(action, ofproto_v1_3_parser.OFPActionPushVlan):
                            action_dict['type'] = 'PUSH_VLAN'
                            action_dict['ethertype'] = action.ethertype
                        elif isinstance(action, ofproto_v1_3_parser.OFPActionPopVlan):
                            action_dict['type'] = 'POP_VLAN'
                        elif isinstance(action, ofproto_v1_3_parser.OFPActionSetQueue):
                            action_dict['type'] = 'SET_QUEUE'
                            action_dict['queue_id'] = action.queue_id
                        elif isinstance(action, ofproto_v1_3_parser.OFPActionGroup):
                            action_dict['type'] = 'GROUP'
                            action_dict['group_id'] = action.group_id
                        else:
                            action_dict['type'] = 'UNKNOWN'
                            action_dict['raw_type'] = str(action)
                            self.logger.debug("Nieobsługiwany typ akcji: %s", action)
                        actions.append(action_dict)
            else:
                # Inne instrukcje jeśli sie pojawią
                pass
        return actions

    def get_link_stats(self):
        link_stats = {}
        for link in get_link(self):
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port_no = link.src.port_no
            dst_port_no = link.dst.port_no

            retries = 5
            while retries > 0:
                src_port_stats = self.stats_data['port_stats'].get(src_dpid, {}).get(src_port_no)
                dst_port_stats = self.stats_data['port_stats'].get(dst_dpid, {}).get(dst_port_no)
                if src_port_stats and dst_port_stats:
                    break
                time.sleep(0.5)
                retries -= 1

            if src_port_stats and dst_port_stats:
                link_key = f"{src_dpid}:{src_port_no}-{dst_dpid}:{dst_port_no}"
                link_stats[link_key] = {
                    'src_dpid': src_dpid,
                    'src_port_no': src_port_no,
                    'dst_dpid': dst_dpid,
                    'dst_port_no': dst_port_no,
                    'rx_packets': src_port_stats['rx_packets'],
                    'tx_packets': src_port_stats['tx_packets'],
                    'rx_bytes': src_port_stats['rx_bytes'],
                    'tx_bytes': src_port_stats['tx_bytes'],
                    'dst_rx_packets': dst_port_stats['rx_packets'],
                    'dst_tx_packets': dst_port_stats['tx_packets'],
                    'dst_rx_bytes': dst_port_stats['rx_bytes'],
                    'dst_tx_bytes': dst_port_stats['tx_bytes'],
                }
        self.stats_data['link_stats'] = link_stats

    def flatten_stats_data(self):
        timestamp = int(time.time())
        data_points = []

        # Flatten port stats
        for dpid, ports in self.stats_data.get('port_stats', {}).items():
            for port_no, stats in ports.items():
                dpidportcombo = f"DPID: {dpid} - Port: {port_no}"
                data_point = {
                    'timestamp': timestamp,
                    'dpid': dpid,
                    'port_no': port_no,
                    'dpid_port_no': dpidportcombo,
                    'rx_packets': stats['rx_packets'],
                    'tx_packets': stats['tx_packets'],
                    'rx_bytes': stats['rx_bytes'],
                    'tx_bytes': stats['tx_bytes']
                }
                data_points.append(data_point)

        # Flatten link stats
        for link_key, stats in self.stats_data.get('link_stats', {}).items():
            data_point = {
                'timestamp': timestamp,
                'link_key': link_key,
                'src_dpid': stats['src_dpid'],
                'dst_dpid': stats['dst_dpid'],
                'rx_packets': stats['rx_packets'],
                'tx_packets': stats['tx_packets'],
                'rx_bytes': stats['rx_bytes'],
                'tx_bytes': stats['tx_bytes'],
                'dst_rx_packets': stats['dst_rx_packets'],
                'dst_tx_packets': stats['dst_tx_packets'],
                'dst_rx_bytes': stats['dst_rx_bytes'],
                'dst_tx_bytes': stats['dst_tx_bytes']
            }
            data_points.append(data_point)

        # Zapis do grafana_stats_data 
        with self.grafana_stats_lock:
            self.grafana_stats_data.extend(data_points)
