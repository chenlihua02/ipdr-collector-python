import socket
import struct
import binascii
import ctypes

addr = '127.0.0.1'
port = 4737

CONNECT                     = 0x05
CONNECT_RESPONSE            = 0x06
DISCONNECT                  = 0x07
FLOW_START                  = 0x01
FLOW_STOP                   = 0x03
SESSION_START               = 0x08
SESSION_STOP                = 0x09
KEEP_ALIVE                  = 0x40
TEMPLATE_DATA               = 0x10
MODIFY_TEMPLATE             = 0x1A
MODIFY_TEMPLATE_RESPONSE    = 0x1B
FINAL_TEMPLATE_DATA_ACK     = 0x13
START_NEGOTIATION           = 0x1D
START_NEGOTIATION_REJECT    = 0x1E
GET_SESSIONS                = 0x14
GET_SESSIONS_RESPONSE       = 0x15
GET_TEMPLATES               = 0x16
GET_TEMPLATES_RESPONSE      = 0x17
DATA                        = 0x20
DATA_ACK                    = 0x21
ERROR                       = 0x23


class MsgHeader:
    version = 2
    messageId = 0
    sessionId = 0
    messageFlags = 0
    messageLen = 0
    rawData = None
    hs = struct.Struct('!bbbbi')

    def __init__(self, rawData):
        header = self.hs.unpack_from(rawData, 0)
        self.version = header[0]
        self.messageId = header[1]
        self.sessionId = header[2]
        self.messageFlags = header[3]
        self.messageLen = header[4]
        self.rawData = rawData

    def Encode(self):
        print('encode')

    def Decode(self):
        print('decode')

    def Desc(self):
        print('desc: ', binascii.hexlify(self.rawData), ' type: ', self.messageId)

    def RspMsg(self):
        print('rsp')

    def getMsgType(self):
        return self.messageId

    def getMsgLen(self):
        return self.messageLen

    def getRawData(self):
        return self.rawData

class Connect(MsgHeader):
    def __init__(self, ipaddr, port, ka_interval, vendor):
        self.ipaddr = ipaddr
        self.port = port
        self.ka_interval = ka_interval
        self.vendor = vendor
        self.messageId = CONNECT
        self.messageLen = 26 + len(vendor)

    def Encode(self):
        s = struct.Struct('!bbbbiihiii4s')
        return s.pack(*(
            2, CONNECT, 0, 0, self.messageLen, #header
            self.ipaddr,
            self.port,
            2,
            self.ka_interval,
            len(self.vendor), self.vendor
        ))

    def Decode(self):
        print('not support')

    def Desc(self):
        print('CONNECT: ip %d, port %d' %(self.ipaddr, self.port))

    def RespMsg(self):
        return None

class ConnectRsp(MsgHeader):
    def __init__(self, rawData):
        self.rawData = rawData
        self.messageId = CONNECT_RESPONSE

    def Encode(self):
        print('not support')

    def Decode(self):
        hs = struct.Struct('!bbbbi')
        header = hs.unpack_from(self.rawData, 0)
        msg_type = header[1]

        print('recvd msg type: %d' %msg_type)

    def Desc(self):
        print('connect rsp')

    def RespMsg(self):
        return GetSessions()

class GetSessions(MsgHeader):
    def __init__(self):
        self.messageId = GET_SESSIONS
        self.messageLen = 10 #fixed length
    
    def Encode(self):
        s = struct.Struct('!bbbbih')
        return s.pack(*(
            2, GET_SESSIONS, 0, 0, self.messageLen,
            0
        ))

    def Decode(self):
        print('not support')

    def Desc(self):
        print('get session')

    def RespMsg(self):
        return None

def msgDecode(data):
    hs = struct.Struct('!bbbbi')
    header = hs.unpack_from(data, 0)
    msg_type = header[1]
    msg = None

    if msg_type == CONNECT_RESPONSE:
        msg = ConnectRsp(data)
    elif msg_type == GET_SESSIONS_RESPONSE:
        print('todo: get sessoin response')
    else:
        print('todo else %d' %msg_type)

    return msg


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((addr, port))

ipdr_conn = Connect(175900724, 12646, 20, 'IPDR')
print(ipdr_conn.Desc())
client.send(ipdr_conn.Encode())
data = client.recv(1024)
header = MsgHeader(data)

print(header.Desc())

msgDecode(data)

getSessions = GetSessions()
print(getSessions.Desc())
client.send(getSessions.Encode())
data = client.recv(1024)
header = MsgHeader(data)
print(header.Desc())
msgDecode(data)



client.close()

