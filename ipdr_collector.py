import socket
import struct
import binascii
import ctypes
import threading
import time
import random
import sys

'''
Exporter
'''
addr = '192.168.0.1'
port = 4737
passive_mode = False
initiator_addr = '127.0.0.1'
ka_interval = 20 #interval for collector expected to receive KA from exporter
vendor = 'IPDR Python Client'


'''
IPDR Message Type
'''
CONNECT                     = 0x05
CONNECT_RESPONSE            = 0x06
DISCONNECT                  = 0x07
FLOW_START                  = 0x01
FLOW_STOP                   = 0x03
SESSION_START               = 0x08
SESSION_STOP                = 0x09
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
REQUEST                     = 0x30
RESPONSE                    = 0x31
KEEP_ALIVE                  = 0x40

'''
IPDR Error message type
'''
ERR_KEEPALIVE_EXPIRED             = 0
ERR_MSG_INVALID_FOR_CAPABILITIES  = 1
ERR_MSG_INVALID_FOR_STATE         = 2
ERR_MSG_DECODE_ERROR              = 3
ERR_MSG_PROCESS_TERMINATING       = 4

'''
XDR type
'''
# Basic type
XDR_INT        = 0x00000021
XDR_UINT       = 0x00000022
XDR_LONG       = 0x00000023
XDR_ULONG      = 0x00000024
XDR_FLOAT      = 0x00000025
XDR_DOUBLE     = 0x00000026
XDR_HEXBINARY  = 0x00000027
XDR_STRING     = 0x00000028
XDR_BOOLEAN    = 0x00000029
XDR_BYTE       = 0x0000002a
XDR_UBYTE      = 0x0000002b
XDR_SHORT      = 0x0000002c
XDR_USHORT     = 0x0000002d
# Derived Type
XDR_DATETIME      = 0x00000122
XDR_DATETIMEMSEC  = 0x00000224
XDR_IPV4ADDR      = 0x00000322
XDR_IPV6ADDR      = 0x00000427
XDR_IPADDR        = 0x00000827
XDR_UUID          = 0x00000527
XDR_DATETIMEUSEC  = 0x00000623
XDR_MACADDR       = 0x00000723

def XdrTypeLength(type, rawData):
    if type == XDR_INT or type == XDR_UINT or type == XDR_FLOAT or type == XDR_DATETIME or type == XDR_IPV4ADDR:
        return 4
    elif type == XDR_LONG or type == XDR_ULONG or type == XDR_FLOAT or type == XDR_DATETIMEUSEC or type == XDR_DATETIMEMSEC or type == XDR_MACADDR:
        return 8
    elif type == XDR_HEXBINARY or type == XDR_STRING or type == XDR_IPADDR:
        return struct.Struct('!i').unpack_from(rawData)[0] + 4
    elif type == XDR_BOOLEAN or type == XDR_BYTE or type == XDR_UBYTE:
        return 1
    elif type == XDR_SHORT or type == XDR_USHORT:
        return 2
    elif type == XDR_IPV6ADDR or type == XDR_UUID:
        return 20
    else:
        return 0

def XdrDecode(type, rawData):
    if type == XDR_SHORT:
        return str(struct.Struct('!h').unpack_from(rawData, 0)[0])
    elif type == XDR_USHORT:
        return str(struct.Struct('!H').unpack_from(rawData, 0)[0])
    elif type == XDR_INT:
        return str(struct.Struct('!i').unpack_from(rawData, 0)[0])
    elif type == XDR_UINT or type == XDR_DATETIME:
        return str(struct.Struct('!I').unpack_from(rawData, 0)[0])
    elif type == XDR_LONG or type == XDR_DATETIMEUSEC:
        return str(struct.Struct('!q').unpack_from(rawData, 0)[0])
    elif type == XDR_ULONG or type == XDR_DATETIMEMSEC:
        return str(struct.Struct('!Q').unpack_from(rawData, 0)[0])
    elif type == XDR_FLOAT:
        return str(struct.Struct('!f').unpack_from(rawData, 0)[0])
    elif type == XDR_DOUBLE:
        return str(struct.Struct('!d').unpack_from(rawData, 0)[0])
    elif type == XDR_HEXBINARY:
        return binascii.hexlify(rawData[4:])
    elif type == XDR_STRING:
        length = struct.Struct('!i').unpack_from(rawData, 0)[0]
        rawData = rawData[4:]
        return struct.Struct('!%ds'%length).unpack_from(rawData, 0)[0]
    elif type == XDR_IPV4ADDR:
        s = struct.Struct('!BBBB').unpack_from(rawData, 0)
        return '.'.join(str(i) for i in s)
    elif type == XDR_IPV6ADDR:
        s = struct.Struct('!HHHHHHHH').unpack_from(rawData, 4)
        return ':'.join(str(i) for i in s)
    elif type == XDR_IPADDR:
        length = struct.Struct('!i').unpack_from(rawData, 0)[0]
        rawData = rawData[4:]
        if length == 4:
            s = struct.Struct('!BBBB').unpack_from(rawData, 0)
            return '.'.join(str(i) for i in s)
        else:
            s = struct.Struct('!HHHHHHHH').unpack_from(rawData, 4)
            return ':'.join(str(i) for i in s)
    elif type == XDR_UUID:
        length = struct.Struct('!i').unpack_from(rawData, 0)[0]
        rawData = rawData[4:]
        s = struct.Struct('!HHHHHHHH').unpack_from(rawData, 4)
        return ('%02x%02x-%02x%02x-%02x%02x-%02x%02x'%(s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]))
    elif type == XDR_MACADDR:
        rawData = rawData[2:]
        s = struct.Struct('!BBBBBB').unpack_from(rawData, 0)
        return ('%02x%02x.%02x%02x.%02x%02x'%(s[0], s[1], s[2], s[3], s[4], s[5]))
    elif type == XDR_BOOLEAN:
        s = struct.Struct('!?').unpack_from(rawData, 0)
        if s[0] == 0:
            return 'false'
        else:
            return 'true'
    elif type == XDR_BYTE:
        return str(struct.Struct('!b').unpack_from(rawData, 0)[0])
    elif type == XDR_UBYTE:
        return str(struct.Struct('!B').unpack_from(rawData, 0)[0])
    else:
        return 'Unknown'


def InitiatorAddrToId(initiator_addr):
    strlist = initiator_addr.split('.')
    return ((int(strlist[0])<<24) + (int(strlist[1])<<16) + (int(strlist[2])<<8) + (int(strlist[3])))

def IdToInitiatorAddr(id):
    s = []
    for i in range(4):
        ip_part = str(id % 256)
        s.append(ip_part)
        id /= 256
    return '.'.join(s[::-1])

class MsgHeader:
    version = 2
    messageId = 0
    sessionId = 0
    messageFlags = 0
    messageLen = 0
    rawData = None
    hs = struct.Struct('!bbbbi')

    def __init__(self, rawData):
        if rawData is not None:
            header = self.hs.unpack_from(rawData, 0)
            self.version = header[0]
            self.messageId = header[1]
            self.sessionId = header[2]
            self.messageFlags = header[3]
            self.messageLen = header[4]
            self.rawData = rawData
        #self.sessionMgr = None

    def Encode(self):
        return

    def Decode(self, sessionMgr = None):
        return

    def Desc(self):
        return ('desc: %s, type %d' % (binascii.hexlify(self.rawData), self.messageId))

    def RespMsg(self):
        return None

    def getMsgType(self):
        return self.messageId

    def getMsgLen(self):
        return self.messageLen

    def getRawData(self):
        return self.rawData

class Connect(MsgHeader):
    def __init__(self, rawData, initiator = None, port = None, ka_interval = None, vendor = None):
        if rawData is not None:
            MsgHeader.__init__(self, rawData)
            s = struct.Struct('!iHiii').unpack_from(self.rawData, 8)
            self.initiator = IdToInitiatorAddr(s[0])
            self.port = s[1]
            self.capabilities = s[2]
            self.ka_interval = s[3]
            self.vendorIdLen = s[4]
            self.vendorId = struct.Struct('!%ds' %self.vendorIdLen).unpack_from(rawData, 26)[0]
        else:
            self.initiator = initiator
            self.port = port
            self.ka_interval = ka_interval
            self.vendor = vendor
            self.messageId = CONNECT
            self.messageLen = 26 + len(vendor)

    def Encode(self):
        s = struct.Struct('!bbbbiihiii%ds'%len(vendor))
        return s.pack(*(
            2, CONNECT, 0, 0, self.messageLen, #header
            InitiatorAddrToId(self.initiator),
            self.port,
            2,
            self.ka_interval,
            len(self.vendor), self.vendor
        ))

    def Desc(self):
        return ('CONNECT: initiator %s, port %u' %(self.initiator, self.port))

    def RespMsg(self):
        return [ConnectRsp(None, vendor), GetSessions()]


class ConnectRsp(MsgHeader):
    def __init__(self, rawData = None, vendor = None):
        MsgHeader.__init__(self, rawData)
        if rawData is not None:
            ss = struct.Struct('!iii').unpack_from(rawData, 8)
            self.capabilities = ss[0]
            self.keepAliveInterval = ss[1]
            self.vendorIdLen = ss[2]
            self.vendorId = struct.Struct('!%ds'%ss[2]).unpack_from(rawData, 20)[0]
        else:
            self.vendorIdLen = len(vendor)
            self.vendorId = vendor
            self.messageLen = 20 + len(vendor)

    def Encode(self):
        s = struct.Struct('!bbbbiiii%ds'%len(self.vendorId))
        return s.pack(*(
            2, CONNECT_RESPONSE, 0, 0, self.messageLen,
            2, ka_interval, self.vendorIdLen, self.vendorId))

    def Decode(self, sessionMgr):
        sessionMgr.SetKaSendInterval(self.keepAliveInterval)

    def Desc(self):
        return ('CONNECT_RESPONSE')

    def RespMsg(self):
        return [GetSessions()]

class GetSessions(MsgHeader):

    def __init__(self):
        self.messageId = GET_SESSIONS
        self.messageLen = 10
    
    def Encode(self):
        s = struct.Struct('!bbbbih')
        return s.pack(*(
            2, GET_SESSIONS, 0, 0, self.messageLen,
            0
        ))

    def Desc(self):
        return ('GET_SESSIONS')


class GetSessionsRsp(MsgHeader):
    def __init__(self, rawData):
        MsgHeader.__init__(self, rawData)
        self.requestId = struct.Struct('!h').unpack_from(rawData, 8)[0]
        self.sb_list = []
        msg_len = len(rawData)
        pos = 10
        sb_length = struct.Struct('!i').unpack_from(rawData, pos)[0]
        pos = pos + 4

        while True:
            if pos >= msg_len:
                break
            sessionId = struct.Struct('!b').unpack_from(rawData, pos)[0]
            pos = pos + 1
            reserved = struct.Struct('!b').unpack_from(rawData, pos)[0]
            pos = pos + 1
            sessionNameLen = struct.Struct('!i').unpack_from(rawData, pos)[0]
            pos = pos + 4
            sessionName = struct.Struct('!%ds'%sessionNameLen).unpack_from(rawData, pos)[0]
            pos = pos + sessionNameLen
            sessionDescLen = struct.Struct('!i').unpack_from(rawData, pos)[0]
            pos = pos + 4
            sessionDesc = struct.Struct('!%ds'%sessionDescLen).unpack_from(rawData, pos)[0]
            pos = pos + sessionDescLen
            ackTimeInterval = struct.Struct('!i').unpack_from(rawData, pos)[0]
            pos = pos + 4
            ackSequenceInterval = struct.Struct('!i').unpack_from(rawData, pos)[0]
            pos = pos + 4
            sb = (sessionId, reserved, sessionNameLen, sessionName, sessionDescLen,
                    sessionDesc, ackTimeInterval, ackSequenceInterval)
            self.sb_list.append(sb)

    def Decode(self, sessionMgr):
        for sb in self.sb_list:
            sessionMgr.AddSession(sb[0], sb[1], sb[7], sb[6])

    def Desc(self):
        return ('GET_SESSIONS_RESPONSE: ' + str(self.sb_list))

    def RespMsg(self):
        msg_list = []
        for sb in self.sb_list:
            flowStart = FlowStart(sb[0])
            msg_list.append(flowStart)
        return msg_list

class FlowStart(MsgHeader):

    def __init__(self, sessionId):
        self.sessionId = sessionId
        self.messageLen = 8

    def Encode(self):
        s = struct.Struct('!bbbbi')
        return s.pack(*(
                2, FLOW_START, self.sessionId, 0, self.messageLen
            ))

    def Desc(self):
        return ('FLOW_START, id %d' %self.sessionId)


class TemplateData(MsgHeader):
    def __init__(self, rawData):
        MsgHeader.__init__(self, rawData)
        self.templateList = []
        s = struct.Struct('!hb').unpack_from(rawData, 8)
        self.configId = s[0]
        self.flags = s[1]
        s = struct.Struct('!i').unpack_from(rawData, 11)
        block_len = s[0]
        pos = 15
        for i in range(block_len):
            s = struct.Struct('!hi').unpack_from(rawData, pos)
            templateId = s[0]
            schemaNameLen = s[1]
            pos = pos + 6
            s = struct.Struct('!%dsi' %schemaNameLen).unpack_from(rawData, pos)
            schemaName = s[0]
            typeNameLen = s[1]
            pos = pos + len(schemaName) + 4
            s = struct.Struct('!%dsi' %typeNameLen).unpack_from(rawData, pos)
            typeName = s[0]
            field_len = s[1]
            pos = pos + len(typeName) + 4
            t = Template(templateId, schemaName, typeName)
            self.templateList.append(t)

            for j in range(field_len):
                s = struct.Struct('!iii').unpack_from(rawData, pos)
                typeId = s[0]
                fieldId = s[1]
                fieldNameLen = s[2]
                pos = pos + 12
                s = struct.Struct('!%ds?' %fieldNameLen).unpack_from(rawData, pos)
                fieldName = s[0]
                isEnabled = s[1]
                pos = pos + len(fieldName) + 1
                f = Field(typeId, fieldId, fieldName, isEnabled)
                t.AddField(f)

    def Decode(self, sessionMgr):
        sessionMgr.UpdateSession(self.sessionId, self.templateList)

    def Desc(self):
        return ('TEMPLATE_DATA, id %d' %self.sessionId)

    def RespMsg(self):
        return [FinalTemplateDataAck(self.sessionId)]

#todo: class ModifyTemplate/ModifyTemplateRsp

class FinalTemplateDataAck(MsgHeader):
    def __init__(self, sessionId):
        self.sessionId = sessionId
        self.messageLen = 8

    def Encode(self):
        s = struct.Struct('!bbbbi')
        return s.pack(*(
                2, FINAL_TEMPLATE_DATA_ACK, self.sessionId, 0, self.messageLen
            ))

    def Desc(self):
        return ('FINAL_TEMPLATE_DATA_ACK, id %d' %self.sessionId)


class SessionStart(MsgHeader):
    def __init__(self, rawData):
        MsgHeader.__init__(self, rawData)
        ss = struct.Struct('!iqq?ii16s').unpack_from(rawData, 8)
        self.exporterBootTime = ss[0]
        self.firstRecordSeqNum = ss[1]
        self.droppedRecordCount = ss[2]
        self.primary = ss[3]
        self.ackTimeInterval = ss[4]
        self.ackSequenceInterval = ss[5]
        self.documentId = ss[6]

    def Decode(self, sessionMgr):
        sessionMgr.StartSession(self.sessionId, self.documentId, self.firstRecordSeqNum, self.ackSequenceInterval, self.ackTimeInterval)


    def Desc(self):
        return ('SESSION_START, id %d, ackTimeInterval: %d, ackSequenceInterval: %d'
         %(self.sessionId, self.ackTimeInterval, self.ackSequenceInterval))

class SessionStop(MsgHeader):
    def __init__(self, rawData):
        MsgHeader.__init__(self, rawData)
        ss = struct.Struct('!hi').unpack_from(rawData, 8)
        self.reasonCode = ss[0]
        self.reasonInfoLen = ss[1]
        self.reasonInfo = struct.Struct('!%ds'%self.reasonInfoLen).unpack_from(rawData, 14)[0]
        
    def Decode(self, sessionMgr):
        sessionMgr.StopSession(self.sessionId, self.reasonCode, self.reasonInfo)

    def Desc(self):
        return ('SESSION_STOP, id %d' %self.sessionId)

class Data(MsgHeader):
    def __init__(self, rawData):
        MsgHeader.__init__(self, rawData)
        #ss: (templateId, configId, flags, sequenceNum)
        ss = struct.Struct('!hhbq').unpack_from(rawData, 8)
        self.templateId = ss[0]
        self.configId = ss[1]
        self.flags = ss[2]
        self.seqNum = ss[3]
        self.ss = ss

    def Decode(self, sessionMgr):
        sessionMgr.ReceivedData(self.sessionId, self.ss, self.rawData[21:])

    def Desc(self):
        return ('DATA, id %d, template: %d, seqNum: %d' %(self.sessionId, self.templateId, self.seqNum))

class DataAck(MsgHeader):
    def __init__(self, configId, sessionId, lastSeq):
        self.messageId = DATA_ACK
        self.messageLen = 18
        self.configId = configId
        self.sessionId = sessionId
        self.seqNum = lastSeq

    def Encode(self):
        s = struct.Struct('!bbbbihq')
        return s.pack(*(
                2, DATA_ACK, self.sessionId, 0, self.messageLen, self.configId, self.seqNum
            ))

    def Desc(self):
        return ('DATA_ACK, id %d, lastSeq %d' %(self.sessionId, self.seqNum))

class KeepAlive(MsgHeader):
    def __init__(self, rawData = None):
        if rawData is not None:
            MsgHeader.__init__(self, rawData)

    def Encode(self):
        return struct.Struct('!bbbbi').pack(*(
            2, KEEP_ALIVE, 0, 0, 8
            ))

    def Desc(self):
        return ('KEEP_ALIVE')

class Error(MsgHeader):
    def __init__(self, rawData = None, errorCode = None, desc = None):
        self.errorCode = 255
        self.desc = ''
        if rawData is not None:
            MsgHeader.__init__(self, rawData)
            s = struct.Struct('!ihi').unpack_from(self.rawData, 8)
            self.timestamp = s[0]
            self.errorCode = s[1]
            self.desc_len = s[2]
            self.desc = struct.Struct('!%ds'%self.desc_len).unpack_from(self.rawData, 18)
        else:
            if errorCode is not None:
                self.errorCode = errorCode
            if desc is not None:
                self.desc = desc
        self.messageLen = 18 + len(self.desc)

    def Encode(self):
        timestamp = int(time.time())
        s = struct.Struct('!bbbbiihi%ds'%len(self.desc))
        return s.pack(*(
                2, ERROR, self.sessionId, 0, self.messageLen,
                timestamp, self.errorCode, len(self.desc), self.desc
            ))

    def Desc(self):
        return ('ERROR %d - %s' %(self.errorCode, self.desc))


class Decoder():

    def __init__(self, sessionMgr):
        self.sessionMgr = sessionMgr
        self.remain_data = ''
        self.remain_data_len = 0

    def Decode(self, data):
        self.remain_data += data
        self.remain_data_len = len(self.remain_data)

    def GetDecodedMsgList(self):

        msg_list = []
        hs = struct.Struct('!bbbbi')

        while True:
            header = hs.unpack_from(self.remain_data, 0)
            msg_type = header[1]
            msg_len = header[4]
            msg_data = self.remain_data[:msg_len]

            if msg_len > len(self.remain_data):
                break

            msg = None

            if msg_type == CONNECT:
                msg = Connect(msg_data)
            elif msg_type == CONNECT_RESPONSE:
                msg = ConnectRsp(msg_data)
            elif msg_type == GET_SESSIONS_RESPONSE:
                msg = GetSessionsRsp(msg_data)
            elif msg_type == TEMPLATE_DATA:
                msg = TemplateData(msg_data)
            elif msg_type == SESSION_START:
                msg = SessionStart(msg_data)
            elif msg_type == SESSION_STOP:
                msg = SessionStop(msg_data)
            elif msg_type == DATA:
                msg = Data(msg_data)
            elif msg_type == KEEP_ALIVE:
                msg = KeepAlive()
            elif msg_type == ERROR:
                msg = Error(msg_data)
            else:
                print('todo else %d' %msg_type)

            if msg is not None:
                print('%s rcvd: %s' %(time.strftime('[%Y-%m-%d %H:%M:%S] '), msg.Desc()))
                msg.Decode(self.sessionMgr)
                msg_list.append(msg)

            self.remain_data = self.remain_data[msg_len:]
            if len(self.remain_data) < 8:
                #remaining msg too short
                break

        return msg_list




class Field():
    def __init__(self, typeId, fieldId, fieldName, isEnabled):
        self.typeId = typeId
        self.fieldId = fieldId
        self.fieldName = fieldName
        self.isEnabled = isEnabled

    def __str__(self):
        return ('typeId: %d, fieldId: %d, fiendName %s, isEnabled: %d' %(self.typeId, self.fieldId, self.fieldName, self.isEnabled))


class Template():
    def __init__(self, templateId, schemaName, typeName):
        self.templateId = templateId
        self.schemaName = schemaName
        self.typeName = typeName
        self.fields = []
        self.fileName = ''
        self.file = None

    def AddField(self, f):
        self.fields.append(f)

    def AppendRecord(self, r):
        totalRecords = struct.Struct('!i').unpack_from(r)[0]
        r = r[4:]
        records = []
        for f in self.fields:
            length = XdrTypeLength(f.typeId, r)
            str = XdrDecode(f.typeId, r[:length])
            #print ('%s = %s' %(f.fieldName, str))
            records.append(str)
            if len(r) > length:
                r = r[length:]
            else:
                break

        if len(records) != 0:
            record_str = ','.join(records)
            self.file.write(record_str)
            self.file.write('\n')
            self.file.flush()

    def __str__(self):
        return ('id: %d, schemaName %s, typeName %s\r\nfields\r\n%s' %(self.templateId,self.schemaName,self.typeName,'\r\n'.join(str(f) for f in self.fields)))


class Session():
    def __init__(self, sessionId, sessionType, ackSequenceInterval, ackTimeInterval, connectionMgr):
        self.sessionId = sessionId
        self.type = sessionType
        self.ackSequenceInterval = ackSequenceInterval
        self.ackTimeInterval = ackTimeInterval
        self.configId = 0
        self.unackedNum = 0
        self.lastSeq = 0
        self.lastAcktTime = 0
        self.started = False
        self.connectionMgr = connectionMgr
        self.firstRecordSeqNum = 0
        self.reasonCode = 0
        self.reasonInfo = ''
        self.documentId = ''
        self.templateList = {}

    def SendAck(self):
        self.unackedNum = 0
        self.lastAcktTime = time.time()
        msg = DataAck(self.configId, self.sessionId, self.lastSeq)
        self.connectionMgr.SendMsg(msg)

    def CheckSequenceInterval(self):
        if self.unackedNum >= self.ackSequenceInterval:
            self.SendAck()

    def CheckAckTimeInterval(self):
        if self.started == False:
            return
        if self.unackedNum == 0:
            return

        if time.time() - self.lastAcktTime + 2 >= self.ackTimeInterval:
            self.SendAck()

    def CreateRecordFiles(self):
        for t in self.templateList.values():
            fileName = 'IPDR_RECORD_%s_%s_S%d_%s.csv'%(time.strftime('%Y%m%d%H%M%S'), self.documentId, self.sessionId, t.typeName)
            t.fileName = fileName
            t.file = open(fileName, 'w+')
            field_header = []
            for f in t.fields:
                field_header.append(f.fieldName)
            t.file.write('%s\n'%(','.join(field_header)))
            t.file.flush()


    def CloseRecordFiles(self):
        for t in self.templateList.values():
            t.file.close()


class SessionMgr(threading.Thread):
    def __init__(self):
        self.sessionList = {}
        self.lastKaSendTime = time.time()
        self.lastKaRcvdTime = time.time()
        self.connectionMgr = None
        self.ka_send_interval = 20

    def SetConnectionMgr(self, c):
        self.connectionMgr = c

    def AddSession(self, sessionId, sessionType, ackSequenceInterval, ackTimeInterval):
        s = Session(sessionId, sessionType, ackSequenceInterval, ackTimeInterval, self.connectionMgr)
        #del self.sessionList[sessionId]
        self.sessionList[sessionId] = s

    def StartSession(self, sessionId, documentId, firstRecordSeqNum, ackSequenceInterval, ackTimeInterval):
        s = self.sessionList[sessionId]
        s.started = True
        s.documentId = binascii.hexlify(documentId)
        s.firstRecordSeqNum = firstRecordSeqNum
        s.ackSequenceInterval = ackSequenceInterval
        s.ackTimeInterval = ackTimeInterval
        s.unackedNum = 0
        s.lastSeq = 0
        s.lastAcktTime = time.time()
        s.CreateRecordFiles()

    def StopSession(self, sessionId, reasonCode, reasonInfo):
        s = self.sessionList[sessionId]
        s.started = False
        s.reasonCode = reasonCode
        s.reasonInfo = reasonInfo
        s.CloseRecordFiles()

    # called when received TEMPLATE_DATA
    def UpdateSession(self, sessionId, templateList):
        s = self.sessionList[sessionId]
        for t in templateList:
            s.templateList[t.templateId] = t

    # called when received DATA.
    def ReceivedData(self, sessionId, ss, rawRecords):
        #ss: (templateId, configId, flags, sequenceNum)
        s = self.sessionList[sessionId]
        s.configId = ss[1]
        s.lastSeq = ss[3]
        s.unackedNum = s.unackedNum + 1
        s.CheckSequenceInterval()
        t = s.templateList[ss[0]]
        t.AppendRecord(rawRecords)


    def DeleteSession(self, sessionId):
        del self.sessionList[sessionId]

    def UpdateLastKASendTime(self):
        self.lastKaSendTime = time.time()

    def UpdateLastKaRcvdTime(self):
        self.lastKaRcvdTime = time.time()

    def SetKaSendInterval(self, ka_send_interval):
        self.ka_send_interval = ka_send_interval

    def checkTime(self):

        current_time = time.time()

        if (current_time - self.lastKaSendTime) + 2 >= self.ka_send_interval:
            self.connectionMgr.SendMsg(KeepAlive())


        if (current_time - self.lastKaRcvdTime) >= ka_interval + 2:
            self.connectionMgr.SendMsg(Error(None, ERR_KEEPALIVE_EXPIRED, 'ka timeout'))
            self.UpdateLastKaRcvdTime()

        for s in self.sessionList.values():
            s.CheckAckTimeInterval()

        t = threading.Timer(1, self.checkTime)
        t.start()

    def run(self):
        self.checkTime()


class ConnectionMgr(threading.Thread):
    def __init__(self, addr, port, passive = False):
        self.passive = passive
        self.client = None
        self.server = None
        try:
            if self.passive is False:
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((addr, port))
                print ('%s Setup TCP connection to %s:%d' %(time.strftime('[%Y-%m-%d %H:%M:%S] '), addr, port))
            else:
                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.bind((initiator_addr, port))
                self.server.listen(1)
                print ('%s Listen at %s:%d...' %(time.strftime('[%Y-%m-%d %H:%M:%S] '), initiator_addr, port))
        except Exception as err:
            print ('init connection error: %s %s %s' %(__file__, sys._getframe().f_lineno, err))

    def SetSessionMgr(self, s):
        self.sessionMgr = s

    def SendMsg(self, msg):
        if self.client is not None:
            self.sessionMgr.UpdateLastKASendTime()
            print('%s sent: %s' %(time.strftime('[%Y-%m-%d %H:%M:%S] '), msg.Desc()))
            self.client.send(msg.Encode())

    def Close(self):
        self.client.close()

    def run(self):
        decoder = Decoder(self.sessionMgr)

        if self.passive is False:
            client_port = random.randint(12600, 32700)
            connect = Connect(None, initiator_addr, client_port, ka_interval, vendor)
            self.SendMsg(connect)

            while True:
                data = self.client.recv(1024*1024)
                decoder.Decode(data)
                rcvd_msg_list = decoder.GetDecodedMsgList()
                if rcvd_msg_list is not None:
                    for rcvd_msg in rcvd_msg_list:
                        self.sessionMgr.UpdateLastKaRcvdTime()
                        resp_msg_list = rcvd_msg.RespMsg()
                        if resp_msg_list is not None:
                            for resp_msg in resp_msg_list:
                                self.SendMsg(resp_msg)

        else:
            while True:
                self.client, peer_addr = self.server.accept()
                print('%s TCP Client %s connected!' %(time.strftime('[%Y-%m-%d %H:%M:%S] '), peer_addr))
                while True:
                    data = self.client.recv(1024*1024)
                    if not data:
                        break
                    decoder.Decode(data)
                    rcvd_msg_list = decoder.GetDecodedMsgList()
                    if rcvd_msg_list is not None:
                        for rcvd_msg in rcvd_msg_list:
                            self.sessionMgr.UpdateLastKaRcvdTime()
                            resp_msg_list = rcvd_msg.RespMsg()
                            if resp_msg_list is not None:
                                for resp_msg in resp_msg_list:
                                    self.SendMsg(resp_msg)

if __name__ == '__main__':

    s = SessionMgr()
    c = ConnectionMgr(addr, port, passive_mode)
    s.SetConnectionMgr(c)
    c.SetSessionMgr(s)
    
    s.run()
    c.run()

