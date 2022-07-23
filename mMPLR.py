import hashlib
import collections
try:
    from collections import abc
    collections.MutableMapping = abc.MutableMapping
except:
    pass

class mMPLR:

    def __init__(self):
        self.DeviceID = '1'
        self.DestinationID = '1'
        self.PAYLD_SIZE = '0'
        self.ServiceType = '1' #1 - Text;2 - Image; 3- Audio
        self.SequenceNo = '1'
        self.BatchSize = '1'
        self.Flag = '2' #0 - SYN;1 - SYN-ACK;2 - DATA;3 - BVACK;4 - FIN;5 - ACK
        self.Checksum = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~' #hashlib.md5(b'').digest()
        self.Payload = ''

        self.maxPayloadSize = 239

    def setDeviceID(self, deviceId):
        self.DeviceID = str(deviceId)

    def setDestinationID(self, deviceId):
        self.DestinationID = str(deviceId)
    
    def setPayloadSize(self, loadSize):
        self.PAYLD_SIZE = str(loadSize)

    def setServiceType(self, service): 
        if type(service) != str:
            self.ServiceType = str(service)
            return
        services = {"text":1, "image": 2, "audio": 3}
        self.ServiceType = str(services.get(service.lower()))
        
    def setSequenceNo(self, seqNo):
        self.SequenceNo = str(seqNo)

    def setBatchSize(self, batchSize):
        self.BatchSize = str(batchSize)    
    
    def setFlag(self, flag):
        if type(flag) != str:
            self.Flag = str(flag)
            return
        flags = {'SYN':0, 'SYN-ACK':1,'DATA':2,'BVACK':3,'FIN':4,'ACK':5}
        self.Flag = str(flags.get(flag.upper()))

    def genChecksum(self):
        header = bytes(self.DestinationID, 'ascii').ljust(32)[:32]\
        +bytes(self.DeviceID, 'ascii').ljust(32)[:32]\
        +bytes(self.ServiceType, 'ascii').zfill(8)\
        +bytes(self.SequenceNo, 'ascii').zfill(16)\
        +bytes(self.Flag, 'ascii').zfill(8)\
        +bytes(self.PAYLD_SIZE, 'ascii').zfill(8)\
        +bytes(self.BatchSize, 'ascii').zfill(8)
        self.Checksum = hashlib.md5(header).digest() 
        return self.Checksum, header

    def setPayload(self, payload: str):
        assert(len(payload) <= self.maxPayloadSize)
        self.setPayloadSize(len(payload))
        self.Payload = payload

    def genHeader(self):
        checksum, head = self.genChecksum()
        return head+checksum[:16]
    

    def genPacket(self, packetNo, payload):
        #self.setFlag()
        self.setPayload(payload=payload)
        self.setSequenceNo(seqNo=packetNo)
        packet = self.genHeader() + bytes(self.Payload, 'ascii')
        return packet

    def getPackets(self, data, dataType, destinationId):
        packets = []
    
        leng = len(data)
        self.setDestinationID(destinationId)
        self.setBatchSize(leng//self.maxPayloadSize+ (1 if leng%self.maxPayloadSize else 0))
        self.setServiceType(dataType)
        i = 0
        while i < (leng//self.maxPayloadSize):
            packets.append(self.genPacket(i, data[i*self.maxPayloadSize: min((i+1)*self.maxPayloadSize, leng)])) 
            i += 1   
        if leng%self.maxPayloadSize != 0:
            packets.append(self.genPacket(i, data[i*self.maxPayloadSize: ]))    

        return packets

    
    def parsePacket(self, rawpacket):
        assert len(rawpacket) >= 128
        rawheader = rawpacket[:16*8]
        header = {"DestinationUID":rawheader[:32].rstrip().decode('ascii'),
        "DeviceUID":rawheader[32:64].rstrip().decode('ascii'),
        "Service":rawheader[64:72].decode('ascii'),
        "SequenceNo":rawheader[72:88].decode('ascii'),
        "Flag":rawheader[88:96].decode('ascii'),
        "PayloadSize":rawheader[96:104].decode('ascii'),
        "BatchSize":rawheader[104:112].decode('ascii'),
        "Checksum":rawheader[112:] 
        }
        if header["Checksum"] != hashlib.md5(rawheader[:-16]).digest():
            print("Packet Corrupt.\nPacket ",header["SequenceNo"], " to be resent")
            return {"isCorrupt":True, "PacketNo":header["SequenceNo"]} 
        content = rawpacket[16*8:]
        return {"Header": header, "Content": content}

    def parsePackets(self, packets):
        content = b''
        BatchACK = []
        for pkt in packets:
            packet = self.parsePacket(pkt)
            #print(packet)
            if packet.get("isCorrupt", False):
                BatchACK.append(packet.get("PacketNo"))
                break
            content += packet.get("Content")
        if len(BatchACK): return print("Batch Partially Corrupt")
        return content.decode('ascii')


if __name__ == "__main__":
    mplr = mMPLR()
    packets = mplr.getPackets("cz3gm8ix0gr092bnzyijsdmau4e8ublxb4gz2jx85gqir8r3sj5ekdigk139g6jalbe0xl1hro9xlvq2sewa8iqo9e46ap2eyu0coojtpfi6tzzre94719c17id9hpvhkw6amcvtmfdf1m9811o71xyx1yb3p9hx8hwcbo7f7qawlupgkm8kttbxqcbj0z53wotey1v33utg0lcjkbug4vx0jvunyxxfhbw0vjqaq493yyw5vsym6xcmkwy2z21ob9xgutg51n86nc9onrw8sgwp1v79bvl3pqo99bnlpsyorb4w1sct1cphr96qc7l6qi9v0u7dgvqiaq9w5ei9t3pvxqjux1dqhx23ffgdo1ke2ub9x4dpr2ioslyr8p2fyvwm30kpun5mok8deld43wmihc3c0ldg8yb01eu4xzdoc6fsmxsqs2poqa87ghdvxfqt24licn9hiureey069n3xdfsr7no8d21z5ndy45k1p6ndhxed", 2, "1")
    print(mplr.parsePackets(packets=packets))
        