import os
import psutil
import pyshark  
import pkgGlobal as gv


class PacketParser(object):
    def __init__(self, debugFlg=False):
        self.packetInfoLines = None
        self.debugMD = debugFlg

    def loadCapFile(self, filePath):
        if os.path.exists("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap"):
            capture = pyshark.FileCapture("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap")
            self.packetInfoLines = [str(cap).split('\n') for cap in capture]
            if self.debugMD: print(str(self.packetInfoLines))
            return True
        print(">> Error: loadCapFile() file %s not found." % str("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap"))
        return False

    
    def loadNetLive(self, interfaceName, packetCount = 10):
        addrs = psutil.net_if_addrs()
        if interfaceName in addrs.keys() and interfaceName in gv.gInterfaceDict.keys():
            capture = pyshark.LiveCapture(interface = gv.gInterfaceDict[interfaceName])
            self.packetInfoLines = []
            for captureArr in capture.sniff_continuously(packet_count=packetCount):
                if self.debugMD: print("Captured live packets.")
                self.packetInfoLines += [str(cap).split('\n') for cap in captureArr]  
            print("Finished capture.")
            return True
        else:
            print(">> Error: The network interface  %s not found." % str(interfaceName))
            return False

    def getProtocalList(self):
        
        if (not self.packetInfoLines) or len(self.packetInfoLines) == 0:
            if self.debugMD: print("No packet data stored.")
            return None
        protocalList = []
        for packetInfo in self.packetInfoLines:
            layerList = []
            srcIP, distIP, protocalInfo = '', '', ''
            for line in packetInfo:
                line = line.strip()
                if len(line) > 0 and line[0] != '\t' and 'Layer' in line:
                    if line[-1] == ':': line = line[:-1]
                    layerList.append(line)
                if 'Protocol:' in line: protocalInfo = str(line.split(':')[1]).lstrip()
                if 'Source:' in line: srcIP = str(line.split(':')[1]).lstrip()
                if 'Destination:' in line: distIP = str(line.split(':')[1]).lstrip()
            packetInfo = {
                gv.SRC_TAG: srcIP,
                gv.DES_TAG: distIP,
                gv.PRO_TAG: protocalInfo,
                gv.LAY_TAG: layerList,
            }
            if self.debugMD: print(packetInfo)
            protocalList.append(packetInfo)
        return protocalList

    
    def exportInfo(self, filePath):
        
        with open(f"C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap", 'w') as fh:
            for packetInfo in self.packetInfoLines:
                for line in packetInfo:
                    fh.write(line)


class protcolRcdDict(object):
   
    def __init__(self, src, dist):
        self.src = src
        self.dist = dist
        self.pktCount = 0
        self.tcpCount = 0
        self.udpCount = 0
        self.encriptDict = {gv.NTE_TAG: 0} 

    
    def addRecord(self, dataDict):
        
        self.pktCount +=1
        if 'UDP' in dataDict[gv.PRO_TAG]: self.udpCount +=1
        if 'TCP' in dataDict[gv.PRO_TAG]: self.tcpCount +=1
        if len(dataDict[gv.LAY_TAG]) < 4:
            self.encriptDict[gv.NTE_TAG] +=1
        else:
            for element in dataDict[gv.LAY_TAG][3:]:
                if element in self.encriptDict.keys():
                    self.encriptDict[element] += 1
                else:
                    self.encriptDict[element] = 1

    
    def printData(self):
        print("src: %s" %str(self.src))
        print("dist: %s" %str(self.dist))
        print("pktCount: %s" %str(self.pktCount))
        print("tcpCount: %s" %str(self.tcpCount))
        print("udpCount: %s" %str(self.udpCount))
        print("encriptDict: %s" %str(self.encriptDict))

   
    def getSourceIPaddr(self):
        return self.src

    def getDistIPaddr(self):
        return self.dist

    def getTotolPktNum(self):
        return self.pktCount

    def getTcpPktNum(self):
        return self.tcpCount
    
    def getUdpPktNum(self):
        return self.udpCount

    def getEncriptDict(self):
        return self.encriptDict

def testCase(mode=0):
    parser = PacketParser(debugFlg=True)
    
    if mode == 0:
        if not parser.loadCapFile('capData/test_WGVPN.pcap'):
            print("Error: Could not load the pcap file.")
            return
        
    elif mode == 1:
        if not parser.loadNetLive('Wi-Fi'):
            print("Error: Could not capture live network traffic.")
            return

    proList = parser.getProtocalList()

    if not proList:
        print("No protocol data to process.")
        return

    proSumDict = {}
    for item in proList:
        keyVal = item[gv.SRC_TAG] + '-' + item[gv.DES_TAG]
        if keyVal not in proSumDict:
            proSumDict[keyVal] = protcolRcdDict(item[gv.SRC_TAG], item[gv.DES_TAG])
        proSumDict[keyVal].addRecord(item)

    for item in proSumDict.values():
        item.printData()

    parser.exportInfo('packetExample/wgInfo.txt')

if __name__ == '__main__':
    testCase()