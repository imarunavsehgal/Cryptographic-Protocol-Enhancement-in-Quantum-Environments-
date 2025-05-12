import os
import time
import threading
import asyncio
from fnmatch import fnmatch
import pyshark  # Added to dynamically fetch interfaces
import pkgGlobal as gv
import PacketParser as pp
import ProtocolChecker as pc

LOOP_T = 0.5

class DataMgr(object):
    
    def __init__(self) -> None:
        super().__init__()
        self.parser = pp.PacketParser()
        self.checker = pc.ProtocolChecker(gv.PRO_SCORE_REF)
        self.proList = {}
        self.proSumDict = {}
        self.soreRst = {}

    def calCommSumDict(self):
        self.proSumDict = {}
        for item in self.proList:
            keyVal = item[gv.SRC_TAG] + '-' + item[gv.DES_TAG]
            if not (keyVal in self.proSumDict.keys()):
                self.proSumDict[keyVal] = pp.protcolRcdDict(item[gv.SRC_TAG], item[gv.DES_TAG])
            self.proSumDict[keyVal].addRecord(item)

    def calQRScore(self):
        self.soreRst = {}
        for key, item in self.proSumDict.items():
            value = self.checker.matchScore(item.encriptDict)
            self.soreRst[key] = value

    def loadFile(self, filePath):
        typeCheck = fnmatch("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap", '*.cap') or fnmatch("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap", '*.pcap') or fnmatch("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap", '*.pcapng')
        if os.path.exists("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap") and typeCheck:
            self.parser.loadCapFile("C:\\Users\\Amolik Singh\\Desktop\\test_WGVPN.pcap")
            self.proList = self.parser.getProtocalList()
            return True
        print(">> Error: file not exist or file type not valid!")
        return False

    def loadNetLive(self, interfaceName, packetCount=10):
        self.parser.loadNetLive(interfaceName, packetCount=packetCount)
        self.proList = self.parser.getProtocalList()
        return True

    def getProtocalDict(self):
        return self.proSumDict

    def getScoreDict(self):
        return self.soreRst


class DataMgrPT(threading.Thread):
    
    def __init__(self, threadID, name, debugMD=False):
        threading.Thread.__init__(self)
        self.dataMgr = DataMgr()
        self.debugMD = debugMD
        self.fileNeedLoad = None        
        self.interfaceNeedLoad = None   
        self.interfacePacktNum = 30     
        self.updateFlag = False         
        self.terminate = False

    def checkUpdating(self):
        return self.updateFlag 

    def loadFile(self, filePath):
        self.fileNeedLoad = filePath
        self.interfaceNeedLoad = None
        self.updateFlag = True
        return True

    def loadNetLive(self, interfaceName=None, packetCount=50):
        # Automatically choose the correct interface if not provided
        if interfaceName is None:
            interfaceName = self.getCorrectInterface()
        
        if interfaceName:
            self.interfaceNeedLoad = interfaceName
            self.interfacePacktNum = packetCount
            self.fileNeedLoad = None
            self.updateFlag = True
            return True
        print(">> Error: No valid network interface available.")
        return False

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while not self.terminate:
            if self.updateFlag:
                if self.debugMD: 
                    print(">> Load the data : ")
                if self.fileNeedLoad:
                    print("From File %s" % str(self.fileNeedLoad))
                    self.dataMgr.loadFile(self.fileNeedLoad)
                    self.fileNeedLoad = None
                if self.interfaceNeedLoad:
                    print('From Network Interface: %s' % str(self.interfaceNeedLoad))
                    self.dataMgr.loadNetLive(self.interfaceNeedLoad, self.interfacePacktNum)
                    self.interfaceNeedLoad = None

                self.dataMgr.calCommSumDict()
                self.dataMgr.calQRScore()
                self.updateFlag = False
            time.sleep(LOOP_T)
        print("DataManagerPT thread stopped!")

    def getProtocalDict(self):
        if self.updateFlag: return None
        return self.dataMgr.getProtocalDict()

    def getScoreDict(self):
        if self.updateFlag: return None
        return self.dataMgr.getScoreDict()

    def stop(self):
        """ Stop the thread."""
        self.terminate = True

    def getCorrectInterface(self):
        """
        Method to fetch and choose the correct network interface for capturing.
        Automatically selects 'Wi-Fi' or lists available interfaces for user selection.
        """
        interfaces = pyshark.LiveCapture().interfaces
        print("Available Interfaces: ", interfaces)

        # Attempt to auto-select Wi-Fi interface
        for interface in interfaces:
            if 'Wi-Fi' in interface:
                print(f"Using Wi-Fi interface: {interface}")
                return interface

        print("No Wi-Fi interface found. Please choose a valid interface from the list above.")
        return None


def testCase(mode=0):
    if mode == 0:
        print("> Start test: Init datamanager")
        dataMgr = DataMgr()
        r1 = dataMgr.loadFile('FILE_NOT_EXIST!')
        pcapPath = os.path.join(gv.dirpath, "capData", "test_normal.pcapng")
        r2 = dataMgr.loadFile(pcapPath)
        result = 'Pass' if (not r1) and r2 else 'Fail'
        print(">> Test load file: %s" % result)

        dataMgr.calCommSumDict()
        print('>> Calculate the protocol summary: ')
        print(dataMgr.getProtocalDict())

        dataMgr.calQRScore()
        print('>> Calculate the quantum safe score: ')
        print(dataMgr.getScoreDict())
        dataMgr = None

        print("\n> Test parallel thread data manager.")

        dataMgrMT = DataMgrPT(1, 'Test MultiThread')
        dataMgrMT.start()
        pcapPath = os.path.join(gv.dirpath, "capData", "test_normal.pcapng")
        dataMgrMT.loadFile(pcapPath)

        while dataMgrMT.checkUpdating():
            time.sleep(0.5)
        
        print('>> Print the protocol summary: ')
        print(dataMgrMT.getProtocalDict())

        print('>> Print the quantum safe score: ')
        print(dataMgrMT.getScoreDict())

        dataMgrMT.stop()

    elif mode == 1:
        print("> Start test: Load from Wifi network interface")
        dataMgrMT = DataMgrPT(1, 'Test MultiThread')
        dataMgrMT.start()
        dataMgrMT.loadNetLive()  # Automatically selects Wi-Fi or lists available interfaces

        while dataMgrMT.checkUpdating():
            time.sleep(0.5)

        print('>> Print the protocol summary: ')
        print(dataMgrMT.getProtocalDict())

        print('>> Print the quantum safe score: ')
        print(dataMgrMT.getScoreDict())

        dataMgrMT.stop()

    else:
        print('>> Put your own test code here:')

if __name__ == '__main__':
    testCase(mode=1)
