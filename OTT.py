# -*- encoding:utf8 -*-
import socket,SocketServer
from traceback import format_exc
THREADCOUNT=10
PROCESSCOUNT=1
DEBUG=True

class OTTBase:
    def debug(self,*args):
        try:
            from inspect import stack
            from time import strftime
            from sys import stdout
            stdout.write(' '.join([strftime('%y%m%d %H:%M:%S'),' '.join([str(t) for t in args])]))
            stdout.write('\n')
            stdout.flush()
        except Exception:
            pass
    def PINgenerate(self):
        from random import choice
        LST=[str(t) for t in range(0,10)]
        LST.extend([chr(t) for t in range(65,91)])
        LST.extend([chr(t) for t in range(97,123)])
        result=[choice(LST) for i in range(choice(range(512,1024)))]
        return ''.join(result)
    def KEYgenerate(self,PIN=None):
        PINLEN=len(PIN)
        key=[PIN[PINLEN//i] for i in range(2,18)]
        self.AESKEY=''.join(key)
        return self.AESKEY
    def addpadding(self,string,blocksize=16):
        pad=blocksize-( len(string) % blocksize);
        string+=chr(pad)*pad
        return string
    def strippadding(self,string):
        pad=ord(string[-1])
        return string[:-pad]
    def AESen(self,string):
        from base64 import b64encode
        from Crypto.Cipher import AES
        return b64encode(AES.new(self.AESKEY, AES.MODE_CBC, self.AESKEY).encrypt(self.addpadding(string)))
    def AESde(self,encrypted_string):
        from base64 import b64decode
        from Crypto.Cipher import AES
        return self.strippadding(AES.new(self.AESKEY, AES.MODE_CBC, self.AESKEY).decrypt(b64decode(encrypted_string)))

class Client(OTTBase):
    def __init__(self):
        self.request=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.request.settimeout(300)
        self.request.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    
    def setting(self):
        from struct import Struct
        self.Head=Struct('!HII')
        self.Id=0
    
    def connect(self,server,port):
        self.setting()
        self.server=server
        self.port=port
        self.request.connect((self.server,self.port))
    def SendPacket(self,Fcode,Data):
        from struct import pack
        Packet=self.Head.pack(Fcode,self.Id,len(Data))
        Packet+=pack('!%ds'%(len(Data),),Data)
        self.request.sendall(Packet)
        return (Fcode,self.Id,len(Data),Data,)
    def ReceivePacket(self):
        from struct import Struct
        MAXBUFFSIZE=1024
        Packet=self.request.recv(self.Head.size)
        if not Packet:
            raise socket.error('request disconnected')
        Fcode,Id,DataLength=self.Head.unpack(Packet)
        Body=Struct('!%ds'%(DataLength,))
        Packet=''
        while DataLength>0:
            if DataLength<MAXBUFFSIZE:
                BUFFSIZE=DataLength+0
            else:
                BUFFSIZE=MAXBUFFSIZE+0
            receivepacket=self.request.recv(BUFFSIZE)
            if receivepacket:
                DataLength-=len(receivepacket)
                Packet+=receivepacket
            else:
                raise socket.error('request disconnected')
        Data=Body.unpack(Packet)[0]
        return Fcode,Id,Body.size,Data
    
class MyThreadingTCPServer(SocketServer.ThreadingTCPServer):
    def process_request(self, request, client_address):
        from threading import Thread
        """Start a new thread to process the request."""
        t = Thread(target = self.process_request_thread,
                             args = (request, client_address))
        t.setDaemon=True
        t.start()
    
    def serve_forever(self, poll_interval=0.5):
        global THREADCOUNT
        from threading import activeCount
        from select import select
        self.__is_shut_down = self._BaseServer__is_shut_down
        self.__shutdown_request = self._BaseServer__shutdown_request
        _eintr_retry=SocketServer._eintr_retry
        
        self.__is_shut_down.clear()
        try:
            while not self.__shutdown_request:
                if activeCount() >=THREADCOUNT+1:
                    time.sleep(5)
                    continue
                r, w, e = _eintr_retry(select, [self], [], [],
                                       poll_interval)
                if self in r:
                    self._handle_request_noblock()
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

class RequestHandler(OTTBase):
    disconnecctd_message='request disconnected'
    def setup(self):
        from struct import Struct
        #socket options
        self.request.settimeout(300)
        self.request.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.request.setsockopt(socket.SOL_TCP, socket.TCP_DEFER_ACCEPT,1)
        self.clientIP,self.clientPORT=self.client_address
        self.Head=Struct('!HII')
        self.Id=0
    def SendPacket(self,Fcode,Data):
        from struct import pack
        Packet=self.Head.pack(Fcode,self.Id,len(Data))
        Packet+=pack('!%ds'%(len(Data),),Data)
        self.request.sendall(Packet)
        return (Fcode,self.Id,len(Data),Data,)
    def ReceivePacket(self):
        from struct import Struct
        MAXBUFFSIZE=1024
        Packet=self.request.recv(self.Head.size)
        if not Packet:
            raise socket.error(self.disconnecctd_message)
        Fcode,Id,DataLength=self.Head.unpack(Packet)
        Body=Struct('!%ds'%(DataLength,))
        Packet=''
        while DataLength>0:
            if DataLength<MAXBUFFSIZE:
                BUFFSIZE=DataLength+0
            else:
                BUFFSIZE=MAXBUFFSIZE+0
            receivepacket=self.request.recv(BUFFSIZE)
            if receivepacket:
                DataLength-=len(receivepacket)
                Packet+=receivepacket
            else:
                raise socket.error(self.disconnecctd_message)
        Data=Body.unpack(Packet)[0]
        return Fcode,Id,Body.size,Data
    def __init__(self, request, client_address, server):
        self.request = request
        self.client_address = client_address
        self.server = server
        self.setup()
        self.debug(self.clientIP,self.clientPORT,'[D]','Client Connected')
        try:
            self.handle()
        except Exception as err:
            if str(err)==self.disconnecctd_message:
                pass
            else:
                self.debug(format_exc(err))
                #raise Exception(err)
        finally:
            self.finish()
    def handle(self):
        while True:
            self.Fcode,self.Id,self.RBodyLength,self.RBody=self.ReceivePacket()
            self.debug(self.clientIP,self.clientPORT,'[R]',[self.Fcode,self.Id,self.RBodyLength,self.RBody])
            self.Fcode,self.Id,self.SBodyLength,SBody=self.SendPacket(self.Fcode,self.RBody)
            self.debug(self.clientIP,self.clientPORT,'[S]',[self.Fcode,self.Id,self.SBodyLength,self.SBody])
    def finish(self):
        self.debug(self.clientIP,self.clientPORT,'[D]','Client Disconnected')

class Server:
    def __init__(self,SERVER='',PORT=54321):
        self.SERVER=SERVER
        self.PORT=PORT
    def runserver(self,RequestHandler):
        global PROCESSCOUNT
        self.RequestHandler=RequestHandler
        from struct import pack
        from multiprocessing import Process
        server = MyThreadingTCPServer((self.SERVER, self.PORT),self.RequestHandler)
        server.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, pack('ii', 1, 0))
        for i in range(1,PROCESSCOUNT+1):
            p=Process(target=server.serve_forever,args=(0.5,))
            p.start()

