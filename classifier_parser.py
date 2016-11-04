'''
#######################################################################################################
#######################################################################################################
Arash Molavi Kakhki (arash@ccs.neu.edu)
Northeastern University

A library being called by other programs

the main function: beingCalled(Side, Num, Action, Prot, MList)

Side: 'Client' or 'Server'

Num: an int specifies which packet should be changed

Action: Delete : Delete the specified packet from the trace
        Random : Randomize the whole packet and store the randomized packet into /random/randomClient.pickle and randomServer.pickle
        Truncate : Change the packet to a packet with random MList[0] bytes
        Move : Move the bytes between MList[0][0] to MList[0][1]
        ReplaceW : Replace multiple region specified by the MList argument
        ReplaceR : Replace multiple region with random bytes(random pickles) specified by the MList argument

Prot: udp or tcp

MList: multiple usage list,
    When used in ReplaceW, it should be {(x,y):'something'...}, which would replace the payload from x to y byte to 'something'
    When used in ReplaceR, it should be {(x1,y1),(x2,y2)...}, which would replace the payload from x1 to y1 byte to
    the random payload from x1 to y1 byte(loaded from random pickle) and so on...

#######################################################################################################
#######################################################################################################
'''


import sys, os, pickle, copy, mimetools, StringIO, email, re, random, string
import ipaddress
import python_lib
from python_lib import *

DEBUG = 2

ipIgnoreList = ['17.0.0.0/8']   #Apple ip range --> see it a lot when recording on iPhone/iPad

def getUDPstreamsMap(pcap_file, client_ip):
    command = 'tshark -r ' + pcap_file + ' -2 -R "udp" -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport > tmp'
    os.system(command)
    streams = set()
    with open('tmp', 'r') as f:
        for l in f:
            l = l.strip().split()
            
            if len(l) != 4:
                continue
            
            if client_ip == l[0]:
                p1 = ':'.join(l[:2])
                p2 = ':'.join(l[2:])
            elif client_ip == l[2]:
                p1 = ':'.join(l[2:])
                p2 = ':'.join(l[:2])
            else:
                continue    
            streams.add(p1+','+p2)
    os.system('rm tmp')
    return streams

def createPacketMeta(pcapFile, outFile):
    command = ' '.join(['tshark -r', pcapFile, 
                        '-2 -R "not tcp.analysis.retransmission"',
                        '-T fields', 
                        '-e frame.number', '-e frame.protocols', '-e frame.time_relative', 
                        '-e tcp.stream'  , '-e udp.stream'     , 
                        '-e ip.src'      , '-e tcp.srcport'    , '-e udp.srcport'        , 
                        '-e ip.dst'      , '-e tcp.dstport'    , '-e udp.dstport'        ,
                        '-e tcp.len'     , '-e udp.length'     ,
                        '-e tcp.seq'     , '-e tcp.nxtseq'     , 
                        '> ', outFile])
    os.system(command)

def mapUDPstream2csp(packetMeta, clientIP):
    streams = {}
    with open(packetMeta, 'r') as f:
        for l in f:
            l = l.strip().split('\t')
            if 'ip:udp' not in l[1]:
                continue
            else:
                streamNo = l[4]
                srcIP    = l[5]
                srcPort  = l[7]
                dstIP    = l[8]
                dstPort  = l[10]
                if srcIP != clientIP:
                    continue
                else:
                    csp = convert_ip(srcIP+'.'+srcPort) + '.' + convert_ip(dstIP+'.'+dstPort)
                    if csp in streams:
                        assert(streams[csp] == streamNo)
                    else:
                        streams[csp] = streamNo
    return streams

def extractStreams(pcap_file, follow_folder, client_ip, protocol, UDPstreamsMap=None):
    '''
    For every TCP/UDP flow, it makes a separate text file with hex payloads.
    
    The "-2 -R not tcp.analysis.retransmission" seems NOT to work with 
    '''
    protocol = protocol.lower()
    
    noRetransmitPcap = pcap_file.rpartition('.')[0]+'_no_retransmits.pcap'
    command          = 'tshark -2 -R "not tcp.analysis.retransmission" -r {} -w {}'.format(pcap_file, noRetransmitPcap)
    os.system(command)
    
    if protocol == 'tcp':
        command = ("PCAP_FILE='" + pcap_file + "'\n" +
                   "PCAP_FILE_noRe='" + noRetransmitPcap + "'\n" +
                   "follow_folder='" + follow_folder + "'\n" +
                   "END=$(tshark -r $PCAP_FILE_noRe -T fields -e " + protocol + ".stream | sort -n | tail -1)\n" +
                   "echo '\tNumber of streams: '$END+1\n\n" +
                   "for ((i=0;i<=END;i++))\n" +
                   "do\n" +
                    "\techo '\tDoing TCP stream: '$i\n" +
                    "\ttshark -r $PCAP_FILE_noRe -qz follow," + protocol + ",raw,$i > $follow_folder/follow-stream-$i.txt\n" +
                   "done"
                  )
        os.system(command)
        
    elif protocol == 'udp':
        streams = getUDPstreamsMap(pcap_file, client_ip)
        for s in streams:
            csp = convert_ip(s.replace(':', '.').split(',')[0]) + '.' + convert_ip(s.replace(':', '.').split(',')[1])
            
            if isPrivate(csp[:15]) and isPrivate(csp[22:-6]):
                print '\t\tIS LOCAL!!! Skipping:', csp
                continue

            filename = UDPstreamsMap[csp]
            print '\tDoing UDP stream:', filename
            
            command = "tshark -r " + pcap_file + " -qz follow," + protocol + ",raw,"+ s + ' > ' + follow_folder + '/follow-stream-' + filename +'.txt'
            os.system(command)

def readPayload(streamFile):
    with open(streamFile, 'r') as f:
        for i in xrange(6):
            f.readline()
        
        l = f.readline()
        while l[0] != '=':
            if l[0] == '\t':
                yield ('s', l.strip())
            else:
                yield ('c', l.strip())
            l = f.readline()

def addUDPKeepAlives(udpClientQ):
    new_clientQ    = []
    prev_times     = {}
    prev_csp       = {}
    keepAliveCount = 0
    
    maxGap = 20
    step = maxGap/2
     
    for udp in udpClientQ:
         
        new_clientQ.append(udp)
         
        server_port = udp.c_s_pair[-5:]
         
        if server_port not in prev_times:
            prev_times[server_port] = udp.timestamp
            prev_csp[server_port]   = udp.c_s_pair
         
        else:
            diff = udp.timestamp - prev_times[server_port]
     
            if diff < maxGap:
                pass
     
            else:
                number = int(diff/step)
      
                for i in range(1, number+1):
                    new_udp = UDPset('', prev_times[server_port]+(i*step), prev_csp[server_port])
                    new_clientQ.append(new_udp)
                    keepAliveCount += 1
            
            prev_times[server_port] = udp.timestamp
            prev_csp[server_port]   = udp.c_s_pair
            
    new_clientQ.sort(key=lambda x: x.timestamp)
     
    # PRINT_ACTION('Number of keep-alive packets added: '+str(keepAliveCount), 1, action=False)
    
    return new_clientQ

def createHashLUT(clientQ, replay_name, numberOfHashed=5):
    LUT     = {}
    seenCSP = {}
            
    for udp in clientQ:
        
        if udp.c_s_pair not in seenCSP:
            seenCSP[udp.c_s_pair] = 0
            
        if seenCSP[udp.c_s_pair] < numberOfHashed:
            the_hash = hash(udp.payload.decode('hex'))
            
            if the_hash in LUT:
                print 'PLEASE INVESTIGATE MANUALLY: DUP!:', udp.c_s_pair

            LUT[the_hash] = (replay_name, udp.c_s_pair)
            seenCSP[udp.c_s_pair] += 1
        
        else:
            continue
    
    return LUT

def sortAndClean(tcpMetas):
    #Sorting
    for stream in tcpMetas:
        for talker in tcpMetas[stream]:
            tcpMetas[stream][talker].sort(key=lambda x: [x.seq, x.timestamp])
    
    #Tossing retransmissions
    new_tcpMetas = {}
    for stream in tcpMetas:
        new_tcpMetas[stream] = {'c':[], 's':[]}
        for talker in tcpMetas[stream]:
            for x in tcpMetas[stream][talker]:
                try:
                    lastOne = new_tcpMetas[stream][talker][-1]
                except IndexError:
                    new_tcpMetas[stream][talker].append(x)
                    continue
                if x.seq != lastOne.seq:
                    new_tcpMetas[stream][talker].append(x)
                elif x.seq == lastOne.seq:
                    '''
                    There are cases where retransmitted packet partially overlaps with previous packet.
                    This clause is to take care of that
                    ''' 
                    if x.NXseq == lastOne.NXseq:
                        continue
                    else:
                        new_x = copy.deepcopy(x)
                        new_x.length =  x.length - lastOne.length
                        new_tcpMetas[stream][talker].append(new_x)
    return new_tcpMetas

def random_ascii_by_size(size):
    return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(size))
    
def random_hex_by_size(size):
    '''
    Takes the size of the random hex string it should generate:
        1-Generates a random string (chars and numbers) of size/2
        2-Encodes the generated randon string into hex
        
    Note: one ascii char will have length of 2 when converted to hex
    '''
    assert( size % 2 == 0)
    size = size/2
    asciiPayload = random_ascii_by_size(size)
    return asciiPayload.encode('hex')

def random_hex_by_payload(hexPayload):
    '''
    Takes the size of the random hex string it should generate:
        1-Generates a random string (chars and numbers) of size/2
        2-Encodes the generated randon string into hex
        
    Note: one ascii char will have length of 2 when converted to hex
    '''
    if Configs().get('pureRandom'):
        return random_hex_by_size( len(hexPayload) )

    else:
        payload = hexPayload.decode('hex')
        
        if payload.startswith('GET'):
            req = Request( payload ).createRequestPacket()
            return req.encode('hex')
        
        elif payload.startswith('HTTP'):
            res = Response( payload ).createResponsePacket()
            return res.encode('hex')
        
        else:
            return random_hex_by_size( len(hexPayload) )
        
class Request(object):
    def __init__(self, stringData, splitter='\r\n'):
        (req, dummy, head)                        = stringData.partition(splitter)  
        (self.method, path_params, self.protocol) = req.split(' ')
        (self.path, dummy, params)                = path_params.partition('?')
        self.params                               = re.findall(r"(?P<name>.*?)=(?P<value>.*?)&"  , params+'&')        
        self.headers                              = re.findall(r"(?P<name>.*?): (?P<value>.*?){}".format(splitter), head+'\r\n')
        
    def createRequestPacket(self):
        serializedParams  = '&'.join([k[0] + '=' + random_ascii_by_size(len(k[1]))  for k in self.params])
        serializedHeaders = '\r\n'.join([k[0] + ': '+ random_ascii_by_size(len(k[1])) for k in self.headers])
        
        newRequest = (self.method + ' ' + 
                      random_ascii_by_size(len(self.path)) + 
                      '?' + serializedParams + ' ' + 
                      self.protocol + '\r\n' + 
                      serializedHeaders + '\r\n' + '\r\n')
         
        return newRequest
    
    def __str__(self):
        return str(self.headers)
    
class Response(object):
    def __init__(self, stringData, reqPath=None, splitter='\r\n'):
        self.reqPath               = reqPath
        (self.status, dummy, head) = stringData.partition(splitter)
        self.headers               = re.findall(r"(?P<name>.*?): (?P<value>.*?){}".format(splitter), head)
 
    def createResponsePacket(self):
        return "{}\r\n{}\r\n\r\n".format(self.status, '\r\n'.join([k[0]+': '+random_ascii_by_size(len(k[1])) for k in self.headers]))
    
    def __str__(self):
        return str(self.headers)

def tcpStream2Qs(streamMeta, streamHandle):
    '''
    Creates client and server queues from a tcp strams
    
    Flow diagram of this is in a Evernote note
    '''
    end     = True    
    
    clientQ = []
    serverQ = []
    
    packetReader = readNextPacket(streamMeta, streamHandle, randomPayload=Configs().get('randomPayload'))
    
    p = packetReader.next()
    
    #If the stream file is empty, the generator return the 
    #counter (which is a dict) at the very first .next() 
    if type(p) is dict: 
        end = False
    
    #The stream MUST start with a client request
    assert(p.talking == 'c')
    
    while end:
        
        reqList = [p]
        
        while end:
            pp      = p
            p       = packetReader.next()
            
            #If the stream file reaches the end, the  
            #generator return the counter (which is a dict) 
            if type(p) is dict: 
                end = False
                break
            
            if p.talking == 'c':
                clientQ.append( RequestSet(pp.payload, pp.csp, None, pp.timestamp) )
                reqList.append(p)
            else:
                break
        
        if not end:
            break 
        
        resTimeOrigin = p.timestamp
        resList       = [OneResponse(p.payload , 0)]
        pp = p
        
        while end:
            p = packetReader.next()
            if type(p) is dict: end = False; break
            
            if p.talking == 's':
                resList.append( OneResponse(p.payload , p.timestamp-resTimeOrigin) )
                pp = p
            else:
                tmpp = reqList[-1]
                serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), resList) )
                clientQ.append( RequestSet(tmpp.payload, tmpp.csp, ''.join([x.payload for x in resList]), tmpp.timestamp) )
                break
    
    if pp.talking == 's':
        tmpp = reqList[-1]
        clientQ.append( RequestSet(tmpp.payload, tmpp.csp, ''.join([x.payload for x in resList]), tmpp.timestamp) )
        serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), resList) )
    elif pp.talking == 'c':
        clientQ.append( RequestSet(pp.payload, pp.csp, None, pp.timestamp) )
        serverQ.append( ResponseSet(''.join([x.payload for x in reqList]), []) )
    
    '''
    Sometimes the order of packets mismatches the TCP stream.
    In these cases we need to adjust the times to avoid packets being
    send in the wrong order which results in tcp server/client halting 
    (because of length mismatch)
    '''
    for i in range(1, len(clientQ)):
        if clientQ[i].timestamp < clientQ[i-1].timestamp:
            clientQ[i].timestamp = clientQ[i-1].timestamp

    return clientQ, serverQ, pp.csp
    
def readNextPacket(streamMeta, streamHandle, randomPayload=False):
    counter = {'c':0, 's':0}
    
    while True:
        try:
            [talking, payload]  = streamHandle.next()
            p                   = streamMeta[talking][counter[talking]]
            
            if p.length != len(payload)/2:
                if '6279746573206d697373696e6720696e20636170747572652066696c655d' in payload:
                    continue
                else:
                    print '\nSomething is wrong!'
                    print '\nI am seeing payload in stream which is missing from packetMeta'
                    if DEBUG == 3: print p.timestamp, '\t', p.talking, '=', talking, '\t', p.protocol, '\t', p.stream, '\t', p.length, '=', len(payload)/2,'\t', payload
                    sys.exit(-1)
        except StopIteration:
            yield counter
            break
        
        counter[talking] += 1

        p.payload = payload
        
        if randomPayload is True:
#             p.payload = random_hex(len(p.payload))
            p.payload = random_hex_by_payload(p.payload)
        
        yield p
    
class singlePacket(object):
    def __init__(self, desString, clientIP):
        l              = desString.replace('\n', '').split('\t')
        self.timestamp = float(l[2])
        self.srcIP     = l[5]
        self.dstIP     = l[8]
        self.payload   = None
        self.talking   = None
        self.stream    = None
        
        if 'ip:tcp' in l[1]:
            self.protocol  = 'tcp'
        elif 'ip:udp' in l[1]:
            self.protocol  = 'udp'
        else:
            PRINT_ACTION('Skipping protocol: '+l[1], 1, action=False)
            return
                
        if self.protocol == 'tcp':
            self.stream  = l[3]
            self.srcPort = l[6]
            self.dstPort = l[9]
            self.length  = int(l[11])
            self.seq     = int(l[13])
            try:
                self.NXseq = int(l[14])
            except ValueError:
                self.NXseq = -1
                
        elif self.protocol == 'udp':
            self.stream  = l[4]
            self.srcPort = l[7]
            self.dstPort = l[10]
            self.length  = int(l[12])-8   #subtracting UDP header length
            
        if self.srcIP == clientIP:
            self.talking    = 'c'
            self.clientPort = self.srcPort.zfill(5)
            self.serverIP   = convert_ip(self.dstIP)
            self.serverPort = self.dstPort
            self.csp        = convert_ip(self.srcIP+'.'+str(self.srcPort)) + '-' + convert_ip(self.dstIP+'.'+str(self.dstPort))
        elif self.dstIP == clientIP:
            self.talking    = 's'
            self.clientPort = self.dstPort.zfill(5)
            self.serverIP   = convert_ip(self.srcIP)
            self.serverPort = self.srcPort
            self.csp        = convert_ip(self.dstIP+'.'+str(self.dstPort)) + '-' + convert_ip(self.srcIP+'.'+str(self.srcPort))

def isPrivate(ip):
    ip = convert_back_ip(ip)
    ip = unicode(ip)
    return ipaddress.ip_address(ip).is_private

def isInNetworks(ip, listOfNetworks):
    ip = convert_back_ip(ip)
    ip = unicode(ip)
    ip = ipaddress.ip_address(ip)
    
    for n in listOfNetworks:
        n = ipaddress.IPv4Network(unicode(n))
        if ip in n:
            return True
        
    return False

def isLocal(ip):
    '''
    DEPRECATED!!!
    
    use isPrivate() function instead
    '''
    ip = ip.split('.')

    if ip[0] in ['10', '010']:
        return True
    if ip[0] == '172' and 16<=int(ip[1])<=31:
        return True
    if ip[0]+'.'+ip[1] == '192.168':
        return True
    else:
        return False

def Truncate(payload, Tbyte):
    # Truncate the payload to Tbyte
    if len(payload.decode('hex')) < Tbyte:
        print '\n\t ***Attention*** Plen is',len(payload),' Tbyte is ',Tbyte, 'Returning original payload'
        return payload

    trunPayload = ''.join(chr(random.getrandbits(8)) for x in range(Tbyte))
    trunPayload = trunPayload.encode('hex')

    return trunPayload

# Would randomize the whole payload in this packet
def Randomize(payload):
    # randomize the whole payload except the bytes from L to R
    payload = payload.decode('hex')
    plen = len(payload)
    payload = ''.join(chr(random.getrandbits(8)) for x in range(plen))
    payload = payload.encode('hex')

    return payload

# def Randomize(payload, L, R):
#     # randomize the whole payload except the bytes from L to R
#     payload = payload.decode('hex')
#     plen = len(payload)
#     if R > plen or L < 0 :
#         print '\n\t\t ***Attention***Payload length is ',plen,'BUT L bond is ', L, 'R bond is',R,\
#             'Returning original payload'
#     else:
#         oriPart = payload[L : R]
#         LeftPad = ''.join(chr(random.getrandbits(8)) for x in range(L))
#         RightPad = ''.join(chr(random.getrandbits(8)) for x in range(plen-R))
#         payload = LeftPad + oriPart + RightPad
#
#     payload = payload.encode('hex')
#
#     return payload

def Move(payload, L, R):
    # Move the specified part of the payload to the end of the packet
    payload = payload.decode('hex')
    plen = len(payload)
    if R > plen or L < 0 :
        print '\n\t\t ***Attention***Payload length is ',plen,'BUT L bond is ', L, 'R bond is',R,\
            'Returning original payload'
    else:
        oriPart = payload[L : R]
        LeftPad = payload[: L]
        RightPad = payload[ R :]
        payload = LeftPad + RightPad + oriPart

    payload = payload.encode('hex')
    return payload

def MultiReplace(payload, regions, rpayload):
    # When randomPayload is '', that means we need to replace payload with the strings stores in regions
    # e.g. regions[(1,2):'haha']
    if rpayload == '':
        for region in regions:
            L = region[0]
            R = region[1]
            payload = Replace(payload, L, R, regions[region])
    else:
        for region in regions:
            L = region[0]
            R = region[1]
            payload = Replace(payload, L, R, rpayload[L:R])

    return payload


def Replace(payload, L, R, replaceS):
    # replace the bytes from L to R to replaceS
    payload = payload.decode('hex')
    plen = len(payload)
    if R > plen or L < 0 :
        print '\n\t\t ***Attention***Payload length is ',plen,'BUT L bond is ', L, 'R bond is',R,\
            'Returning original payload'
    else:
        LeftPad = payload[: L]
        RightPad = payload[R :]
        payload = LeftPad + replaceS + RightPad
    payload = payload.encode('hex')
    return payload

def to_list(chain, offset):
    return [chain[i:i+offset] for i in range(0, len(chain), offset)]

# Bit hex string operations
def bin2str(chain):
    return ''.join((chr(int(chain[i:i+8], 2)) for i in range(0, len(chain), 8)))

def bin2hex(chain):
    return ''.join((hex(int(chain[i:i+8], 2))[2:] for i in range(0, len(chain), 8)))

def str2bin(chain):
    return ''.join((bin(ord(c))[2:].zfill(8) for c in chain))

def str2hex(chain):
    return ''.join((hex(ord(c))[2:] for c in chain))

def hex2bin(chain):
    return ''.join((bin(int(chain[i:i+2], 16))[2:].zfill(8) for i in range(0, len(chain), 2)))

def hex2str(chain):
    return ''.join((chr(int(chain[i:i+2], 16)) for i in range(0, len(chain), 2)))

def XorPayload(payload):
    payload = payload.decode('hex')
    bpayload = str2bin(payload)
    newb = ''
    for char in bpayload:
        if char == '0':
            newb += '1'
        else:
            newb += '0'
    newpayload = bin2str(newb).encode('hex')
    return newpayload

# Dump the packets with xored payload into /random directory
def XorDump(configs, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts):
    if not os.path.isdir(configs.get('pcap_folder')+'/xor'):
        os.makedirs(configs.get('pcap_folder')+'/xor')

    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name)          ,
                open((configs.get('pcap_folder')+'/xor/xorClient.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replay_name),
                open((configs.get('pcap_folder')+'/xor/xorServer.pickle'), "w" ), 2)


def XorLoad(configs, side, PacketNum, Protocol, csp):
    # Client Side
    if side == 'Client':
        clientQ, udpClientPorts, tcpCSPs, replayName = \
            pickle.load(open(configs.get('pcap_folder')+'/xor/xorClient.pickle','r'))

        rpayload = clientQ[PacketNum-1].payload

    # Server Side
    else:
        serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
            pickle.load(open(configs.get('pcap_folder')+'/xor/xorServer.pickle','r'))

        if Protocol == 'udp':
            rpayload = serverQ[Protocol][csp][PacketNum-1].payload
        else:
            rpayload = serverQ[Protocol][csp][PacketNum-1].response_list[0].payload

    return rpayload


# Dump the packets with random payload into /random directory
def RandomDump(configs, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts):
    if not os.path.isdir(configs.get('pcap_folder')+'/random'):
        os.makedirs(configs.get('pcap_folder')+'/random')

    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name)          ,
                open((configs.get('pcap_folder')+'/random/randomClient.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replay_name),
                open((configs.get('pcap_folder')+'/random/randomServer.pickle'), "w" ), 2)

def RandomLoad(configs, side, PacketNum, Protocol, csp):
    # Client Side
    if side == 'Client':
        clientQ, udpClientPorts, tcpCSPs, replayName = \
            pickle.load(open(configs.get('pcap_folder')+'/random/randomClient.pickle','r'))

        rpayload = clientQ[PacketNum-1].payload

    # Server Side
    else:
        serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
            pickle.load(open(configs.get('pcap_folder')+'/random/randomServer.pickle','r'))

        if Protocol == 'udp':
            rpayload = serverQ[Protocol][csp][PacketNum-1].payload
        else:
            rpayload = serverQ[Protocol][csp][PacketNum-1].response_list[0].payload

    return rpayload

def run(directory, MSide = '', MPacketNum = 0, MAction = '', MProtocol = '', MList = [],
        RemainPackets = {'Client':[],'Server:':[]}):
    '''##########################################################'''

    # PRINT_ACTION('Reading configs and args', 0)
    configs = Configs()
    configs.set('pcap_folder', directory)
    configs.set('randomPayload', False)
    configs.set('pureRandom'   , False)

    
    try:
        onlyStreams = configs.get('onlyStreams').split(',')
    except KeyError:
        onlyStreams   = []      #if this list is NOT empty, ONLY streams in this list will be considered!
    streamSkippedList = []      #This will save all skipped streames to be used when parsing for random
    streamIgnoreList  = []      #example: streamIgnoreList = ['0', '1']
                                #if you need to skip a stream, add it to streamIgnoreList 
    
    '''##########################################################'''
    # PRINT_ACTION('Locating necessary files', 0)
    for file in os.listdir(configs.get('pcap_folder')):
        if file.endswith('.pcap'):
            if file.endswith('_no_retransmits.pcap'):
                continue
            pcap_file   = os.path.abspath(configs.get('pcap_folder')) + '/' + file
            replay_name = file.partition('.pcap')[0]
        if file == 'client_ip.txt':
            client_ip_file = os.path.abspath(configs.get('pcap_folder')) + '/' + file
    
    follow_folder_TCP = configs.get('pcap_folder') + '/' + os.path.basename(configs.get('pcap_folder')) + '_follows_TCP'
    follow_folder_UDP = configs.get('pcap_folder') + '/' + os.path.basename(configs.get('pcap_folder')) + '_follows_UDP'
    packetMeta        = os.path.abspath(configs.get('pcap_folder')) + '/' + 'packetMeta'

    if configs.is_given('replay_name'):
        replay_name = configs.get('replay_name')
    replay_name = replay_name.replace('_', '-')
    # PRINT_ACTION('Replay name: '+replay_name, 0)
    
    if not os.path.isfile(pcap_file):
        PRINT_ACTION('The folder is missing the pcap file! Exiting with error!', 1, action=False, exit=True)
    
    if not os.path.isfile(client_ip_file):
        PRINT_ACTION('The folder is missing the client_ip file! Exiting with error!', 1, action=False, exit=True)
    else:
        # PRINT_ACTION('Reading client_ip', 0)
        client_ip = read_client_ip(client_ip_file)
    
    '''##########################################################'''
    # PRINT_ACTION('Extracting payloads and streams', 0)
    
    if not os.path.isfile(packetMeta):
        # PRINT_ACTION('Creating packetMeta', 0)
        createPacketMeta(pcap_file, packetMeta)
    
    if not os.path.isdir(follow_folder_TCP):
        # PRINT_ACTION('TCP Follows folder does not exist. Creating the follows folder...', 0)
        os.makedirs(follow_folder_TCP)
        extractStreams(pcap_file, follow_folder_TCP, client_ip, 'TCP')
    
    if not os.path.isdir(follow_folder_UDP):
        # PRINT_ACTION('UDP Follows folder does not exist. Creating the follows folder...', 0)
        os.makedirs(follow_folder_UDP)
        UDPstreamsMap = mapUDPstream2csp(packetMeta, client_ip)
        extractStreams(pcap_file, follow_folder_UDP, client_ip, 'UDP', UDPstreamsMap=UDPstreamsMap)
    
    
    '''##########################################################'''
    handles = {'tcp':{}, 'udp':{}}
    for file in os.listdir(follow_folder_TCP):
        stream = file.rpartition('-')[2].partition('.')[0]
        handles['tcp'][stream] = readPayload(follow_folder_TCP+'/'+file)
    for file in os.listdir(follow_folder_UDP):
        stream = file.rpartition('-')[2].partition('.')[0]
        handles['udp'][stream] = readPayload(follow_folder_UDP+'/'+file)
    
    udpClientQ        = []
    serverQ           = {'tcp':{}, 'udp':{}}
    serversTimeOrigin = {'tcp':{}, 'udp':{}}
    LUT               = {'tcp':{}, 'udp':{}}
    startedStreams    = {'tcp':[], 'udp':[]}
    brokenStreams     = {'tcp':[], 'udp':[]}
    
    udpClientPorts    = set()
    udpServers        = {}
    tcpMetas          = {}
    
    with open(packetMeta, 'r') as f:
        count = 0
        for line in f:
            #0-Create packet object
            dPacket = singlePacket(line, client_ip)
            
            #1-Do necessary checks and skip when necessary
                        
            #1a-Skip no-man's packets or unknown protocols
            if (dPacket.talking is None) or (dPacket.stream is None):
                continue
            
            #1b-Skip local flows (mostly happens for DNS)            
            if isPrivate(dPacket.srcIP) and isPrivate(dPacket.dstIP):
                continue
            
            #1c-Skip no-payload packets
            if dPacket.length == 0:
                continue

            #1d-Skip streams where server is starting them!
            if dPacket.stream in brokenStreams[dPacket.protocol]:
                continue
            elif dPacket.stream not in startedStreams[dPacket.protocol]:
                if dPacket.talking == 's':
                    brokenStreams[dPacket.protocol].append(dPacket.stream)
                    continue
                else:
                    startedStreams[dPacket.protocol].append(dPacket.stream)
            
            #2a-For TCP, append to tcpMetas
            if dPacket.protocol == 'tcp':
                if dPacket.NXseq == -1:
                    continue
                elif dPacket.stream not in tcpMetas:
                    tcpMetas[dPacket.stream] = {'c':[], 's':[]}
                tcpMetas[dPacket.stream][dPacket.talking].append(dPacket)
                continue
                    
            #2b-For UDP, check consistency
            #Note we check len(payload)/2 because payload is in HEX
            (talking, payload) = handles[dPacket.protocol][dPacket.stream].next()
            assert(talking == dPacket.talking and len(payload)/2 == dPacket.length)
            
            #3-Extract necessary info
            udpClientPorts.add(dPacket.clientPort)
            
            if dPacket.serverIP not in udpServers:
                udpServers[dPacket.serverIP] = set()
            udpServers[dPacket.serverIP].add(dPacket.serverPort)
            
            #4-Add to queues
            if dPacket.csp not in serverQ[dPacket.protocol]:
                serverQ[dPacket.protocol][dPacket.csp]           = []
                serversTimeOrigin[dPacket.protocol][dPacket.csp] = dPacket.timestamp
            
            if configs.get('randomPayload') is True:
#                 payload = random_hex(len(payload))
                  payload = random_hex_by_payload(payload)

            # print '\n\t ****Count ***',count,'***talking****',talking
            if talking == 'c':
                udpClientQ.append( UDPset(payload, dPacket.timestamp, dPacket.csp) )
            elif talking == 's':
                serverQ[dPacket.protocol][dPacket.csp].append( UDPset(payload, dPacket.timestamp-serversTimeOrigin[dPacket.protocol][dPacket.csp], dPacket.csp) )
            count += 1

    # PRINT_ACTION('Adding UDP keep-alive packets', 0)
    udpClientQ = addUDPKeepAlives(udpClientQ)
    
    # PRINT_ACTION('Creating the hash Look-up Table', 0)
    LUT['udp'] = createHashLUT(udpClientQ, replay_name)

    # PRINT_ACTION('Sorting tcpMetas and tossing retransmissions', 0)
    tcpMetas = sortAndClean(tcpMetas)
    
    # PRINT_ACTION('Creating TCP queues', 0)
    
    sample_size    = 400
    tcpClientQ     = []
    tcpCSPs        = set()
    tcpServerPorts = set()
    
    diss   = []
    getLUT = {}
    
    if configs.get('randomPayload'):
        nonRandomStreamSkippedList = configs.get('pcap_folder').rpartition('_random')[0] + '/streamSkippedList.pickle'
        if os.path.isfile(nonRandomStreamSkippedList):
            nonRandomStreamSkippedList = pickle.load( open(nonRandomStreamSkippedList, 'r') )
            streamIgnoreList += nonRandomStreamSkippedList
    
    for stream in sorted(tcpMetas.keys()):
        if DEBUG == 2: print '\tDoing stream:', stream, len(tcpMetas[stream]['c']), len(tcpMetas[stream]['s'])
        
        if onlyStreams:
            if stream not in onlyStreams:
                streamSkippedList.append(stream)
                # print '\t\tStream not in onlyStreams list, skipping'
                continue 
        
        if stream in streamIgnoreList:
            streamSkippedList.append(stream)
            # print '\t\tStream in ignore list, skipping'
            continue
        
        [TMPclientQ, TMPserverQ, csp] = tcpStream2Qs(tcpMetas[stream], handles['tcp'][stream])


        '''
        ###############################
        Applying filters on TCP streams:
        ###############################
        '''
        #1- IP based filtering
        serverIP = csp[22:37]
        
#         if serverIP in ipIgnoreList:
        if isInNetworks(serverIP, ipIgnoreList):
            streamSkippedList.append(stream)
            # print '\t\tIgnoring stream {}. Server IP in ignore list!'.format(csp)
            continue
        
        #2- Request based filtering
        if 'Host: static.ess.apple.com:80' in TMPclientQ[0].payload.decode('hex'):
            streamSkippedList.append(stream)
            # print '\t\tIgnoring stream {}. apple static!'.format(csp)
            continue
        '''
        ###############################
        '''

        toHash  = TMPclientQ[0].payload.decode('hex')[:sample_size]
        theHash = hash(toHash)
        
        if theHash in LUT['tcp']:
            streamSkippedList.append(stream)
            print '\n\t*******************************************'
            print '\t*******************************************'
            print '\tATTENTION: take a look!!!'
            print '\tDUP in tcp LUT:', theHash, '\t', (replay_name, csp), '\n'
            print '\t', toHash
            print '\tSKIPPING!!!'
            print '\t*******************************************'
            print '\t*******************************************\n'  
            continue
        
        serverQ['tcp'][csp] = TMPserverQ
        tcpClientQ         += TMPclientQ
        
        tcpCSPs.add(csp)
        tcpServerPorts.add(csp[-5:])

        LUT['tcp'][theHash] = (replay_name, csp)
        
        '''
        ISPs may add/remove/modify HTTP headers. To prevent this from causing KeyErrors on the server
        when consulting the LUT, I create a getLUT[(replay_name, c_s_pair)] = dict(get request)
        
        When server sees a hash miss of a get request, consults getLUT and picks the closest. 
        '''
        if toHash[0:3] == 'GET':
            theDict = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", toHash.partition('\n')[2]))
            theDict['GET'] = toHash.partition('\r\n')[0]
            getLUT[(replay_name, csp)] = theDict
            diss.append( theDict )
    
    tcpClientQ.sort(key=lambda q: q.timestamp)
    
    # PRINT_ACTION('Merging UDP and TCP', 0)
    clientQ = tcpClientQ + udpClientQ
    clientQ.sort(key=lambda q: q.timestamp)
        
    # PRINT_ACTION('Serializing queues', 0)
    udpClientPorts = list(udpClientPorts) #JSON cannot serialize sets.
    tcpServerPorts = list(tcpServerPorts)
    for serverIP in udpServers:
        udpServers[serverIP] = list(udpServers[serverIP])

    # ******************************************************
    # THE FOLLOWING CODE IS USED FOR MAKING CHANGES ON THE QS
    # ******************************************************
    # Make changes on the flow level
    if RemainPackets != {'Client':[],'Server:':[]}:
        if RemainPackets['Client'] != ['all']:
            tempCQ = []
            # preparing Qs by only keeping the packets that are not in remainPart
            for num in RemainPackets['Client']:
                tempCQ.append(clientQ[num])
            # Update the Client Q
            clientQ = tempCQ

        if RemainPackets['Server'] == []:
            csp = serverQ[MProtocol].keys()[0]
            if MProtocol == 'udp':
                serverQ[MProtocol][csp] = []
            # TCP Analysis
            # else:
            #     for num in RemainPackets['Server']:
            #         tempSQ.append(serverQ[MProtocol][csp][num].response_list[0])

        elif RemainPackets['Server'] != ['all']:
            tempSQ = []
            csp = serverQ[MProtocol].keys()[0]
            if MProtocol == 'udp':
                for num in RemainPackets['Server']:
                    tempSQ.append(serverQ[MProtocol][csp][num])
            else:
                for num in RemainPackets['Server']:
                    tempSQ.append(serverQ[MProtocol][csp][num].response_list[0])
            # Update the Server Q
            serverQ[MProtocol][csp] = tempSQ


    # Make more changes on packet level
    if MSide != '':

        # modifications on the Client side is independent of the protocol
        if MSide == 'Client':
            print '\n\t Making Client changes ', MAction,'On packet',MPacketNum
            # print '\n\t Client packet', MPacketNum, ' Before ::',clientQ[MPacketNum-1].payload.decode('hex')

            if 'Random' in MAction:

                clientQ[MPacketNum-1].payload = XorPayload(clientQ[MPacketNum-1].payload)

                # print '\n\t After randomization ::',clientQ[MPacketNum-1].payload.decode('hex')
            #     Store the Qs with randomized packet into the /random dir, which will be loaded in RandomReplace
                print '\n\t Dumping the random payload into /random'
                XorDump(configs, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts)


            elif 'Truncate' in MAction:
                Tbyte = MList[0]
                clientQ[MPacketNum-1].payload = Truncate(clientQ[MPacketNum-1].payload, Tbyte)
                # print '\n\t After truncating ::',clientQ[MPacketNum-1].payload.decode('hex')

            elif 'Move' in MAction:
                clientQ[MPacketNum-1].payload = Move(clientQ[MPacketNum-1].payload, MList[0][0], MList[0][1])
                # print '\n\t After moving ::',clientQ[MPacketNum-1].payload.decode('hex')

            elif 'Delete' in MAction:
                # print '\n\t Client Q Before deleting ::',clientQ
                clientQ.pop(MPacketNum-1)
                # print '\n\t Client Q after deleting ::',clientQ

            elif 'ReplaceW' in MAction:
                regions = MList
                clientQ[MPacketNum-1].payload = MultiReplace(clientQ[MPacketNum-1].payload, regions, '')
                print '\n\t After ReplaceW ::',clientQ[MPacketNum-1].payload.decode('hex')

            elif 'ReplaceR' in MAction:

                regions = MList

                rpayload = XorLoad(configs, MSide, MPacketNum, 'client', 'client')
                rpayload = rpayload.decode('hex')

                clientQ[MPacketNum-1].payload = MultiReplace(clientQ[MPacketNum-1].payload, regions, rpayload)


            else:

                print '\n\t MAction is ',MAction,'No such action specified yet. No ACTION taken'


# The procotol needs to be specified when making changes on the server side

        elif MSide == 'Server':

            print '\n\t Making changes on Server', MProtocol, MAction,'On packet',MPacketNum

            # UDP server changes
            if MProtocol == 'udp':
                # There should only be one csp cause we have to clean up the original pcap before processing
                csp = serverQ[MProtocol].keys()[0]
                # print '\n\t Server packet', MPacketNum, ' Before ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                if 'Random' in MAction:
                    serverQ[MProtocol][csp][MPacketNum-1].payload = \
                        XorPayload(serverQ[MProtocol][csp][MPacketNum-1].payload)
                    # print '\n\t After randomization ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')
                    print '\n\t Dumping the random payload into /random'
                    XorDump(configs, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts)

                elif 'Truncate' in MAction:
                    Tbyte = MList[0]
                    serverQ[MProtocol][csp][MPacketNum-1].payload = \
                        Truncate(serverQ[MProtocol][csp][MPacketNum-1].payload, Tbyte)
                    # print '\n\t After truncating ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                elif 'Move' in MAction:
                    serverQ[MProtocol][csp][MPacketNum-1].payload = \
                        Move(serverQ[MProtocol][csp][MPacketNum-1].payload, MList[0][0], MList[0][1])
                    # print '\n\t After moving ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                elif 'Delete' in MAction:
                    # print '\n\t Server Q Before deleting ::',serverQ[MProtocol][csp]
                    serverQ[MProtocol][csp].pop(MPacketNum-1)
                    # print '\n\t Server Q after deleting ::',serverQ[MProtocol][csp]

                elif 'ReplaceW' in MAction:
                    regions = MList
                    serverQ[MProtocol][csp][MPacketNum-1].payload = \
                        MultiReplace(serverQ[MProtocol][csp][MPacketNum-1].payload, regions, '')
                    print '\n\t After ReplaceW ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                elif 'ReplaceR' in MAction:
                    regions = MList
                    rpayload = XorLoad(configs, MSide, MPacketNum, 'udp', csp)
                    rpayload = rpayload.decode('hex')
                    serverQ[MProtocol][csp][MPacketNum-1].payload = \
                        MultiReplace(serverQ[MProtocol][csp][MPacketNum-1].payload,regions, rpayload)

                else:

                    print '\n\t MAction is ',MAction,'No such action specified yet. No ACTION taken'

            #TCP server changes
            else:
                csp = serverQ[MProtocol].keys()[0]
                # For TCP, count the number of serverQ['tcp'][csp], make changes on serverQ['tcp'][csp][PacketNum].response_list[0].payload
                # print '\n\t Server packet', MPacketNum, ' Before ::',serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload.decode('hex')

                if 'Random' in MAction:
                    serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload = \
                        Randomize(serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload)
                    # print '\n\t After randomization ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')
                    print '\n\t Dumping the random payload into /random'
                    XorDump(configs, clientQ, udpClientPorts, tcpCSPs, replay_name, serverQ, LUT, getLUT, udpServers, tcpServerPorts)

                elif 'Truncate' in MAction:
                    Tbyte = MList[0]
                    serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload = \
                        Truncate(serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload, Tbyte)
                    # print '\n\t After truncating ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                elif 'Move' in MAction:
                    serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload = \
                        Move(serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload, MList[0][0], MList[0][1])
                    # print '\n\t After moving ::',serverQ[MProtocol][csp][MPacketNum-1].payload.decode('hex')

                elif 'Delete' in MAction:
                    # print '\n\t Server Q Before deleting ::',serverQ[MProtocol][csp]
                    serverQ[MProtocol][csp].pop(MPacketNum-1)
                    # print '\n\t Server Q after deleting ::',serverQ[MProtocol][csp]

                elif 'ReplaceW' in MAction:
                    regions = MList
                    serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload = \
                        MultiReplace(serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload, regions, '')
                    print '\n\t After ReplaceW ::',serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload.decode('hex')

                elif 'ReplaceR' in MAction:
                    regions = MList
                    rpayload = XorLoad(configs, MSide, MPacketNum, 'udp', csp)
                    rpayload = rpayload.decode('hex')
                    serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload = \
                        MultiReplace(serverQ[MProtocol][csp][MPacketNum-1].response_list[0].payload, regions, rpayload)

                else:
                    print '\n\t MAction is ',MAction,'No such action specified yet. No ACTION taken'
    # ***********************************************

    pickle.dump(streamSkippedList, open((configs.get('pcap_folder')+'/streamSkippedList.pickle'), "w" ), 2)
    pickle.dump((clientQ, udpClientPorts, list(tcpCSPs), replay_name)          , open((pcap_file+'_client_all.pickle'), "w" ), 2)
    pickle.dump((serverQ, LUT, getLUT, udpServers, tcpServerPorts, replay_name), open((pcap_file+'_server_all.pickle'), "w" ), 2)


def beingCalled(PcapDirectory, Side, Num, Action, Prot='tcp', Mlist = [],
                RemainPackets = {'Client':[],'Server':[]}):
    PcapDirectory = PcapDirectory+'/'
    run(PcapDirectory, Side, Num, Action, Prot, Mlist,RemainPackets)



