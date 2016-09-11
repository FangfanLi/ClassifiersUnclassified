import sys,pickle,classifier_parser,runReplay,time,subprocess

from collections import deque

# Attention: User should provide the pcap folder in main

Replaycounter = 0

def GetMeta(PcapDirectory, Prot):

    Meta = {'Client':[], 'Server':[]}

    # Do classical stuff, make the pickles without any change
    prepareNewpickle(PcapDirectory, '',0,'','',[])

    serverQ, tmpLUT, tmpgetLUT, udpServers, tcpServerPorts, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_server_all.pickle','r'))

    clientQ, udpClientPorts, tcpCSPs, replayName = \
        pickle.load(open(PcapDirectory + '/test.pcap_client_all.pickle', 'r'))

    # There should always be at least one client packet
    if len(clientQ) > 0:
        for cPacket in clientQ:
            Meta['Client'].append(len(cPacket.payload.decode('hex')))

    # There should only be a single csp
    csp = serverQ[Prot].keys()[0]

    if len(serverQ) > 0:
        # For UDP traffic
        if Prot == 'udp':
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.payload.decode('hex')))

        else:
            for sPacket in serverQ[Prot][csp]:
                Meta['Server'].append(len(sPacket.response_list[0].payload.decode('hex')))

    return Meta,csp

def detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, analysisRegion, csp):
    LeftB = analysisRegion[0][0]
    RightB = analysisRegion[0][1]
    Masked = analysisRegion[1]
    noEffect = []
    hasEffect = []
    for num in xrange(RightB - LeftB):
        newMask = list(Masked)
        newMask.append((LeftB+num,LeftB+num+1))
        print '\n\t  PREPARING Detailed MASK',Masked,newMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,newMask)
        Classi = Replay(PcapDirectory, csp)
        if Classi == original:
            noEffect.append(LeftB+num)
        else:
            hasEffect.append(LeftB+num)

    print '\n\t The change HAS Effect OR NOT',hasEffect,noEffect
    return hasEffect


# Make new pickle with specified changes and scp the new files to the server side
def prepareNewpickle(PcapDirectory, Side,Num,Action,Prot,MList):
    classifier_parser.beingCalled(PcapDirectory, Side, Num, Action, Prot, MList)
    # Deliver the new pickles to tuco
    subprocess.call('scp '+PcapDirectory+'/*all.pickle tuco:/home/fangfan/Test', stdout=subprocess.PIPE , shell=True)

# RPanalysis stands for Random Payload analysis
# It would return the key regions by randomizing different part of the payload
# The key regions are the regions that trigger the classification
def RPanalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, csp):
    # Create the pickle files with this packet randomized
    allRegions = []
    # RAque is the queue that stores the analysis that are needed to run
    # each element of the queue is a pair of a. (pair of int) and b. (list of pairs): ((x,y),[(a,b),(c,d)])
    # (x,y) is the suspected region, meaning somewhere in this region triggers the classification
    # [(a,b),(c,d)] is the list of regions that we know does not have effect, so those region would be randomized
    # We would randomize half of the bytes in (x,y), and enqueue the new region based on the result of replaying both halves
    RAque = deque()
    # Initialization
    RAque.append(((0,Length),[]))
    analysis = RAque.popleft()
    # While the length of each suspected region is longer than 4, we need to keep doing the binary randomization
    while analysis[0][1] - analysis[0][0] > 4:
        LeftBar = analysis[0][0]
        RightBar = analysis[0][1]
        MidPoint = LeftBar + (RightBar - LeftBar)/2
        MaskedRegions = analysis[1]
        LeftMask = list(MaskedRegions)
        RightMask = list(MaskedRegions)
        LeftMask.append((LeftBar, MidPoint))
        RightMask.append((MidPoint, RightBar))

        print '\n\t  PREPARING LEFT MASK',MaskedRegions,LeftMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,LeftMask)
        LeftClass = Replay(PcapDirectory, csp)
        print '\n\t  PREPARING RIGHT MASK',MaskedRegions,RightMask
        prepareNewpickle(PcapDirectory, Side,PacketNum,'ReplaceR',Prot,RightMask)
        RightClass = Replay(PcapDirectory, csp)
        # Four different cases
        if LeftClass == original and RightClass != original:
            RAque.append(((MidPoint, RightBar), LeftMask))

        elif LeftClass != original and RightClass == original:
            RAque.append(((LeftBar, MidPoint), RightMask))

        elif LeftClass != original and RightClass != original:
            RAque.append(((LeftBar,MidPoint), MaskedRegions))
            RAque.append(((MidPoint,RightBar), MaskedRegions))

        else:
            allRegions = ['Both sides have no effect']
            break

        analysis = RAque.popleft()

    if allRegions != []:
        return allRegions

    else:
        # Put the last poped element back
        RAque.appendleft(analysis)

        for region in RAque:
            effectRegion = detailAnalysis(PcapDirectory, Side, PacketNum, Length, Prot, original, region, csp)
            allRegions.append(effectRegion)

    return allRegions


def Replay(PcapDirectory,csp):
    global Replaycounter
    Replaycounter += 1
    print '\n\t Preparing for replay'
    time.sleep(20)

    classification = runReplay.main(PcapDirectory,csp)
    while classification == '':
        print '\n\t *******Attention Empty classification, re-run in 20 secs '
        time.sleep(20)
        classification = runReplay.main(PcapDirectory,csp)

    return classification

# This would do an analysis on the length of this packet
# By binary changing the length of the packet,
# it would isolate the length of the packet that triggers the classification
def TRanalysis(PcapDirectory, Side, PacketNum , Length, Protocol, Classi_Origin, csp):
    preCutPoint = Length
    cutPoint = Length/2
    threshold = 10
    # Coarse analysis, if the classification changes between length x and length x+threshold packet
    # We then conclude that x is the length that the classifier is looking for
    while preCutPoint - cutPoint > threshold:
        print '\n\t&&& preparing to truncate',Side,PacketNum,cutPoint
        prepareNewpickle(PcapDirectory, Side, PacketNum, 'Truncate',Protocol,[cutPoint])
        Classi = Replay(PcapDirectory,csp)
        # If the classification does not change
        if Classi == Classi_Origin:
            preCutPoint = cutPoint
            cutPoint = preCutPoint/2
        else:
            cutPoint = preCutPoint - cutPoint/2

    print '\n\t &&&&& the two lengths are ',cutPoint, preCutPoint


    return cutPoint


# This would do a full analysis on one side of the conversation
# Delete each packet from the side first
# If deleting it do not change the result, this packet has no effect
# Else, then look into the payload by binary randomization
#       If the key regions can be found in the payload
#           record those regions
#       Else do Truncate analysis to check whether the length of packet has effect
def FullAnalysis(PcapDirectory, meta,Classi_Origin,Protocol,Side,csp):
    Analysis = {}
    for packetNum in xrange(len(meta[Side])):
        Analysis[packetNum] = []
        # Remember adding 1 to packetNumber before calling makeNewpickle
        # Skip removing this packet if it is the only one on Client side(otherwise the replay would not begin)
        if Side == 'Client' and len(meta[Side]) == 1 :
            Classi = ''
        else:
            print '\n\t Preparing to delete on ', Side, packetNum+1
            prepareNewpickle(PcapDirectory, Side,packetNum + 1,'Delete',Protocol,[])
            Classi = Replay(PcapDirectory,csp)
        # if removing does not change classification


        if Classi == Classi_Origin:
            Analysis[packetNum]='removable'
        # Else do random payload analysis
        else:
            regions = []
            trial = 1
            RClass = ''
            # At Most try 3 times to confirm that the payload does not matter
            trialBar = 3
            while trial < trialBar:
                prepareNewpickle(PcapDirectory, Side , packetNum + 1,'Random',Protocol,[])
                RClass = Replay(PcapDirectory,csp)
                if RClass != Classi_Origin:
                    regions = RPanalysis(PcapDirectory, Side, packetNum + 1, meta[Side][packetNum], Protocol, Classi_Origin,csp)
                    break
                else:
                    trial += 1

            # No key regions being identified, Do truncate analysis
            if regions == []:
                Length = TRanalysis(PcapDirectory, Side, packetNum + 1 ,meta[Side][packetNum], Protocol, Classi_Origin,csp)
                TRresult = ['Truncate Length', Length]
                Analysis[packetNum] = TRresult

            else:
                RPresult = ['Payload matter, key regions:', regions]
                Analysis[packetNum] = RPresult

    return Analysis


def main(args):
    # Please specify the PcapDirectory here
    PcapDirectory = ''

    try:
        Protocol = args[1]

        if Protocol not in ['udp','tcp']:
            print 'The protocol can either be "udp" or "tcp" \n'
            sys.exit()

        if '-d' in args:
            PcapDirectory = args[args.index('-d')+1]
            args.remove('-d')
            args.remove(PcapDirectory)
    except:
        print 'Please provide the parameters as specified: [protocol] <-d PcapDirectory>\n'
        # print 'Please provide the parameters as specified: [protocol]  [directory] '
        sys.exit()


    meta,csp = GetMeta(PcapDirectory, Protocol)
    print 'META DATA', meta, csp

    # Get Original Classification
    global Replaycounter

    Classi_Origin = Replay(PcapDirectory,csp)

    # Start from Client Packets analysis
    Client = FullAnalysis(PcapDirectory, meta, Classi_Origin, Protocol, 'Client',csp)
    # Then work on server side
    Server = FullAnalysis(PcapDirectory, meta, Classi_Origin, Protocol, 'Server',csp)

    print '\n\t Client analysis',Client,'\n\t Server analysis',Server, 'Number of Tests:', Replaycounter


if __name__=="__main__":
    main(sys.argv)