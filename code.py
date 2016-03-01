# Tanuj Khattar
# Joyneel Misra

import select
import socket
import os
import sys
import hashlib
from os import walk
import time
import subprocess
from subprocess import check_output
from Queue import Queue


def run(cmd):
    # runs commands for the application
    ret = []
    if cmd[0] == "IndexGet":
        ret = indexGet(cmd)
        return ret
    elif cmd[0] == "FileHash":
        ret = fileHash(cmd)
        return '+'.join(ret)
    elif cmd[0] == "FileDownload":
        ret = fileDownload(cmd)
        return ret
    elif cmd[0] == "FileSpecs":
        ret = fileSpecs(cmd)
        return ret
    else:
        return "Error : Invalid Command"


def parse(string):
    string = string.strip()
    cmd = string.split(' ')
    for i in xrange(len(cmd)):
        cmd[i] = cmd[i].strip()
    return cmd


def fileDownload(cmd):
    # returns file as a string
    if len(cmd) != 2:
        return ['Error : invalid syntax\nUse Syntax\
        \t$> FileDownload <filename>']
    filename = cmd[1]
    filename = filename.lstrip('.').lstrip('/')
    path = os.path.dirname(os.path.abspath(__file__)) + '/' + str(filename)
    if os.path.isfile(filename):
        f = open(path, "rb")
        ret = ''
        chunk = f.read(size)
        while(chunk):
            ret = ret + chunk
            chunk = f.read(size)
        f.close()
        return ret
    else:
        return 'Error : invalid filename, file does not exist'


def fileSpecs(cmd):
    ret = []
    filename = cmd[1]
    filename = filename.lstrip('.').lstrip('/')
    path = os.path.dirname(os.path.abspath(__file__)) + '/' + str(filename)
    ret.append(checkSum(path))
    ret.append(str(os.stat(path).st_size))
    ret.append(timeModified(path))
    ret.append(filename)
    return '$'.join(ret)


def checkSum(path):
    # returns file checksum
    return hashlib.md5(open(path, 'rb').read()).hexdigest()


def timeModified(path):
    # returns file time modified
    return time.ctime(os.path.getmtime(path))


def verify(cmd):
    # returns checksum and 'lastmodified' timestamp of a filename
    if len(cmd) != 2:
        return ['Error : invalid syntax\nUse Syntax\
        \t$> FileHash verify <filename>']
    filename = cmd[1]
    if os.path.isfile(filename):
        filename = filename.lstrip('.').lstrip('/')
        path = os.path.dirname(os.path.abspath(__file__)) + '/' + str(filename)
        ret = []
        ret.append(checkSum(path))
        ret.append(timeModified(path))
        return ret
    else:
        return ["Error : invalid filename, file doesn't exist"]


def checkAll(cmd):
    # returns checksum and 'lastmodified' timestamp of all files in shared
    # folder
    mypath = os.path.dirname(os.path.abspath(__file__))
    f = []
    for (dirpath, dirnames, filenames) in walk(mypath):
        f.extend(filenames)
        break
    ret = []
    for filename in f:
        path = os.path.dirname(os.path.abspath(__file__)) + '/' + str(filename)
        ret.append(filename)
        ret.append(checkSum(path))
        ret.append(timeModified(path))
    return ret


def fileHash(cmd):
    # runs the  command
    if len(cmd) < 2:
        return ['Error : invalid syntax\nUse Syntax\t$> FileHash <flag> args']
    else:
        if cmd[1] == "verify":
            return verify(cmd[1:])
        elif cmd[1] == "checkall":
            return checkAll(cmd[1:])
        else:
            return ['Error : invalid flag']


folder = "."


def shortList(cmd):
    # returns listing of files within timestamps
    if len(cmd) not in [3, 5]:
        return 'Error : invalid syntax\nUse Syntax\
        \t$> IndexGet shortlist <starttimestamp> <endtimestamp>'
    if len(cmd) == 3:
        start = cmd[1]
        end = cmd[2]
    elif len(cmd) == 5:
        start = str(cmd[1]) + " " + str(cmd[2])
        end = str(cmd[3]) + " " + str(cmd[4])
    ret = []
    retstr = '\tType\tSize\t\tTimestamp\t\t\tName\n'
    retstr = retstr + check_output(["find", folder, "-newermt", start, "!",
                                    "-newermt", end,
                                    "-printf",
                                    "\t%Y\t%s B\t\t%Td-%Tb-%TY %Tr\t%p\n"])
    ret.append(retstr)
    return ''.join(ret)


def longList(cmd):
    # returns entire listing of shared directory
    ret = []
    retstr = '\tType\tSize\t\tTimestamp\t\t\tName\n'
    retstr = retstr + \
        check_output(
            ["find", folder, "-printf", "\t%Y\t%s B\t\t%Td-%Tb-%TY %Tr\t%p\n"])
    ret.append(retstr)
    return ''.join(ret)


def regexList(cmd):
    # returns listing of files in shared directory satisfyting a regex
    if len(cmd) != 2:
        return 'Error : invalid syntax\n\
        Use Syntax\t$> IndexGet regex <regex>'
    regex = '^.*' + str(cmd[1])
    ret = []
    retstr = '\tType\tSize\t\tTimestamp\t\t\tName\n'
    retstr = retstr + check_output(["find", folder,
                                    "-regextype", "posix-egrep",
                                    "-regex", regex, "-printf",
                                    "\t%Y\t%s B\t\t%Td-%Tb-%TY %Tr\t%p\n"])
    ret.append(retstr)
    return ''.join(ret)


def indexGet(cmd):
    # runs the IndexGet command
    if len(cmd) > 1:
        if cmd[1] == "shortlist":
            return shortList(cmd[1:])
        elif cmd[1] == "longlist":
            return longList(cmd[1:])
        elif cmd[1] == "regex":
            return regexList(cmd[1:])
        else:
            return "Error: invalid syntax"
    else:
        return "Error: invalid syntax"


host = ''
backlog = 5
size = 65535
timeout = 2
mp = {}


def getBasicDetails():
    global server_host_name, my_tcp_port, my_tcp_server
    global my_udp_server, my_udp_port, server_udp_port, server_tcp_port
    # sys.stdout.write("Enter server host address : ")
    # server_host_name = raw_input()
    server_host_name = 'localhost'
    my_tcp_port = int(sys.argv[1])
    my_udp_port = int(sys.argv[2])
    server_tcp_port = int(sys.argv[3])
    server_udp_port = int(sys.argv[4])
    return
    sys.stdout.write("Enter my tcp port : ")
    my_tcp_port = int(raw_input())
    sys.stdout.write("Enter my udp port : ")
    my_udp_port = int(raw_input())
    sys.stdout.write("Enter server tcp port : ")
    server_tcp_port = int(raw_input())
    sys.stdout.write("Enter server udp port : ")
    server_udp_port = int(raw_input())


def readDataFromUDPSocket(s):
    (data, addr) = s.recvfrom(size)
    # print addr
    if addr not in mp.keys():
        mp[addr] = ''
    mp[addr] = mp[addr] + data
    if mp[addr][-1] == '$':
        mp[addr] = mp[addr][:-1]
        return (True, addr)
    else:
        return (False, addr)


def sendDataToUDPSocket(data, addr, s):
    s.sendto(str(data + "$"), addr)


def readDataFromTCPSocket(s):
    c = ''
    data = ''
    while c != '$':
        data = data + str(c)
        c = s.recv(1)
    msglen = int(data)
    data = ''
    bytes_rcvd = 0
    while(bytes_rcvd < msglen):
        chunk = s.recv(min(msglen - bytes_rcvd, size))
        data = data + chunk
        bytes_rcvd = bytes_rcvd + len(chunk)
    return data


def sendDataToTCPSocket(data, s):
    data = str(data)
    data = str(len(data)) + "$" + data
    msglen = len(data)
    totalsent = 0
    while totalsent < msglen:
        sent = s.send(data[totalsent:])
        totalsent = totalsent + sent


def processCommand(command):
    command = parse(command)
    return run(command)

fileDict = {}


def notify(message):
    subprocess.Popen(['notify-send', message])


def getUpdate(data):
    # checks for any updates in peer folder
    tpDict = {}
    tp = data.split('+')
    for i in range(0, len(tp), 3):
        tpDict[tp[i]] = [tp[i+1], tp[i+2]]
    global fileDict
    if not fileDict:
        fileDict = tpDict
    else:
        for i in tpDict.keys():
            if i in fileDict.keys():
                if tpDict[i][0] != fileDict[i][0]:
                    notify(i + " has been changed.")
        for i in tpDict.keys():
            if i not in fileDict.keys():
                notify(i + " has been added.")
        for j in fileDict.keys():
            if j not in tpDict.keys():
                notify(j + " has been deleted.")
        fileDict = tpDict


def process(command, data):
    global server_tcp_host
    global q
    command = parse(command)
    if(command[0] == 'FileDownload'):
        if "Error : invalid filename, file does not exist" in data:
            print data
        else:
            # print command[1]
            fname = command[1]
            f = open(fname, "wb")
            f.write(data)
            f.close()
            sendCommand = "FileSpecs " + fname
            sendDataToTCPSocket(sendCommand, server_tcp_host)
            q.put(sendCommand)

    elif command[0] == 'FileSpecs':
            print data
            tp = data.split('$')
            fname = command[1]
            fname = fname.lstrip('.').lstrip('/')
            path = os.path.dirname(
                os.path.abspath(__file__)) + '/' + str(fname)
            if tp[0] == checkSum(path):
                print "\tHash\t\t\t\tSize\t\t\t\
                Time Modified\t\t\tFilename"
                print '\t'.join(tp)
                notify("FileDownload succesful!")
            else:
                print tp[0]
                print checkSum(path)
                notify("FileDownload Unsuccesful!")
                os.remove(path)

    elif command[0] == 'FileHash':
        print "reply from server : "
        if command[1] == 'checkall':
            tp = data.split('+')
            if len(tp) == 1:
                print tp[0]
            else:
                filelist = {}
                print "\tHash\t\t\t\tTime Modified\t\t\tFilename"
                for i in range(0, len(tp), 3):
                    print "\t%s\t%s\t%s\
                    " % (tp[i+1], tp[i+2], tp[i])
                    pair = []
                    pair.append(tp[i+1])
                    pair.append(tp[i+2])
                    filelist[tp[i]] = pair
        elif command[1] == 'verify':
            tp = data.split('+')
            if len(tp) == 1:
                print tp[0]
            else:
                print "\t%s\t%s\
                " % (tp[0], tp[1])
    else:
        print "reply from server : \n" + str(data)


def main():
    getBasicDetails()
    my_tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_tcp_server.bind((host, my_tcp_port))
    my_udp_server.bind((host, my_udp_port))
    my_tcp_server.listen(backlog)
    global server_tcp_host
    server_tcp_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_input("Press Enter to connect to server")
    server_tcp_host.connect((server_host_name, server_tcp_port))
    input = [my_tcp_server, my_udp_server,
             server_tcp_host, sys.stdin]
    print_prompt = 1
    checkFile = False
    currTime = 0
    clock = 15
    global q
    q = Queue(1000)
    while 1:
        currTime = currTime + 1
        if currTime >= clock:
            checkFile = True
            currTime = 0
        if print_prompt == 1:
            print "$> ",
            sys.stdout.flush()
        print_prompt = 0
        inputready, outputready, exceptready = select.select(
            input, [], [], timeout)
        if checkFile is True:
            cmd = "FileHash checkall"
            sendDataToTCPSocket(cmd, server_tcp_host)
            q.put("getUpdate")
            checkFile = False
        for s in inputready:

            if s == my_tcp_server:
                client, addr = s.accept()
                input.append(client)

            elif s == my_udp_server:
                # handle the udp socket. Data coming from another client to
                # me by udp. Process it and send the output back using udp.
                (status, addr) = readDataFromUDPSocket(s)
                if status is True:
                    # Process data here and send the reply :)
                    reply = processCommand(mp[addr])
                    sendDataToUDPSocket(reply, addr, s)
                    mp[addr] = ''

            elif s == server_tcp_host:
                data = readDataFromTCPSocket(server_tcp_host)
                command = q.get()
                if(command == "getUpdate"):
                    getUpdate(data)
                else:
                    process(command, data)
                    print_prompt = 1

            elif s == sys.stdin:
                # handle standard input
                command = raw_input()
                data = ''
                if command == 'exit':
                    sys.exit(0)

                elif "tcp" in command:
                    command = command.strip(' ').strip('tcp').strip(' ')
                    sendDataToTCPSocket(command, server_tcp_host)
                    q.put(command)

                elif "udp" in command:
                    command = command.strip(' ').strip('udp').strip(' ')
                    addr = (server_host_name, server_udp_port)
                    sendDataToUDPSocket(command, addr, my_udp_server)
                    addr = readDataFromUDPSocket(my_udp_server)[1]
                    data = mp[addr]

                else:
                    sendDataToTCPSocket(command, server_tcp_host)
                    q.put(command)

                print_prompt = 1

            else:
                # handle data coming via TCP request to me here.
                data = readDataFromTCPSocket(s)
                reply = processCommand(data)
                # send the response back
                sendDataToTCPSocket(reply, s)
                # done :)
    my_tcp_server.close()
    my_udp_server.close()


if __name__ == "__main__":
    main()
