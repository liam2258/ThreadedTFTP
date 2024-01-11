import argparse
from socket import *
import filecmp
import threading
import random

parser = argparse.ArgumentParser(description='Uses TFTP over UDP to send or receive file')
parser.add_argument('-sp', '--serverport', help='local server port to use', type=int, required=True)
args = parser.parse_args()  
if not args.serverport:
    print("invalid argument\n" + "Please try again")
    exit()
elif args.serverport < 5000 or args.serverport > 65535:
    print("port range is restricted to 5000 and 65535, inclusive \n" + "Please try again")
    exit()

serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', args.serverport))

threads = []

def shut_down():
    serverSocket.close()
    exit()

def build_error_packet(errorCode, variable):
    packet = bytearray()

    packet.append(0)
    packet.append(5)
    packet.append(0)
    packet.append(errorCode)

    variable = bytearray(variable.encode('utf-8'))
    packet += variable
    packet.append(0)

    return packet

def build_ack(byte1, byte2):
    ack = bytearray()
    ack.append(0)
    ack.append(4)
    ack.append(byte1)
    ack.append(byte2)
    return ack

def unpack_DATA(filename, packet):

    opcode = packet[1]
    block = [packet[2], packet[3]]
    j = 4
    data = bytearray()
    if len(packet) < 5:
        with open(filename, 'ba') as file_object:
            file_object.close()
    
    else:
        while j < len(packet):
            data.append(packet[j])
            j = j + 1

        with open(filename, 'ba') as file_object:
            file_object.write(data)

    file_object.close()

    return opcode, block, data

def create_data(filename):
    with open(filename) as f:
        content = f.read()

    content = bytearray(content.encode('utf-8'))

    dataPackets = []
    dataPacket = bytearray()

    y = 0
    x = 0

    while x < len(content):
        while y != 512 and x < len(content):
            dataPacket.append(content[x])
            y += 1
            x += 1
        y = 0
        dataPackets.append(dataPacket)
        dataPacket = bytearray()

    y = 0
    x = 1

    Packets = []
    Packet = bytearray()

    for count, data in enumerate(dataPackets):
        Packet = bytearray()
        Packet.append(0)
        Packet.append(3)
        if x > 255:
            y += 1
            x = 0
        Packet.append(y)
        Packet.append(x)
        Packets.append(Packet + dataPackets[count])
        x += 1

    if len(Packets) > 1 and len(Packets[-1]) == 516:
        Packet = bytearray()
        Packet.append(0)
        Packet.append(3)
        Packet.append(0)
        Packet.append(0)
        Packets.append(Packet)
    return Packets

def send_packet(packet, Address, newSocket):
    modifiedMessage = ''
    serverAddress = ''
    flag = True
    x = 0
    while flag and x != 20:
        try:
            newSocket.sendto(packet, Address)
            newSocket.settimeout(10)
            modifiedMessage, serverAddress = newSocket.recvfrom(1024)
            if len(modifiedMessage) < 2 and serverAddress == Address:
                error = build_error_packet(4, 'Invalid packet size: Too small')
                newSocket.sendto(error, Address)
                shut_down()
            if len(modifiedMessage) > 516:
                error = build_error_packet(4, 'Invalid packet size: Too large')
            if modifiedMessage[1] == 5:
                print('Received error, shutting down')
                shut_down()
            if modifiedMessage[1] != 1 and modifiedMessage[1] != 2 and modifiedMessage[1] != 3 and modifiedMessage[1] != 4 and modifiedMessage[1] != 5 and serverAddress == Address:
                error = build_error_packet(4, 'Invalid op code')
                newSocket.sendto(error, Address)
                shut_down()
            while serverAddress != Address:
                error = build_error_packet(5, 'Wrong port')
                newSocket.sendto(error, (serverAddress[0], serverAddress[1]))
                modifiedMessage, serverAddress = newSocket.recvfrom(1024)
            flag = False
        except timeout:
            x += 1
        if x == 20:
            print('unable to connect, shutting down')
            shut_down()
    return modifiedMessage

def rrq_thread_function(filename, clientAddress):
    print("Starting thread for client port:", clientAddress)
    packets = create_data(filename)
    newSocket = socket(AF_INET, SOCK_DGRAM)
    newSocket.bind(('', random.randint(5000, 65535)))
    newSocket.connect(clientAddress)

    for data in packets:
        ack = send_packet(data, clientAddress, newSocket)
        while ack[2] != data[2] or ack[3] != data[3]:
            ack = send_packet(data, clientAddress)

    newSocket.close()

def unpack_request(packet):

    opcode = [packet[0], packet[1]]
    nameEnd = packet.find(b'\0', 2)
    filename = packet[2:nameEnd].decode('utf-8')
    modeEnd = packet.find(b'\0', nameEnd+1)
    mode = packet[nameEnd+1:modeEnd].decode('utf-8')

    return opcode, filename

if __name__ == '__main__':
    prev_block = 0

    while True:
        message, clientAddress = serverSocket.recvfrom(2048)
        print("Received from client:")
        print(message)
        print(clientAddress)
        opcode, filename = unpack_request(message)
        print(opcode)
        if opcode == [0, 1]:
            t = threading.Thread(target=rrq_thread_function, args=(filename, clientAddress))
            t.start()
            threads.append([t, clientAddress])

serverSocket.close()