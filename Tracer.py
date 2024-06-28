#!/usr/bin/python3
#RU_PRESALE_TEAM_BORIS_O
# Perfomance: ~ 50 EPS (Enrichment: 50 connections, 100 RPS)

import socket
from select import select
from signal import signal
from sys import platform
from re import match
from datetime import datetime
from dateutil.relativedelta import relativedelta
from urllib.parse import unquote


SERVER = "0.0.0.0"
PORT = 16666
regexURLFeed = compile(r"\S+?\n?\S+\|url\=([^\|]+).+")
ADDR = (SERVER, PORT)


class CtrlBreakInterrupt(BaseException):
    pass


def handler(*args):
    raise CtrlBreakInterrupt


def all_sockets_closed(server_socket, starttime):
    """closes the server socket and displays the duration of the connection"""
    print("\n\nAll Clients Disconnected\nClosing The Server...")
    endtime = datetime.now()
    diff = relativedelta(endtime, starttime)
    elapsed = "{} year {} month {} days {} hours {} minutes {} seconds {} microseconds".format(diff.years, diff.months, diff.days, diff.hours, diff.minutes, diff.seconds, diff.microseconds)
    server_socket.close()
    print(f"\nThe Server Was Active For: {elapsed}\n\n")


def active_client_sockets(connected_sockets):
    """prints the IP and PORT of all connected sockets"""
    print("\nCurrently Connected Sockets:")
    for c in connected_sockets:
        print("\t", c.getpeername())  # ('IP', PORT)


def serve_client(current_socket, server_socket, connected_sockets, starttime):
    """Takes the msg received from the client and handles it accordingly"""
    try:
        client_data = current_socket.recv(1024).decode()
        date_time = datetime.now()

        if client_data != "":
            print(
                f"\nReceived new message form client {current_socket.getpeername()} at {date_time}:"
            )

    except ConnectionResetError:
        print(f"\nThe client {current_socket.getpeername()} has disconnected...")
        connected_sockets.remove(current_socket)
        current_socket.close()
        if len(connected_sockets) != 0:  # check for other connected sockets
            active_client_sockets(connected_sockets)
        else:
            raise ValueError
        """the whole disconnection sequence is triggered from the exception handler, se we will just raise the exception
                to close the server socket"""
    
    else:        
        if client_data != "":
            print(client_data)
        
        if regexURLFeed.match(client_data):  # HERE ADD YOUR EXTRA ACTIONS FOR ENRICHMENT
            Category = "miniCT_URL_Decoder"
            ioc = regexURLFeed.match(str(client_data)).group(1)
            somedata = unquote(ioc)
            responseToKUMA = "Category={}|MatchedIndicator={}|decodedURL={}\nLookupFinished".format(Category, ioc, somedata)
            #resp = "Category=MyFeed|MatchedIndicator=" + re.match(regexURLFeed, str(client_data)).group(1) + "|popularity=1|threat=" + somedata +"|type=1\nLookupFinished"
            current_socket.send(responseToKUMA.encode())
            current_socket.send("LookupFinished".encode())
            print("Responded by: " + responseToKUMA)
            connected_sockets.remove(current_socket)
            current_socket.close()
        
        if not client_data:
            connected_sockets.remove(current_socket)
            current_socket.close()


def main():
    """server setup and socket handling"""
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # For server TCP_FASTOPEN
    # echo 3 > /proc/sys/net/ipv4/tcp_fastopen
    # and you can set the timeout to 1 second by doing this: echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle 
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if platform != 'win32':
        server_socket.setsockopt(socket.SOL_TCP, 23, 5) # here 23 is the protocol number of TCP_FASTOPEN
    server_socket.bind(ADDR)
    server_socket.listen()

    print("\n* Server is ON *\n")
    print("Waiting for clients to establish connection...")
    starttime = datetime.now()
    connected_sockets = []  # list of the client sockets being connected
    try:
        while True:
            ready_to_read, ready_to_write, in_error = select(
                [server_socket] + connected_sockets, [], []
            )            
            for current_socket in ready_to_read:                
                if (
                    current_socket is server_socket
                ):  # if the current socket is the new socket we receive from the server
                    (client_socket, client_address) = current_socket.accept()
                    print("\nNew client joined!", client_address)
                    connected_sockets.append(client_socket)
                    active_client_sockets(connected_sockets)
                    continue
                serve_client(
                    current_socket, server_socket, connected_sockets, starttime
                )
    except ValueError:
        all_sockets_closed(server_socket, starttime)
        pass
    except CtrlBreakInterrupt:
        print("\nCTRL-BREAK Entered")
    except KeyboardInterrupt:
        print("\nCTRL-C Entered")
        all_sockets_closed(server_socket, starttime)

if __name__ == "__main__":
    main()
