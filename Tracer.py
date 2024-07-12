#!/usr/bin/python3
# coding=utf-8
__version__ = '0.2'

import socket
from select import select
from sys import platform, exit
from re import match, compile, search, error
from datetime import datetime
from optparse import OptionParser
from urllib.parse import unquote
from os.path import isfile, splitext, getsize
from csv import DictReader
from json import load, loads
import pickle
import logging

#logging config
logging.basicConfig(filename='/var/log/Tracer.log',
                    encoding='utf-8',
                    filemode='a',
                    format='%(asctime)s.%(msecs)03d %(name)s %(levelname)s %(message)s',
                    datefmt="%Y-%m-%dT%H:%M:%S%z",
                    level=logging.INFO)

SERVER = "0.0.0.0"
PORT = 16666
ADDR = (SERVER, PORT)
regexURLFeed = compile(r"url\=([^\|]+)")
regexIPFeed = compile(r"ip\=([^\|]+)")
regexHASHFeed = compile(r"hash\=([^\|]+)")

iocs_from_event = {
    "hash": [],
    "ip": [],
    "url": []
}


class CtrlBreakInterrupt(BaseException):
    pass


def handler(*args):
    raise CtrlBreakInterrupt


def get_file_extension(filename):
    _, ext = splitext(filename)
    return ext.lower()


def load_csv_to_dict(file_path, key_field):
    data_dict = {}
    with open(file_path, newline='') as csvfile:
        reader = DictReader(csvfile)
        for row in reader:
            key = row[key_field]
            data_dict[key] = row
    return data_dict


def load_json_to_dict(file_path, key_field):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = load(file)
    if isinstance(data, dict):
        return {data[key_field]: data}
    else:
        raise ValueError("Unsupported JSON structure")


def dict_to_key_value(dictionary):
    if isinstance(dictionary, str):
        dictionary = loads(dictionary)
    def convert_value(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, list):
            return ','.join(convert_value(item) for item in value)
        elif isinstance(value, dict):
            return dict_to_key_value(value)
        else:
            return str(value)
    key_value_pairs = [f"{key}={convert_value(value)}" for key, value in dictionary.items()]
    result = '|'.join(key_value_pairs)
    return result


def search_in_dict_keys(dictionary, pattern, use_regex=False):
    # search_in_dict_keys(my_dict, r'\d$', use_regex=True)
    result = {}
    for key in dictionary.keys():
        if use_regex:
            if search(pattern, key):
                result[key] = dictionary[key]
        else:
            if pattern in key:
                result[key] = dictionary[key]
    return result


def all_sockets_closed(server_socket, starttime):
    """closes the server socket and displays the duration of the connection"""
    #print("\n\nAll Clients Disconnected\nClosing The Server...")
    logging.info("All Clients Disconnected. Closing The Server...")
    endtime = datetime.now()
    diff = endtime - starttime
    elapsed = "{} days {} hours {} minutes {} seconds".format(diff.days, diff.seconds // 3600, diff.seconds // 60 % 60, diff.seconds % 60)
    server_socket.close()
    #print(f"\nThe Server was Active For: {elapsed}\n\n")
    logging.info(f"The Server was Active For: {elapsed}")


def active_client_sockets(connected_sockets):
    """prints the IP and PORT of all connected sockets"""
    print("\nCurrently Connected Sockets:")
    for c in connected_sockets:
        print("\t", c.getpeername())  # ('IP', PORT)


def enrich_url_decoder(url_encoded_str):
        category = "Tracer_URL_Decoder"
        url_enrich = unquote(url_encoded_str)
        response = "Category={}|MatchedIndicator={}|decodedURL={}\n".format(category, url_encoded_str, url_enrich)
        return response


def serve_client(current_socket, server_socket, connected_sockets, starttime, mode, feed_dict, feed_dict_regex):
    """Takes the msg received from the client and handles it accordingly"""
    #peer_name = current_socket.getpeername()
    try:
        client_data = current_socket.recv(1024).decode()
        date_time = datetime.now()

        if client_data != "":
            print(f"\nReceived new message form client {current_socket.getpeername()} at {date_time}:")

    except ConnectionResetError:
        print(f"\nThe client {current_socket.getpeername()} has disconnected...")
        logging.info(f"The client {current_socket.getpeername()} has disconnected...")
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
        
        if regexURLFeed.findall(client_data) or regexHASHFeed.findall(client_data) or regexIPFeed.findall(client_data):  # HERE ADD YOUR EXTRA ACTIONS FOR ENRICHMENT
            logging.info(f"Received new message form client {current_socket.getpeername()} at {date_time}: {client_data}")
            iocs_from_event["url"] = regexURLFeed.findall(client_data)
            iocs_from_event["hash"] = regexHASHFeed.findall(client_data)
            iocs_from_event["ip"] = regexIPFeed.findall(client_data)
            print(f'\nReceived iocs from event, URL: {iocs_from_event["url"]} , HASH: {iocs_from_event["hash"]}, IP: {iocs_from_event["ip"]}')
            logging.info(f'Received iocs from event, URL: {iocs_from_event["url"]} , HASH: {iocs_from_event["hash"]}, IP: {iocs_from_event["ip"]}')

            if mode == 0:
                print("HELLLOO!")
                # custom mode actions
                if iocs_from_event["url"]:
                    for url in iocs_from_event["url"]:
                        url_decode = enrich_url_decoder(url)
                        current_socket.send(url_decode.encode())
                        print("Responded by: " + url_decode)
                get_hash = iocs_from_event["hash"][0]
                print(get_hash)
                tt = r'{"name": "John", "age": 30, "city": "New York", "urls": [{"url": "penispictures.com/big-dick-pics"}, {"url": "anotherurl.com"}], "tags": ["funny", "entertaining"]}'
                print(type(tt))
                dt = dict_to_key_value(tt)
                print(dt)
                hash_enrich = f"Category=HASH_enricher|MatchedIndicator={get_hash}|{dt}\n"
                #responseToKUMA2 = hash_enrich + "\n"
                current_socket.send(hash_enrich.encode())
                print("Responded by: " + hash_enrich)
                #current_socket.send("\nLookupFinished".encode())
                current_socket.send("LookupFinished".encode())
                connected_sockets.remove(current_socket)
                current_socket.close()
            else:
                if iocs_from_event["hash"]:
                    for hash in iocs_from_event["hash"]:
                        try:
                            hash_match = feed_dict[hash]
                        except KeyError:
                            hash_match = 0
                            print(f"KeyError: The key '{hash}' does not exist in the dictionary.")
                            logging.warning(f"KeyError: The key '{hash}' does not exist in the dictionary.")
                        if hash_match:
                            hash_enrich = f"Category=Tracer_HASH_enricher|MatchedIndicator={hash}|{dict_to_key_value(hash_match)}\n"
                            print("Responded by: " + hash_enrich)
                            logging.info(f"Responded by: {hash_enrich[:-1]}")
                            try:
                                current_socket.send(hash_enrich.encode())
                            except BrokenPipeError:
                                print("Broken pipe error while sending data")
                                logging.error("Broken pipe error while sending data")
                if iocs_from_event["ip"]:
                    for ip in iocs_from_event["ip"]:
                        try:
                            ip_match = feed_dict[ip]
                        except KeyError:
                            ip_match = 0
                            print(f"KeyError: The key '{ip}' does not exist in the dictionary.")
                            logging.warning(f"KeyError: The key '{ip}' does not exist in the dictionary.")
                        if ip_match:
                            ip_enrich = f"Category=Tracer_IP_enricher|MatchedIndicator={ip}|{dict_to_key_value(ip_match)}\n"
                            print("Responded by: " + ip_enrich)
                            logging.info(f"Responded by: {ip_enrich[:-1]}")
                            try:
                                current_socket.send(ip_enrich.encode())
                            except BrokenPipeError:
                                print("Broken pipe error while sending data")
                                logging.error("Broken pipe error while sending data")
                if iocs_from_event["url"]:
                    for url in iocs_from_event["url"]:
                        try:
                            url_match = feed_dict[url]
                        except KeyError:
                            url_match = 0
                            print(f"KeyError: The key '{url}' does not exist in the dictionary.")
                            logging.warning(f"KeyError: The key '{url}' does not exist in the dictionary.")
                        if url_match:
                            print(url_match)
                            url_enrich = f"Category=Tracer_URL_enricher|MatchedIndicator={url}|{dict_to_key_value(url_match)}\n"
                            print("Responded by: " + url_enrich)
                            logging.info(f"Responded by: {url_enrich[:-1]}")
                            try:
                                current_socket.send(url_enrich.encode())
                            except BrokenPipeError:
                                print("Broken pipe error while sending data")
                                logging.error("Broken pipe error while sending data")
                        else:
                            #if len(feed_dict_regex.keys()) > 0:
                            for key, value in feed_dict_regex.items():
                                try:
                                    if match(key, url):
                                        print(f"[MATCH]  Regex match {key} matched this  {url}")
                                        url_enrich = f"Category=Tracer_URL_enricher|MatchedIndicator={url}|{dict_to_key_value(feed_dict_regex[key])}\n"
                                        print("Responded by: " + url_enrich)
                                        logging.info(f"[REGEX MATCH] Responded by: {url_enrich[:-1]}")
                                        try:
                                            current_socket.send(url_enrich.encode())
                                        except BrokenPipeError:
                                            print("Broken pipe error while sending data")
                                            logging.error("Broken pipe error while sending data")
                                except error:
                                    continue
                                    #print(f"Error compiling regex: {e} key is {key}")
                current_socket.send("\nLookupFinished".encode())
                #current_socket.send("LookupFinished".encode())
            connected_sockets.remove(current_socket)
            current_socket.close()
    
        if not client_data:
            connected_sockets.remove(current_socket)
            current_socket.close()


def main(mode, feed_file, key_field):
    """server setup and socket handling"""
    
    feed_dict={}
    feed_dict_regex={}

    if mode in (1, 2):
        if not isfile(feed_file):
            print(f"The file {feed_file} does not exist.")
            logging.error(f"The file {feed_file} does not exist.")
            exit(1)
        
        feed_file_ext = get_file_extension(feed_file)

        if feed_file_ext == ".csv":
            print(f"Working with feed_file {feed_file}, please wait ...")
            logging.info(f"Working with feed_file {feed_file}, please wait ...")
            feed_dict = load_csv_to_dict(feed_file, key_field)
            print(f"Loaded {len(feed_dict.keys())} iocs")
            logging.info(f"Loaded {len(feed_dict.keys())} iocs")
        elif feed_file_ext == ".json":        
            print(f"Working with feed_file {feed_file}, please wait ...")
            logging.info(f"Working with feed_file {feed_file}, please wait ...")
            feed_dict = load_json_to_dict(feed_file, key_field)
            print(f"Loaded {len(feed_dict.keys())} iocs")
            logging.info(f"Loaded {len(feed_dict.keys())} iocs")
        else:
            print(f"Not supported file extension {feed_file}.")
            logging.error(f"Not supported file extension {feed_file}.")
            exit(1)
        
        if mode == 2:
            print(f"Dumping file {feed_file}")
            logging.info(f"Dumping file {feed_file}")
            dump_feed_file = feed_file + ".tracer"
            with open(dump_feed_file, 'wb') as file:
                pickle.dump(feed_dict, file)
            print(f"Dumped file {feed_file} with name {dump_feed_file}, size {getsize(dump_feed_file)/1024/1024} Mb")
            logging.info(f"Dumped file {feed_file} with name {dump_feed_file}, size {getsize(dump_feed_file)/1024/1024} Mb")
            exit(0)

    if mode == 3:
        for files in feed_file:
            print(f"Working with feed_file {files}, please wait ...")
            logging.info(f"Working with feed_file {files}, please wait ...")
            with open(files, 'rb') as file:
                feeds = pickle.load(file)
                print(f"Loaded {len(feeds.keys())} iocs")
                logging.info(f"Loaded {len(feeds.keys())} iocs")
                feed_dict.update(feeds)
        print(f"Total loaded {len(feed_dict.keys())} iocs")
        logging.info(f"Total loaded {len(feed_dict.keys())} iocs")

        print("Searching feeds with regex ...")
        logging.info("Searching feeds with regex ...")
        feed_dict_regex_tmp = search_in_dict_keys(feed_dict,'*')
        for key, value in feed_dict_regex_tmp.items():
            key = key.replace(".", r"\.")
            key = key.replace("/", r"\/")
            key = key.replace("(", r"\(")
            key = key.replace(")", r"\)")
            key = key.replace("?", r"\?")
            key = key.replace("*", r".*")
            regex_key = r'^(https?:\/\/|www\.|){}'.format(key)
            try:
                # Compiling regex for boost
                feed_dict_regex[compile(regex_key)] = value
            except error as e:
                #print(f"Error compiling regex: {e} key is {regex_key}")
                logging.error(f"Error compiling regex: {e} key is {regex_key}")
                continue
        feed_dict_regex_tmp={}
        print(f"Feeds with regex: {len(feed_dict_regex.keys())} iocs")
        logging.info(f"Feeds with regex: {len(feed_dict_regex.keys())} iocs")

        # START test block for search
        '''
        print("searching...")
        print(datetime.now())
        search_feed = search_in_dict_keys(feed_dict, 'telosalliance.info')
        print(search_feed)
        print(feed_dict["ECF335B94B983EA654D4A4CD5119B837"])
        print(datetime.now())
        
        print(datetime.now())
        with open("feed_dict_regexRE.txt", 'w') as file:
            for key, value in feed_dict_regex.items():
                file.write(f"{key}: {value}\n")
        '''
        # END test block for search
    
    print("Setting up server...")
    logging.info("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # For server TCP_FASTOPEN
    # echo 3 > /proc/sys/net/ipv4/tcp_fastopen
    # and you can set the timeout to 1 second by doing this: echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if platform != 'win32':
        server_socket.setsockopt(socket.SOL_TCP, 23, 5) # here 23 is the protocol number of TCP_FASTOPEN
    server_socket.bind(ADDR)
    server_socket.listen()

    print("\n* Server is ON *\n")
    logging.info("Server is ACTIVE")
    print(f"Listening {ADDR}. Waiting for clients to establish connection...")
    logging.info(f"Listening {ADDR}. Waiting for clients to establish connection...")
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
                    current_socket, server_socket, connected_sockets, starttime, mode, feed_dict, feed_dict_regex
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
    parser = OptionParser(description='Tracer. Universal KUMA event enrichment. KUMA-Community (c). Version: {0}'.format(__version__), usage="\n\Tracer.py --feed_file=%input_File_FullPath% OR --custom_mode\nExample:\n\Tracer.py --feed_file=/opt/feeds/Feeds.csv -k ioc_column\nTracer.py -l IP_Reputation.json.tracer -l Phishing_URL.json.tracer\n\nTracer.py -d IP_Reputation.json", version='Tracer v.{0}'.format(__version__))
    parser.add_option('-f', '--feed_file', type="string", help='Load feed from single file CSV to Tracer', dest="feed_file", metavar="FILE")
    parser.add_option('-k', '--key_field', type="string", help='Key field from file CSV or JSON', dest="key_field")
    parser.add_option('-d', '--dump', type="string", dest="dump_feed", help='Dump feed to dict with saving to file', metavar="FILE")
    parser.add_option('-l', '--load', action='append', dest="load_feed", help='Loading feed from file to dict', metavar="FILE")
    parser.add_option('-c', '--custom_mode', action="store_true", default=True, dest="custom_mode", help='Use your own functions for enrichment. See example in this code \"def url_decoder_enrich\"')
    options, args = parser.parse_args()
    mode = 0
    feed_file = ""
    print(options)
    logging.info(f"[START] Tracer v{__version__} is starting with options: {options}")
    if not options.feed_file and not options.dump_feed and not options.load_feed:
        print("\n\nExecuting custom_mode mode (default)\n")
        logging.info("[START] Executing custom_mode mode (default)")
        mode = 0
    elif options.custom_mode and options.feed_file is not None and options.key_field is not None and not options.load_feed:
        print("\n\nExecuting feed_file mode\n")
        logging.info("[START] Executing feed_file mode")
        mode = 1
        feed_file = options.feed_file
    elif options.custom_mode and options.feed_file is None and options.key_field is not None and options.load_feed is None and options.dump_feed is not None:
        print("\n\nDumping feed_file mode\n")
        logging.info("[START] Dumping feed_file mode")
        mode = 2
        feed_file = options.dump_feed
    elif options.custom_mode and options.feed_file is None and options.key_field is None and options.load_feed is not None and options.dump_feed is None:
        print("\n\nLoading feed_file mode\n")
        logging.info("[START] Loading feed_file mode")
        mode = 3
        feed_file = options.load_feed
    else:
        parser.print_help()
        parser.error("Incorrect number of arguments")
        logging.error("[START] Incorrect number of arguments")
        exit(1)
    main(mode, feed_file, options.key_field)
