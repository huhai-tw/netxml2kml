#!/usr/bin/env python3
# netxml2kml.py - Python 3 version
# Process Kismet netxml files into Google Earth KML for visualization.

import xml.etree.cElementTree as xml
import sqlite3 as sql
import os, sys, getopt
from os.path import exists
from datetime import datetime
from xml.sax.saxutils import escape

database = os.path.expanduser('~/.netxml/wireless.db')
runtime = ""
total_discovered = 0
total_saved = 0
total_updated = 0
total_exported = 0

def welcome():
    print("\n*****************************************************************")
    print("* netxml2kml, a Kismet netxml file parser                       *")
    print("* Use this script to import networks from a Kismet .netxml file *")
    print("* or to export them to a Google Earth .kml file                 *")
    print("*****************************************************************\n")

def usage():
    print("Usage: netxml2kml [options]")
    print("   Options: can be either import (-i) or export (-x).")
    print("          -i <XML input file>   # Input file has to be Kismet .netxml")
    print("          -x <KML export file>  # Export file can have optional -q SQL query")
    print("             -q '<SQL query>'   # (formatted for Sqlite)")
    print("             -c [Restricts export to networks with attached clients]\n")
    print("Examples:\n"
          "          netxml2kml -i kismet-output-file.netxml\n"
          "          netxml2kml -x all-database-contents.kml\n"
          "          netxml2kml -x strong_wep.kml -c \\\n"
          "              -q \"SELECT * FROM networks WHERE max_signal_dbm > -60 AND encryption = 'WEP'\"")

### SECTION 1: Loading networks from Kismet netxml

# Open xml file and load it into a etree.ElementTree object
# Create a list of tree nodes that contain infrastructure networks
# Parse xml into a list of dictionaries with all important network data
def load_nets_from_xml(xfile):
    global total_discovered, runtime
    netnodes = []
    netlist_dicts = []
    clientlist = []

    print(f"Reading network information from {xfile}\n")

    # Open Kismet .netxml file and load into list of nodes
    try:
        with open(xfile, 'rt', encoding='utf-8', errors='ignore') as kismet:
            try:
                tree = xml.parse(kismet)
            except xml.ParseError as xmlerr:
                print("\n*** ERROR *** Problem parsing input file.")
                print("               Is it a Kismet netxml file?")
                print(f"               Python says: {xmlerr}\n")
                usage()
                sys.exit(2)
    except IOError as ioerr:
        print("\n*** ERROR *** Cannot read input file. Does it exist?")
        print(f"\tPython says: {ioerr}\n")
        usage()
        sys.exit(2)

    for node in tree.iter('detection-run'):
        runtime = node.attrib.get('start-time')

    if runtime_exists():
        print(f"This detection run ({runtime}) has already been imported")
        sys.exit()

    netnodes = pop_xml_netlist(tree)
    # For each wireless network node, create a dictionary, and append it to
    # a list of network dictionaries
    for node in netnodes:
        netlist_dicts.append(populate_net_dict(node))
        populate_client_list(node, clientlist)
    total_discovered = len(netnodes)
    print("")

    return netlist_dicts, clientlist

# Check if the Kismet run being imported has a start-time that is already
# in the database
def runtime_exists():
    exists_flag = False
    con = sql.connect(database)
    with con:
        cur = con.cursor()
        try:
            cur.execute("SELECT * FROM run")
            db_run_time = cur.fetchall()
            for rtime in db_run_time:
                if (runtime != "") and (runtime in rtime):
                    exists_flag = True
        except sql.OperationalError as err:
            if "no such table" in str(err):
                exists_flag = False
    return exists_flag

# Function to return a list of eTree nodes. Takes the whole XML tree as the
# argument and returns a list[] of nodes containing only infrastructire networks
def pop_xml_netlist(whole_tree):
    nodelist = []
    for node in whole_tree.findall('.//wireless-network'):
        if node.attrib.get('type') == 'infrastructure':
            nodelist.append(node)
    if len(nodelist) == 0:
        print("\n+++ WARNING +++  There don't seem to be any wireless networks in your input file\n")
        usage()
        sys.exit()
    return nodelist

# Create a list of clients. Each client is a list of the router bssid,
# the client MAC and the client max_signal
def populate_client_list(wireless_node, client_list):
    bssid = ""
    for lev1 in wireless_node:
        if lev1.tag == 'BSSID':
            bssid = lev1.text
        if lev1.tag == 'wireless-client':
            cldata = []
            if lev1.attrib.get('type') != 'fromds':
                cldata.append(bssid)
                for clientinfo in lev1:
                    if clientinfo.tag == 'client-mac':
                        cldata.append(clientinfo.text)
                    if clientinfo.tag == 'snr-info':
                        for snr in clientinfo:
                            if snr.tag == 'max_signal_dbm':
                                cldata.append(snr.text)
            if len(cldata) > 0:
                client_list.append(cldata)

# Populate values of network dictionary from xml node
def populate_net_dict(wireless_node):
    wn = make_net_dict()
    wn['wn_num'] = wireless_node.attrib['number']
    wn['first_seen'] = wireless_node.attrib['first-time']
    wn['last_seen'] = wireless_node.attrib['last-time']
    wn['placeholder_encryption'] = []
    wn['clients'] = []

    # Iterate through first-level nodes and fill values into empty dictionary
    for lev1 in wireless_node:

        # Append the MAC address of clients as a list
        if lev1.tag == 'wireless-client':
            for cinfo in lev1:
                for ctag in cinfo.iter('client-mac'):
                    wn['clients'].append(ctag.text)

        # Loop through second-level nodes in SSID
        if lev1.tag == 'SSID':
            for ssid_info in lev1:
                # assign multiple ecryption fields to a temporary list
                for e in ssid_info.iter('encryption'):
                    wn['placeholder_encryption'].append(e.text)

                if ssid_info.tag == 'type': wn['ssid_type'] = ssid_info.text
                if ssid_info.tag == 'max-rate': wn['max_speed'] = ssid_info.text
                if ssid_info.tag == 'packets': wn['packets'] = ssid_info.text
                if ssid_info.tag == 'beaconrate': wn['beaconrate'] = ssid_info.text
                if ssid_info.tag == 'wps': wn['wps'] = ssid_info.text
                if ssid_info.tag == 'wps-manuf': wn['wps_manuf'] = ssid_info.text
                if ssid_info.tag == 'dev-name': wn['dev_name'] = ssid_info.text
                if ssid_info.tag == 'model-name': wn['model_name'] = ssid_info.text
                if ssid_info.tag == 'model-num': wn['model_num'] = ssid_info.text
                if ssid_info.tag == 'wpa-version': wn['ssid_wpa_version'] = ssid_info.text
                if ssid_info.tag == 'essid':
                    if ssid_info.attrib.get('cloaked') == 'true':
                        wn['essid'] = ""
                    else: # Replace some characters that cause problems in KML
                        tempessid = ssid_info.text if ssid_info.text else ""
                        wn['essid'] = tempessid.replace('&', '').replace('<', '').replace('>', '')
                    wn['cloaked'] = ssid_info.attrib.get('cloaked')

        if lev1.tag == 'BSSID':
            wn['bssid'] = lev1.text
        if lev1.tag == 'manuf':
            wn['manuf'] = lev1.text
        if lev1.tag == 'channel':
            wn['channel'] = lev1.text
        if lev1.tag == 'maxseenrate':
            wn['maxseenrate'] = lev1.text

        # Loop through snr information
        if lev1.tag == 'snr-info':
            for snr_info in lev1:
                if snr_info.tag == 'max_signal_dbm':
                    wn['max_signal_dbm'] = snr_info.text
                if snr_info.tag == 'max_noise_dbm':
                    wn['max_noise_dbm'] = snr_info.text

        # Loop through GPS information
        if lev1.tag == 'gps-info':
            for gps_info in lev1:
                if gps_info.tag == 'peak-lat':
                    wn['peak_lat'] = gps_info.text
                if gps_info.tag == 'peak-lon':
                    wn['peak_lon'] = gps_info.text
    # select appropriate text for encryption field
    wn['encryption'] = populate_encryption(wn['placeholder_encryption'])

    print(f"Found infrastructure network with BSSID: {wn['bssid']} - encryption: {wn['encryption']}")
    return wn

# Create an empty network dictionary with all needed keys
def make_net_dict():
    keys = ['wn_num',
            'first_seen',
            'last_seen',
            'ssid_type',
            'max_speed',
            'packets',
            'beaconrate',
            'wps',
            'wps_manuf',
            'dev_name',
            'model_name',
            'model_num',
            'placeholder_encryption',
            'encryption',
            'ssid_wpa_version',
            'cloaked',
            'essid',
            'bssid',
            'manuf',
            'channel',
            'maxseenrate',
            'max_signal_dbm',
            'max_noise_dbm',
            'clients',
            'peak_lat',
            'peak_lon']
    return {key: None for key in keys}

# based in the entries in placeholder_encryption, return correct text
def populate_encryption(placeholder_list):
    if 'WEP' in placeholder_list and 'WPA' in placeholder_list:
        return 'WEP + WPA'

    if 'WEP' in placeholder_list:
        return 'WEP'
    
    if 'WPA+TKIP' in placeholder_list and 'WPA+PSK' in placeholder_list:
        return 'WPA+TKIP/PSK'
    
    if 'WPA+TKIP' in placeholder_list:
        return 'WPA+TKIP'
    
    if 'WPA+PSK' in placeholder_list:
        return 'WPA+PSK'
    if 'WPA+AES-CCM' in placeholder_list:
        return 'WPA-MGT'
    
    return 'OPEN'

### SECTION 2: Saving networks to a sqlite3 database

# Open connection to database and loop through networks,
# adding appropriate ones to the database. Mostly self-explanatory
def save_nets_to_db(netlist, clientlist, dfile):
    global total_saved
    con = sql.connect(dfile)
    with con:
        create_tables(con)
        for net in netlist:
            process_network(net, con)
        for client in clientlist:
            save_client(client, con)
        save_detection_run(dfile, con)

# If networks table does not exist, create empty table in database
def create_tables(con):
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS networks(
            wn_num INT,
            bssid TEXT,
            essid TEXT,
            encryption TEXT,
            ssid_wpa_version TEXT,
            ssid_type TEXT,
            packets INT,
            beaconrate INT,
            wps TEXT,
            wps_manuf TEXT,
            dev_name TEXT,
            model_name TEXT,
            model_num TEXT,
            cloaked TEXT,
            manuf TEXT,
            channel INT,
            first_seen TEXT,
            last_seen TEXT,
            max_speed INT,
            maxseenrate INT,
            max_signal_dbm INT,
            max_noise_dbm INT,
            peak_lat TEXT,
            peak_lon TEXT)
    """)
    cur.execute("CREATE TABLE IF NOT EXISTS run(start_time TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS clients(bssid TEXT, client_mac TEXT, client_max_sig INT)")

# Insert a client into the database if it doesn't already exist
def save_client(client, con):
    if not check_if_client_exists(client, con):
        cur = con.cursor()
        cur.execute("INSERT INTO clients VALUES(?, ?, ?)", client)
        print(f"Adding client with MAC: {client[1]} to database")

# Check if client already exists in database
def check_if_client_exists(client, con):
    bssid, mac = client[0], client[1]

    cur = con.cursor()
    cur.execute("SELECT bssid, client_mac FROM clients WHERE bssid=? AND client_mac=?", (bssid, mac))
    return cur.fetchone() is not None

# Check if network exists in database.
# If it exists, and stored network is weaker, erase it and save new data.
def process_network(netdict, con):
    global total_saved, total_updated

    if not check_if_net_exists(netdict, con):
        add_it_to_db(netdict, con)
        print(f"Adding wireless network with BSSID: {netdict['bssid']} to database")
        total_saved += 1

    else:
        stronger = netpower(netdict, con)
        newer = xml_newer_than_db(netdict, con)
        total_updated += 1
        if newer:
            if stronger:
                new_net_stronger(netdict, con)
            else:
                new_net_weaker(netdict, con)
        else:
            if stronger:
                old_net_stronger(netdict, con)
            else:
                old_net_weaker(netdict, con)

# Check if MAC address of network already in DB
def check_if_net_exists(netdict, con):
    cur = con.cursor()
    cur.execute("SELECT bssid FROM networks WHERE bssid=?", (netdict['bssid'],))
    return cur.fetchone() is not None

# Check if xml network datestamp is more recent than in the database
def xml_newer_than_db(netdict, con):
    xml_last_seen = datetime.strptime(netdict['last_seen'], "%a %b %d %H:%M:%S %Y")
    cur = con.cursor()
    cur.execute("SELECT last_seen FROM networks WHERE bssid = ?", (netdict['bssid'],))

    # Load DB date fields into datetime objects
    db_last_seen_str = cur.fetchone()[0]
    db_last_seen = datetime.strptime(db_last_seen_str, "%a %b %d %H:%M:%S %Y")
    return xml_last_seen > db_last_seen

# Check if xml network signal is stronger than in the database
def netpower(netdict, con):
    maxsig = int(netdict['max_signal_dbm'])
    cur = con.cursor()
    cur.execute("SELECT max_signal_dbm FROM networks WHERE bssid = ?", (netdict['bssid'],))
    row = cur.fetchone()
    db_strength = int(row[0]) if row else -999
    return maxsig > db_strength

# When wireless network is not already in the DB, save it
def add_it_to_db(netdict, con):
    netlist = make_ordered_netlist(netdict)
    cur = con.cursor()
    cur.execute("INSERT INTO networks VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", netlist)

# When wireless network is newer and weaker than same bssid in DB
# then update 'last_seen' to latest timestamp
def new_net_weaker(netdict, con):
    cur = con.cursor()
    cur.execute("UPDATE networks SET last_seen = ? where bssid = ?", (netdict['last_seen'], netdict['bssid']))
    print(f"Updating 'last_seen' field on {netdict['bssid']} to newer timestamp")

# When wireless network is newer and stronger than same bssid in DB
# then overwrite db with all new data except 'first_seen'
def new_net_stronger(netdict, con):
    cur = con.cursor()
    cur.execute("SELECT first_seen FROM networks WHERE bssid = ?", (netdict['bssid'],))
    db_first_seen = cur.fetchone()[0]
    delete_net_from_db(netdict, con)
    netdict['first_seen'] = str(db_first_seen)
    add_it_to_db(netdict, con)
    print(f"Updating wireless network with BSSID: {netdict['bssid']} to stronger version")

# When wireless network is older and weaker than same bssid in DB
# then update 'first_seen' to earliest timestamp
def old_net_weaker(netdict, con):
    cur = con.cursor()
    cur.execute("UPDATE networks SET first_seen = ? where bssid = ?", (netdict['first_seen'], netdict['bssid']))
    print(f"Updating 'first_seen' field on {netdict['bssid']} to older timestamp")

# When wireless network is older and stronger than same bssid in DB
# then overwrite db with all new data except 'last_seen'
def old_net_stronger(netdict, con):
    cur = con.cursor()
    cur.execute("SELECT last_seen FROM networks WHERE bssid = ?", (netdict['bssid'],))
    db_last_seen = cur.fetchone()[0]
    delete_net_from_db(netdict, con)
    netdict['last_seen'] = str(db_last_seen)
    add_it_to_db(netdict, con)
    print(f"Updating wireless network with BSSID: {netdict['bssid']} to stronger version")

# Save detection run start time
def save_detection_run(dfile, con):
    cur = con.cursor()
    cur.execute("INSERT INTO run VALUES(?)", (runtime,))
    print(f"Added runtime ({runtime}) to database")

# Turn each net dictionary into a list, return list
def make_ordered_netlist(netdict):
    return (
        int(netdict['wn_num']),
        netdict['bssid'],
        netdict['essid'],
        netdict['encryption'],
        netdict['ssid_wpa_version'],
        netdict['ssid_type'],
        netdict['packets'],
        netdict['beaconrate'],
        netdict['wps'],
        netdict['wps_manuf'],
        netdict['dev_name'],
        netdict['model_name'],
        netdict['model_num'],
        netdict['cloaked'],
        netdict['manuf'],
        int(netdict['channel']),
        netdict['first_seen'],
        netdict['last_seen'],
        netdict['max_speed'],
        int(float(netdict['maxseenrate'])),
        int(float(netdict['max_signal_dbm'])),
        int(float(netdict['max_noise_dbm'])),
        netdict['peak_lat'],
        netdict['peak_lon']
    )

# Erase existing weaker networks from db
def delete_net_from_db(netdict, con):
    cur = con.cursor()
    cur.execute("DELETE from networks WHERE bssid = ?", (netdict['bssid'],))

### SECTION 3: Loading networks from database to create KML

# Load every network in the database.
def load_all_nets_from_db(dfile, clist, conly):
    netlist = []
    client_bssids = [c[0] for c in clist]
    con = sql.connect(dfile)
    with con:
        con.row_factory = sql.Row
        cur = con.cursor()
        cur.execute("SELECT * from networks")
        for row in cur.fetchall():
            if conly and row['bssid'] not in client_bssids: continue
            netlist.append(parse_db_row(row))
    return netlist

# Load networks that match a specific SQL query
def load_from_db_with_sql_arg(dfile, sql_arg, clist, conly):
    netlist = []
    client_bssids = [c[0] for c in clist]
    con = sql.connect(dfile)
    
    with con:
        con.row_factory = sql.Row
        cur = con.cursor()
        try:
            cur.execute(sql_arg)
            for row in cur.fetchall():
                if conly and row['bssid'] not in client_bssids: continue
                netlist.append(parse_db_row(row))
        
        except sql.OperationalError as err:
            print(f"Error: Your SQL query could not be interpreted\n--->\t {sql_arg}")
            print(f"Python says: '{err}'\n")
            usage()
            sys.exit(2)
    return netlist

# Load all clients in the database into a list
def load_clients(dfile):
    con = sql.connect(dfile)
    with con:
        cur = con.cursor()
        cur.execute("SELECT * from clients")
        return [list(row) for row in cur.fetchall()]

# Parse rows of database into dictionary
def parse_db_row(row):
    wndb = make_net_dict()
    for item in row.keys():
        wndb[item] = row[item]
    return wndb

### SECTION 4: Crafting KML
# Assemble all the KML pieces into a list with one line per list item
def make_kml(netlist, clientlist, query):
    kmllist = []
    kmllist = create_kml_headers(kmllist, query)
    kmllist = append_kml_styles(kmllist, netlist)
    kmllist = append_kml_placemarks(kmllist, netlist, clientlist)
    kmllist = close_kml(kmllist)
    return kmllist

# Create header rows
def create_kml_headers(kmllist, query):
    kmllist.append('<?xml version="1.0" encoding="UTF-8"?>')
    kmllist.append('<kml xmlns="http://www.opengis.net/kml/2.2">')
    kmllist.append('\t<Document>')
    kmllist.append('\t\t<name>Wireless Networks</name>')
    desc = escape(query) if query else "Wireless networks parsed from Kismet xml"
    kmllist.append(f'\t\t<description>{desc}</description>')
    return kmllist

# For every encryption type found in query, create a style
def append_kml_styles(kmllist, netlist):
    netcolours = {'WEP':'0090FF', 'WPA':'0000FF', 'OPEN':'00FF00'}
    encryptions = set()
    for n in netlist:
        if 'WEP' in n['encryption']: encryptions.add('WEP')
        if 'WPA' in n['encryption']: encryptions.add('WPA')
        if 'OPEN' in n['encryption']: encryptions.add('OPEN')

    for e in encryptions:
        for suffix, alpha in [("broadcasting", "ff"), ("cloaked", "7f")]:
            kmllist.append(f'\t\t<Style id="{e} {suffix}">')
            kmllist.append('\t\t\t<IconStyle>')
            kmllist.append(f'\t\t\t\t<color>{alpha}{netcolours[e]}</color>')
            kmllist.append('\t\t\t\t<scale>1</scale>')
            kmllist.append('\t\t\t\t<Icon><href>http://maps.google.com/mapfiles/kml/shapes/target.png</href></Icon>')
            kmllist.append('\t\t\t</IconStyle>')
            kmllist.append('\t\t</Style>')
    return kmllist

# Create KML Placemark text and append to list for every network in query
def append_kml_placemarks(kmllist, netlist, clientlist):
    global total_exported
    kmllist.append('\t\t<Folder>\n\t\t\t<name>Placemarks</name>')
    for net in netlist:
        clients_in_net = [c for c in clientlist if c[0] == net['bssid']]
        client_html = f'Clients: {len(clients_in_net)}<br>'
        for client in clients_in_net:
            client_html += f'{client[1]} ({client[2]})<br>'

        kmllist.append('\t\t\t<Placemark>')
        name = escape(net['essid']) if net['essid'] else ""
        kmllist.append(f'\t\t\t\t<name>{name}</name>')
        
        style = "OPEN"
        if 'WEP' in net['encryption']: style = "WEP"
        elif 'WPA' in net['encryption']: style = "WPA"
        
        state = "cloaked" if net['cloaked'] == 'true' else "broadcasting"
        kmllist.append(f'\t\t\t\t<styleUrl>#{style} {state}</styleUrl>')
        
        kmllist.append(f'\t\t\t\t<description><![CDATA[BSSID:{net["bssid"]}<br>{net["last_seen"]}<br>'
                       f'Encryption: {net["encryption"]}<br>Channel: {net["channel"]}<br>Signal: {net["max_signal_dbm"]}<br>'
                       f'{client_html}]]></description>')
        kmllist.append(f'\t\t\t\t<Point><coordinates>{net["peak_lon"]},{net["peak_lat"]},0</coordinates></Point>')
        kmllist.append('\t\t\t</Placemark>')
        print(f"Found network with BSSID: {net['bssid']} ** Exporting to KML file")
        total_exported += 1
    kmllist.append('\t\t</Folder>')
    return kmllist

# Add the closing lines
def close_kml(kmllist):
    kmllist.append('\t</Document>\n</kml>')
    return kmllist

# Save KML list to file one row at a time
def kml_to_file(kml, filename):
    if check_write(filename):
        with open(filename, "w", encoding='utf-8') as f:
            for line in kml:
                f.write(f"{line}\n")

# Check if KML file already exists. If so, ask if OK to overwrite.
def check_write(filename):
    if exists(filename):
        print(f"\nFile {filename} already exists at this location.")
        action = input("Overwrite? (y/N)\t")
        if action.lower() in ('y', 'yes'): return True
        else:
            print("Ok (quitting)")
            sys.exit(2)
    return True

### SECTION 5: Main
def main(argv):
    query = ''
    with_clients_only = False
    welcome()

    try:
        opts, args = getopt.getopt(argv, "hi:x:q:c")
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    if not opts:
        usage()
        sys.exit()

    for opt, arg in opts:
        if opt == "-q": query = arg
        if opt == "-c": with_clients_only = True
        if opt == '-h':
            usage()
            sys.exit()

    for opt, arg in opts:
        if opt == "-i":
            netlist, clientlist = load_nets_from_xml(arg)
            save_nets_to_db(netlist, clientlist, database)
            print(f"\nFound {total_discovered} wireless networks in Kismet netxml file")
            print(f"Added {total_saved} wireless networks to SQL database")
            print(f"Updated {total_updated} wireless networks in SQL database\n")
        elif opt == "-x":
            clientlist = load_clients(database)
            if query:
                db_list = load_from_db_with_sql_arg(database, query, clientlist, with_clients_only)
            else:
                db_list = load_all_nets_from_db(database, clientlist, with_clients_only)
            kml_content = make_kml(db_list, clientlist, query)
            kml_to_file(kml_content, arg)
            print(f"\nExported {total_exported} networks to KML file")

if __name__ == "__main__":
    main(sys.argv[1:])
