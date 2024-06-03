@load base/frameworks/notice

const modbus_ip = 192.168.2.3;
const modbus_port = 502/tcp;
const s7comm_port = 102/tcp;
const opcua_port = 4840/tcp;
const specific_src_ip = 192.168.2.4;

const python_script = "/home/chase/Desktop/OT_network_security/attack_scripts/modbus/mitigate_modbus.py";

global modbus_conns: set[addr, port] = {};
global s7comm_conns: set[addr, port] = {};
global opcua_conns: set[addr, port] = {};
global flood_threshold = 1000; # Threshold for flooding attack detection
global connection_counts: table[addr] of count;

event connection_established(c: connection)
    {
   
    if (c$id$resp_h == modbus_ip && c$id$resp_p == modbus_port)
        {
        add modbus_conns[c$id$orig_h, c$id$orig_p];
        }
    if (c$id$resp_p == s7comm_port)
        {
        add s7comm_conns[c$id$orig_h, c$id$orig_p];
        }
    if (c$id$resp_p == opcua_port)
        {
        add opcua_conns[c$id$orig_h, c$id$orig_p];
        }

    # Track connection counts for flooding detection
    if (c$id$orig_h in connection_counts)
        connection_counts[c$id$orig_h] += 1;
    else
        connection_counts[c$id$orig_h] = 1;

    if (connection_counts[c$id$orig_h] > flood_threshold)
        {
        print fmt("Potential flooding attack detected from %s", c$id$orig_h);
        }
    }

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
    {
    if (c$id$orig_h == modbus_ip)
        {
        if (c$id$resp_h == modbus_ip && c$id$resp_p == modbus_port)
            {
            if (len > 7)
                {
                print "WARNING! Detected modbus packet. Checking the runway status..";
                system(fmt("python2.7 %s", python_script));
                }
            }
        if (c$id$resp_p == s7comm_port)
            {
            if (c$id$resp_h != 192.168.2.4 || c$id$resp_h != 192.168.2.3) {
            # Basic detection of S7comm packet
            print "WARNING! Detected s7Comm packet. Checking the runway status..";
            
            system(fmt("python2.7 %s", python_script));
            }
            }
        if (c$id$resp_p == opcua_port)
            {
            # Basic detection of OPC UA packet
            print "WARNING! Detected OpcUA packet. Checking the runway status..";
            system(fmt("python2.7 %s", python_script));
            }
       }
    
    }
    
   
#event arp_request(c: connection, src: addr, target: addr)
#    {
#    # ARP poisoning detection
#    if (src != target)
#        {
#        print fmt("Potential ARP poisoning attack detected: ARP request from %s to %s", src, target);
#        }
#    }

event zeek_init()
    {
    print "Modbus, S7comm, OPC UA monitoring, flooding detection, and ARP poisoning detection script loaded.";
    }

event zeek_done()
    {
    # Clear the connection counts
    connection_counts = {};
    }








