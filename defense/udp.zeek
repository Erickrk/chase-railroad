global threshold: count = 70;
global detection_counter: count = 0;

event zeek_init()
{
    print "Zeek 6.0 packet detection and dropping script started.";
}

event new_packet(c: connection, p: pkt_hdr)
{
    if (c$id$resp_h == 192.168.3.39 && p$udp$ulen > 10)
    {
        ++detection_counter;
        if (detection_counter == 1)
        {
            print fmt("Packet detected with destination IP 192.168.3.39: %s", p);
        }
        if (detection_counter%100 == 0)
        {
            print fmt("100 more packet detected with destination IP 192.168.3.39: %s", p);
        }
        #NetControl::drop_packet(p);
        NetControl::drop_connection(c$id, 1sec);
        #NetControl::drop_address(c$id$resp_h, 300sec);
    }
}
