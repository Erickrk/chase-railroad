# File: print_tcp_requests.zeek

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
    {
    print fmt("TCP packet from %s:%d to %s:%d - Flags: %s, Seq: %d, Ack: %d, Len: %d",
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, flags, seq, ack, len);
    }

event zeek_init()
    {
    print "TCP request monitoring script loaded.";
    }
