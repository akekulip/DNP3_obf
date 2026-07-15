
redef tcp_content_delivery_ports_orig +={ [20000/tcp] = T };
redef tcp_content_delivery_ports_resp +={ [20000/tcp] = T };

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    #print "fuck God"
    print "tcp contents", network_time(), c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, is_orig, flags, seq, ack, len;
}

