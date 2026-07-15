

redef tcp_content_delivery_ports_orig +={ [20000/tcp] = T };
redef tcp_content_delivery_ports_resp +={ [20000/tcp] = T };

global req_time: table[addr] of table[count] of time;  # indexed by IP and then by ack
global last_fc: table[addr] of count; 
global lat: table[addr] of table[count] of vector of double;
global cur_seq : count = 0;
global cur_ack : count = 0;

global latency_log = open_log_file("latency");

function hl_mean(v1: vector of double): double {
    local sum : double = 0.0;
    for (k in v1) {
        sum = sum + v1[k];
    }
    print sum;
    return (sum / |v1|);
}

function hl_stdev(v1: vector of double): double {
    local mean: double = 0.0;
    local sqsum : double = 0.0;

    mean = hl_mean(v1);
    for (k in v1) {
        sqsum = sqsum + (v1[k] - mean)*(v1[k] - mean);
    }

    return sqrt(sqsum / |v1|);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {

    print "tcp contents", network_time(), c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, is_orig, flags, seq, ack, len;

    cur_ack = ack;
    cur_seq = seq;

}

event dnp3_application_request_header(c: connection, is_orig: bool, application_control: count, fc: count) {
    
    print "dnp3 application request", network_time(), c$id$orig_h, c$id$resp_h;
    # record ack for each ip
    if (c$id$resp_h !in req_time){
        req_time[c$id$resp_h] = table();
    }
    if (cur_ack !in req_time[c$id$resp_h]){
        req_time[c$id$resp_h][cur_ack] = network_time();
    }

    last_fc[c$id$resp_h] = fc;

}

event dnp3_application_response_header(c: connection, is_orig: bool, application_control: count, fc: count, iin: count) {

    print "dnp3 application response", network_time(), c$id$orig_h, c$id$resp_h;

    if (c$id$resp_h !in req_time) {
        print "ALERT not ip in req_time";
        #print c$id$orig_h;
        #print req_time;
    } else {
        if (cur_seq !in req_time[c$id$resp_h]) {
            print "ALERT no reqeust is found before";
        } else {
            if (c$id$resp_h !in lat) {
                lat[c$id$resp_h] = table();
                if (last_fc[c$id$resp_h] !in lat[c$id$resp_h]) {
                    lat[c$id$resp_h][last_fc[c$id$resp_h]] = vector();
                }
            }
            lat[c$id$resp_h][last_fc[c$id$resp_h]][ |lat[c$id$resp_h][last_fc[c$id$resp_h]]| ]  = 
                        interval_to_double(network_time() - req_time[c$id$resp_h][cur_seq]);
        }
    }
}

event bro_done() {
    
    local s1: string = "";
    local v1: vector of double;
    
    #for (k in req_time) {
    #    print k;
    #    for ( kk in req_time[k]) {
    #        print kk, req_time[k][kk];
    #    }
    #}

    for (ip in lat) {
        print fmt("");
        s1 = "";
        for (fc in lat[ip]) {
            #print lat[ip][fc];
            for (kk in lat[ip][fc]) {
                s1 = cat(s1, lat[ip][fc][kk], " ");
            }
        }
        print s1;
        print latency_log, s1;
    }

    # test function
    v1[0] = 1.0;
    v1[1] = 2.0;
    v1[2] = 2.5;
    print hl_mean(v1), hl_stdev(v1);

}
