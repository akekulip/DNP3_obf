



event bro_init() {
    local v1: vector of double;
    local s1: string = "";

    v1[0] = 0.01;
    v1[1] = 0.02;
    v1[2] = 0.03;

    for (k in v1) {
        s1 = cat(s1, k, " ");
    }
    print s1;
}

