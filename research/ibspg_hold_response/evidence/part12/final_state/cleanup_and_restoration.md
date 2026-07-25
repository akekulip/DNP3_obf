# Part 12 cleanup + switch restoration evidence

Recorded 2026-07-25T03:43:48Z.

## Residual-process check (before restore)
```
local   : no run_campaign / part12_trial process
Hulk    : no ibspg_p12_gen, no tcpdump
Vision  : no tcpdump
switch  : no ibspg_p12_read / setup / bfrt client; bf_switchd count = 1
(every pgrep hit was the pgrep command matching itself)
```

## Restoration
```
PRE : bf_switchd PID 139143 --conf-file /home/decps/part12/part12_abs.conf
ACT : sudo pkill -x bf_switchd (rc=0); sudo bash /home/decps/queue_microbench/launch_mb.sh
POST: bf_switchd PID 185496 --conf-file /home/decps/queue_microbench/out/queue_microbench_abs.conf
      bf_switchd count = 1
      fresh mb_switchd.log written 03:43
      bfrt: 'Binding with p4_name queue_microbench successful!!'
```

Restore target is queue_microbench_abs.conf per direction.md, NOT Part 11.

## Host reachability
```
switch  10.10.54.81  : ufispace OK
Vision  10.10.54.19  : vision OK
          addr eno1 10.10.54.19/24
          addr eno1 192.168.10.1/24
          addr eno2 10.10.54.166/24
Hulk    10.10.54.158 : hulk OK
```
