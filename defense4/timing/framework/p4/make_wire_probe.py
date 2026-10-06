"""Extract a non-deployable wire-only compile ablation from the full attempt."""
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent
s=(HERE/'case4_size_kernel.p4').read_text()
a=s.index(' // Singleton owner;');b=s.index(' apply {',a)
s=s[:a]+s[b:]
s=re.sub(r'@pa_(?:atomic|container_size)\([^\n]+\)\n','',s)
a=s.index('  if(m.direction!=8w0&&hdr.tcp.isValid()) {');b=s.index('{',a)+1;level=1
while level:
    if s[b]=='{':level+=1
    elif s[b]=='}':level-=1
    b+=1
s=s[:a]+s[b:]
s=s.replace('if(m.pad_committed==8w1)', 'if(m.allow==8w1)')
# Shipped SDK tna_checksum uses exclusive subtract/get for a residual.
# Subtract the full pseudo-header and TCP frame, with IPv4 total_len rather
# than TCP length. For valid fixed IHL=5 input the residual is -20 = 0xFFEB.
# This avoids mixing the target engine's VERIFY and RESIDUAL modes.
s=s.replace('tcp_check.add(', 'tcp_check.subtract(')
s=s.replace('tcp_check.subtract({10w0,hdr.ip.ihl,2w0});', '')
s=s.replace('m.tcp_valid=tcp_check.verify();', 'm.tcp_sum=tcp_check.get();')
# The shipped SDK example names this raw return value checksum_err_ipv4.
# Keep that error flag and compare it to false in eligibility, without a
# parser or match/action inversion assignment.
s=re.sub(r'\bip_valid\b', 'ip_error', s)
s=s.replace('&&m.ip_error&&', '&&(m.ip_error==false)&&')
s=s.replace(' apply {forwarding.apply();', ' apply {forwarding.apply();if(m.tcp_sum==16w0xFFEB) {m.tcp_valid=true;}')
s=s.replace('  insertion_profile.apply();', '  if(m.tcp_sum==16w0xFFEB) {m.tcp_valid=true;}\n  insertion_profile.apply();')
s='/* WIRE-ONLY COMPILE ABLATION: NO TCP LEDGER. MUST NEVER BE DEPLOYED.\n * This exists to distinguish CRC/layout fit from stateful translation fit.\n * Input IPv4/TCP checksum guards are present; target execution is unproved.\n */\n'+s
(HERE/'case4_wire_only.p4').write_text(s)
