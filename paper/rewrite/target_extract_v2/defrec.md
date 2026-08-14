# DefRec: Establishing Physical Function Virtualization to Disrupt Reconnaissance of Power Grids' Cyber-Physical Infrastructures

**Authors (as printed):** Hui Lin, Jianing Zhuang (University of Nevada, Reno); Yih-Chun Hu (University of Illinois, Urbana-Champaign); Huayu Zhou (University of Nevada, Reno)

**Venue / year (as printed on the PDF):** Network and Distributed Systems Security (NDSS) Symposium 2020, 23-26 February 2020, San Diego, CA, USA. ISBN 1-891562-61-4. https://dx.doi.org/10.14722/ndss.2020.24365

**Printed year:** 2020  
**Source file:** `target/10139606.pdf`  |  **Pages:** 18  |  **Re-extracted with:** PyMuPDF 1.28.2 (column-aware, reading-order)


---

## Section hierarchy (in reading order)

- I. INTRODUCTION  _(p1)_
    - A. Contributions  _(p1)_
- II. DESIGN OBJECTIVES  _(p2)_
    - A. Power Grid Basics  _(p2)_
    - B. Design Objective & Threat Model  _(p3)_
- III. DESIGN OVERVIEW OF DEFREC BASED ON PFV  _(p4)_
    - A. Components of PFV  _(p4)_
    - B. Security Policies based on PFV  _(p5)_
- IV. DISRUPTION POLICY: RANDOMIZE COMMUNICATIONS  _(p6)_
    - A. Randomize Request Patterns  _(p6)_
    - B. Probabilistic Dropping Protocol to Isolate Proactive At-  _(p6)_
- V. ATTACK-MISLEADING POLICY: CRAFT DECOY DATA  _(p7)_
    - A. Decoy Data Construction to Mislead FDIAs  _(p7)_
    - B. Discussion: Decoy Data for Other Attacks  _(p9)_
- VI. IMPLEMENTATION  _(p9)_
- VII. EVALUATION  _(p10)_
    - A. Security Evaluation  _(p10)_
    - B. Performance Evaluation  _(p12)_
- VIII. RELATED WORK  _(p13)_
- IX. CONCLUSION  _(p14)_
- ACKNOWLEDGMENT  _(p14)_
- REFERENCES  _(p14)_
- APPENDIX A  _(p16)_
    - A. Details of Probabilistic Dropping Protocol  _(p16)_
    - B. Evaluation  _(p17)_
- APPENDIX B  _(p18)_
- APPENDIX C  _(p18)_

## Figure / table captions (verbatim first sentence)

- **Fig. 1** (p2): Design principle of PFV: using SDN to interact with.
- **Fig. 2** (p3): Hierarchical network infrastructure of power grids.
- **Fig. 3** (p4): Design overview: (i) PFV constructs virtual nodes that follow the actual.
- **Fig. 4** (p4): Components of PFV: hook network.
- **Fig. 5** (p5): DNP3 configuration in Schneider Electric ION 7550 power.
- **Fig. 6** (p8): Misleading FDIAs in a 3-bus power system.
- **Algorithm 1** (p9): Pseudocode of REFINEDECOY that refines decoy.
- **Fig. 7** (p10): Cyber-physical testbed for evaluation.
- **TABLE I** (p10): Evaluation cases.
- **Fig. 8** (p10): Comparing the execution time (with 99% confidence.
- **Fig. 9** (p11): PDF (y-axis) of execution time (x-axis) of data acquisition (at top) and control operations.
- **Fig. 11** (p11): Accessible-virtual-node
- **Fig. 13** (p12): Virtual nodes vs.
- **Fig. 15** (p12): Capability of packet hooking.
- **Fig. 16** (p12): Comparing RTT with and without DefRec enabled.
- **Fig. 17** (p13): The execution time to craft decoy data.
- **Fig. 18** (p16): Probabilistic dropping protocol.
- **Fig. 19** (p17): Probabilities that an adversary identifies real devices.
- **Fig. 20** (p17): The accuracy of state estimation when we randomly retrieve.
- **Fig. 21** (p17): False negative rate of the probabilistic dropping protocol.
- **Fig. 22** (p17): Normalized residual errors of state estimation when.
- **Fig. 23** (p18): Variations in communication networks or power systems:.
- **Fig. 24** (p18): Formulating decoy data construction.
- **TABLE II** (p18): Storage overhead of device profile: classified based on.
- **TABLE III** (p18): Storage overhead of caching network interactions.

## References (79 entries)

[1] "Allen Bradley MicroLogix 1400 programmable logic controller systems," [Online] Available at: https://ab.rockwellautomation.com/Programmable- Controllers/MicroLogix-1400.

[2] M. Q. Ali and E. Al-Shaer, "Randomization-based intrusion detection system for advanced metering infrastructure," ACM Transactions on Information and System Security, vol. 18, no. 2, pp. 1-30, 2015.

[3] S. Antonatos, P. Akritidis, E. Markatos, and K. Anagnostakis, "Defend- ing against hitlist worms using network address space randomization," Computer Networks, vol. 51, no. 12, pp. 3471-3490, 2007.

[4] P. Berde, M. Gerola, J. Hart, Y. Higuchi, M. Kobayashi, T. Koide, B. Lantz, B. O'Connor, P. Radoslavov, W. Snow, and others, "ONOS: towards an open, distributed SDN OS," in Proceedings of the 3rd workshop on Hot topics in software defined networking. ACM, 2014, pp. 1-6.

[5] R. B. Bobba, K. M. Rogers, Q. Wang, H. Khurana, K. Nahrstedt, and T. J. Overbye, "Detecting false data injection attacks on DC state estimation," in Preprints of the First Workshop on Secure Control Systems, CPSWEEK, 2010, pp. 18-26.

[6] D. I. Buza, F. Juh´asz, G. Miru, M. F´elegyh´azi, and T. Holczer, "CryPLH: Protecting smart energy systems from targeted attacks with a PLC honeypot," in Smart Grid Security, J. Cuellar, Ed. Springer International Publishing, 2014, pp. 181-192.

[7] "IEEE Standard for Synchrophasor Data Transfer for Power Systems," pp. 1-53, Dec 2011.

[8] A. A. Cardenas, S. Amin, Z.-S. Lin, Y.-L. Huang, C.-Y. Huang, and S. Sastry, "Attacks against process control systems: Risk assessment, detection, and response," in Proceedings of the 6th ACM Symposium on Information, Computer and Communications Security (ASIACCS '11), 2011, pp. 355-366.

[9] Chi-Ho Tsang and Sam Kwong, "Multi-agent intrusion detection system in industrial network using ant colony clustering approach and unsu- pervised feature extraction," in 2005 IEEE International Conference on Industrial Technology, 2005, pp. 51-56.

[10] E. Chien, L. OMurchu, and N. Falliere, "W32.duqu: The precursor to the next stuxnet," in 5th USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET 12). San Jose, CA: USENIX Association, Apr. 2012.

[11] "Conpot: low interactive server side industrial control systems honey- pot," [Online] Available at: http://conpot.org/.

[12] V. Costan and S. Devadas, "Intel sgx explained." IACR Cryptology ePrint Archive, vol. 2016, no. 086, pp. 1-118, 2016.

[13] C. Cremers, K. B. Rasmussen, B. Schmidt, and S. Capkun, "Distance hijacking attacks on distance bounding protocols," in 2012 IEEE Symposium on Security and Privacy, May 2012, pp. 113-127.

[14] K. R. Davis, K. L. Morrow, R. Bobba, and E. Heine, "Power flow cyber attacks and perturbation-based defense," in 2012 IEEE Third Interna- tional Conference on Smart Grid Communications (SmartGridComm), Nov 2012, pp. 342-347.

[15] M. Dhawan, R. Poddar, K. Mahajan, and V. Mann, "SPHINX: Detecting security attacks in software-defined networks," in Proceedings 2015 Network and Distributed System Security Symposium. Internet Society, 2015.

[16] "U.S. energy information administration - EIA - independent statistics and analysis," [Online] Available at: https://www.eia.gov/opendata/.

[17] N. Falliere, L. O. Murchu, and E. Chien, "W32. stuxnet dossier," White paper, Symantec Corp., Security Response, vol. 5, no. 6, p. 29, 2011.

[18] D. Formby, P. Srinivasan, A. Leonard, J. Rogers, and R. Beyah, "Who's in control of your control system? device fingerprinting for cyber- physical systems," in Proceedings 2016 Network and Distributed System Security Symposium. Internet Society, 2016.

[19] L. A. Garcia, F. Brasser, M. H. Cintuglu, A.-R. Sadeghi, O. Mohammed, and S. A. Zonouz, "Hey, my malware knows physics! attacking PLCs with physical model aware rootkit," in Proceedings 2017 Network and Distributed System Security Symposium. Internet Society, 2017.

[20] J. D. Glover, M. S. Sarma, and T. Overbye, Power System Analysis & Design, SI Version. Cengage Learning, 2012.

[21] A. Goodney, S. Kumar, A. Ravi, and Y. H. Cho, "Efficient PMU net- working with software defined networks," in 2013 IEEE International Conference on Smart Grid Communications (SmartGridComm). IEEE, 2013, pp. 378-383.

[22] W. Han, Z. Zhao, A. Doup´e, and G.-J. Ahn, "HoneyMix: Toward SDN-based intelligent honeynet," in Proceedings of the 2016 ACM International Workshop on Security in Software Defined Networks & Network Function Virtualization - SDN-NFV Security '16. ACM Press, 2016, pp. 1-6. 14

[23] C. Hoga and G. Wong, "IEC 61850: open communication in practice in substations," in IEEE PES Power Systems Conference and Exposition, vol. 2, Oct 2004, pp. 618-623.

[24] S. Hong, L. Xu, H. Wang, and G. Gu, "Poisoning network visibility in software-defined networks: New attacks and countermeasures," in Proceedings 2015 Network and Distributed System Security Symposium. Internet Society, 2015.

[25] A. Houmansadr, C. Brubaker, and V. Shmatikov, "The parrot is dead: Observing unobservable network communications," in 2013 IEEE Sym- posium on Security and Privacy, May 2013, pp. 65-79.

[26] "HP Ethernet 1Gb 4-port 331FLR Adapter - Specifications," 2012, [Online] Available at: https://support.hpe.com/hpsc/doc/public/display? docLocale=en US&docId=emr na-c03226012.

[27] J. Huang, C. Jiang, and R. Xu, "A review on distributed energy resources and microgrid," Renewable and Sustainable Energy Reviews, vol. 12, no. 9, pp. 2472 - 2483, 2008.

[28] "IEEE standard communication delivery time performance requirements for electric power substation automation," 2005, [Online] Available at https://standards.ieee.org/standard/1646-2004.html.

[29] "IEEE standard for electric power systems communications-distributed network protocol (dnp3)," pp. 1-821, Oct 2012, [Online] Available at https://standards.ieee.org/standard/1815-2012.html.

[30] J. H. Jafarian, E. Al-Shaer, and Q. Duan, "An effective address mutation approach for disrupting reconnaissance attacks," IEEE Transactions on Information Forensics and Security, vol. 10, no. 12, pp. 2562-2577, Dec 2015.

[31] S. Jain, A. Kumar, S. Mandal, J. Ong, L. Poutievski, A. Singh, S. Venkata, J. Wanderer, J. Zhou, M. Zhu, J. Zolla, U. H¨olzle, S. Stuart, and A. Vahdat, "B4: Experience with a globally-deployed software defined wan," in Proceedings of the ACM SIGCOMM 2013 Conference on SIGCOMM, New York, NY, USA, 2013, pp. 3-14.

[32] F. Kelbert, F. Gregor, R. Pires, S. K¨opsell, M. Pasin, A. Havet, V. Schiavoni, P. Felber, C. Fetzer, and P. Pietzuch, "Securecloud: Secure big data processing in untrusted clouds," in Proceedings of the Conference on Design, Automation & Test in Europe, ser. DATE '17. 3001 Leuven, Belgium, Belgium: European Design and Automation Association, 2017, pp. 282-285.

[33] D. Kewley, R. Fink, J. Lowry, and M. Dean, "Dynamic approaches to thwart adversary intelligence gathering," in Proceedings DARPA Information Survivability Conference and Exposition II. DISCEX'01, vol. 1. IEEE Comput. Soc, 2001, pp. 176-185.

[34] S. Knight, H. X. Nguyen, N. Falkner, R. Bowden, and M. Roughan, "The internet topology zoo," IEEE Journal on Selected Areas in Communications, vol. 29, no. 9, pp. 1765-1775, 2011.

[35] O. Kosut, L. Jia, R. J. Thomas, and L. Tong, "Malicious data attacks on the smart grid," IEEE Transactions on Smart Grid, vol. 2, no. 4, pp. 645-658, 2011.

[36] R. Lasseter, A. Akhil, C. Marnay, J. Stephens, J. Dagle, R. Guttromsom, A. S. Meliopoulous, R. Yinger, and J. Eto, "Integration of distributed energy resources: the certs microgrid concept," Consortium Electric Reliability Technology Solution, Tech. Rep., October 2003.

[37] D. Lee, "Ukraine power cut was cyber-attack," Jan 2017, [Online] Available at: https://www.bbc.com/news/technology-38573074.

[38] R. M. Lee, M. J. Assante, and T. Conway, "Analysis of the cyber attack on the ukrainian power grid," SANS and E-ISAC, Tech. Rep., March 2016.

[39] H. Lin, H. Alemzadeh, D. Chen, Z. Kalbarczyk, and R. K. Iyer, "Safety- critical cyber-physical attacks: Analysis, detection, and mitigation," in Proceedings of the Symposium and Bootcamp on the Science of Security (HotSoS). ACM, 2016, pp. 82-89.

[40] H. Lin, A. Slagell, Z. Kalbarczyk, and R. K. Iyer, "Raincoat: Random- ization of network communication in power grid cyber infrastructure to mislead attackers," IEEE Transactions on Smart Grid, pp. 1-1, 2018.

[41] H. Lin, A. Slagell, Z. Kalbarczyk, P. Sauer, and R. K. Iyer, "Runtime semantic security analysis to detect and mitigate control-related attacks in power grids," IEEE Transactions on Smart Grid, vol. 9, no. 1, pp. 163-178, Jan 2018.

[42] Y. Liu, P. Ning, and M. K. Reiter, "False data injection attacks against state estimation in electric power grids," ACM Transactions on Information and System Security, vol. 14, no. 1, pp. 1-33, 2011.

[43] S. Mauw, Z. Smith, J. Toro-Pozo, and R. Trujillo-Rasua, "Distance- bounding protocols: Verification without time and location," in 2018 IEEE Symposium on Security and Privacy (SP), May 2018, pp. 549- 566.

[44] J. M. McCune, A. Perrig, A. Seshadri, and L. van Doorn, "Turtles all the way down: Research challenges in user-based attestation," in USENIX Summit on Hot Topics in Security (HotSec '07). USENIX Association, 2007.

[45] A. Monticelli, "Electric power system state estimation," Proceedings of the IEEE, vol. 88, no. 2, pp. 262-282, 2000-02. [Online]. Available: http://ieeexplore.ieee.org/document/824004/

[46] K. L. Morrow, E. Heine, K. M. Rogers, R. B. Bobba, and T. J. Overbye, "Topology perturbation for detecting malicious data injection," in 2012 45th Hawaii International Conference on System Sciences, 2012, pp. 2104-2113.

[47] K. G. Nagananda, S. Kishore, and R. S. Blum, "A PMU scheduling scheme for transmission of synchrophasor data in electric power sys- tems," IEEE Transactions on Smart Grid, vol. 6, no. 5, pp. 2519-2528, 2015-09.

[48] "Network functions virtualisation: An introduction, benefits, enablers, challenges, and call for action," Oct 2012, [Online] Available at: https: //portal.etsi.org/nfv/nfv white paper.pdf.

[49] "Opendnp3: the de facto reference implementation of ieee-1815 (dnp3)," [Online] Available at: https://www.automatak.com/opendnp3/.

[50] V. Paxson, "Bro: a system for detecting network intruders in real-time," Computer Networks, p. 29, 1999.

[51] M. A. Rahman, E. Al-Shaer, and R. B. Bobba, "Moving target defense for hardening the security of the power system state estimation," in Proceedings of the First ACM Workshop on Moving Target Defense - MTD '14. ACM Press, 2014, pp. 59-68.

[52] "PJM: regional transmission organization (rto) that coordinates the movement of wholesale electricity in all or parts of 13 states and the district of columbia," [Online] Available at: https://www.pjm.com/.

[53] R. Sailer, X. Zhang, T. Jaeger, and L. Van Doorn, "Design and implementation of a tcg-based integrity measurement architecture." in 13th USENIX Security Symposium (USENIX Security '04), publisher = USENIX Association, 2004, pp. 223-238. P. W. Sauer and M. A. Pai, Power system dynamics and stability.

[54] Prentice Hall Upper Saddle River, NJ, 1998, vol. 101.

[55] G. W. Scheer and D. J. Dolezilek, "Comparing the reliability of ethernet network topologies in substation control and monitoring networks," in Western Power Delivery Automation Conference, Spokane, Washington, 2000.

[56] M. Schloesser, "Dionaea low interaction honeypot (forked from dion- aea.carnivore.it): rep/dionaea," [Online] Available at: https://github.com/ rep/dionaea.

[57] S. Scott-Hayward, G. O'Callaghan, and S. Sezer, "SDN security: A survey," in 2013 IEEE SDN for Future Networks and Services (SDN4FNS). IEEE, 2013-11, pp. 1-7.

[58] "Schneider Electric PowerLogic ion7550/ion7650 series," [Online] Available at: https://www.schneider-electric.us/en/product-range/1460- powerlogic-ion7550-ion7650-series/.

[59] "SEL-2740s software-defined network switch," [Online] Available at: https://selinc.com/products/2740S/.

[60] "SEL-751a feeder protection relay," [Online] Available at: https://selinc.com/products/751A/.

[61] D. Shelar, P. Sun, S. Amin, and S. Zonouz, "Compromising security of economic dispatch in power system operations," in 2017 47th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), 6 2017, pp. 531-542.

[62] L. V. Silva, R. Marinho, J. L. Vivas, and A. Brito, "Security and privacy preserving data aggregation in cloud computing," in Proceedings of the Symposium on Applied Computing, ser. SAC '17. New York, NY, USA: ACM, 2017, pp. 1732-1738.

[63] R. Skowyra, L. Xu, G. Gu, V. Dedhia, T. Hobson, H. Okhravi, and J. Landry, "Effective topology tampering attacks and defenses in software-defined networks," in 2018 48th Annual IEEE/IFIP Interna- tional Conference on Dependable Systems and Networks (DSN), 2018- 06, pp. 374-385. 15

[64] S. Soltan, P. Mittal, and H. V. Poor, "BlackIoT: IoT botnet of high wattage devices can disrupt the power grid," in 27th USENIX Security Symposium. USENIX Association, 2018, pp. 15-32.

[65] R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in 2010 IEEE Symposium on Security and Privacy. IEEE, 2010, pp. 305-316.

[66] N. Spring, R. Mahajan, and D. Wetherall, "Measuring ISP topolo- gies with rocketfuel," in Proceedings of the 2002 Conference on Applications, Technologies, Architectures, and Protocols for Computer Communications, ser. SIGCOMM '02. New York, NY, USA: ACM, 2002, pp. 133-145.

[67] F. Stumpf, O. Tafreschi, P. R¨oder, and C. Eckert, "A robust integrity re- porting protocol for remote attestation," Darmstadt Technical University, Department of Business Administration, Economics and Law, Institute for Business Studies (BWL), Publications of Darmstadt Technical University, Institute for Business Studies (BWL), 2006.

[68] U. Tamminen, "Kippo: SSH honeypot. contribute to desaster/kippo development by creating an account on GitHub," 2018-12-02, [Online] Available at: https://github.com/desaster/kippo.

[69] B. E. Ujcich, U. Thakore, and W. H. Sanders, "Attain: An attack injection framework for software-defined networking," in 2017 47th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), June 2017, pp. 567-578.

[70] X. Wang, C. Xu, K. Wang, F. Yan, and D. Zhao, "Toward cost-effective memory scaling in clouds: Symbiosis of virtual and physical memory," in 2018 IEEE 11th International Conference on Cloud Computing (CLOUD), vol. 00, 2018-07, pp. 33-40.

[71] S. Weerakkody, Y. Mo, and B. Sinopoli, "Detecting integrity attacks on control systems using robust physical watermarking," in 53rd IEEE Conference on Decision and Control, 2014, pp. 3757-3764.

[72] K. Wilhoit and S. Hilt, "The GasPot experiment: Unexamined perils in using gas tank monitoring systems," A TrendLabs Research Paper, Trend Micro Inc. [Online]. Available: https: //www.trendmicro.de/media/wp/the-gaspot-experiment-wp-en.pdf

[73] "Wireshark go deep," [Online] Available at: https://www.wireshark.org/.

[74] L. Xu, J. Huang, S. Hong, J. Zhang, and G. Gu, "Attacking the brain: Races in the SDN control plane," in 26th USENIX Security Symposium (USENIX Security 17). Vancouver, BC: USENIX Association, 2017, pp. 451-468.

[75] Yuan Liao and M. Kezunovic, "Online optimal transmission line param- eter estimation for relaying applications," IEEE Transactions on Power Delivery, vol. 24, no. 1, pp. 96-102, Jan 2009.

[76] J. Yuill, D. Denning, and F. Feer, "Using deception to hide things from hackers: Processes, principles, and techniques," Journal of Information Warfare, vol. 3, no. 5, p. 16, 2006.

[77] M. Zalewski, Silence on the wire: a field guide to passive reconnais- sance and indirect attacks. No Starch Press, 2005.

[78] W. Zhou, D. Jin, J. Croft, M. Caesar, and P. B. Godfrey, "Enforcing customizable consistency properties in software-defined networks," in 12th USENIX Symposium on Networked Systems Design and Implemen- tation (NSDI 15). Oakland, CA: USENIX Association, May 2015, pp. 73-85.

[79] R. Zimmerman, C. E. Murillo-Sanchez, and R. Thomas, "MATPOWER: Steady-state operations, planning, and analysis tools for power systems research and education," IEEE Transactions on Power Systems, vol. 26, no. 1, pp. 12-19, 2011. APPENDIX A ADDITIONAL DETAILS ON DISRUPTION POLICY A. Details of Probabilistic Dropping Protocol In Section IV, we propose a probabilistic dropping protocol to reduce the effectiveness of adversaries' probing activities, making successful guessing about real devices difficult. We present the protocol in Figure 18. After an adversary accesses an inaccessible virtual node (marked as device 0), we isolate the adversary when she accesses a device k with the probability pk (including device 0), regardless of whether device k is a real device or a virtual node. We set a threshold δ such that the adversary will be isolated at her access to the device δ +1. In other words, the adversary can only access at most δ real devices before it is isolated from control networks. We model the protocol as a series of biased coin flips with increasing probabilities, i.e., p0, . . . , pk. The probability that an adversary is isolated at her k-th access is Qk = pk×Qk−1 j=0(1− pj) for 1 ≤k ≤δ. Fig. 18: Probabilistic dropping protocol. Theorem 1. The chance that an adversary will be isolated from control networks is evenly distributed, i.e., p0 = Q0 = p0 Q1 = · · · = Qδ, if pk = 1 −k · p0 Proof: We prove this theorem by mathematical induction. p0 By definition, when k = 0, we have p0 = and 1 −0 · p0 Q0 = p0. Assuming that, this condition holds when k = i, i.e., if p0 pi = , we have Qi = p0. When k = i + 1, we 1 −i · p0 have Qi+1 = pi+1 × Qi j=0(1 −pj). Through the following derivation, we can represent Qi+1 in terms of Qi: iY Qi+1 = pi+1 × (1 −pj) j=0 i−1 = pi+1 Y × pi × (1 −pi) × (1 −pj) pi j=0 i−1 = pi+1 Y × (1 −pi) × pi × (1 −pj) pi j=0 = pi+1 × (1 −pi) × Qi (7) pi Based on the inductive step, we can have the following derivation by making Qi+1 = p0: pi+1 p0 p0 = Qi+1 = · (1 − ) · p0 ⇒ p0 1 −i · p0 (1 −i · p0) p0 pi+1 = (8) 1 −(i + 1) · p0 p0 Consequently, if pk = , we always have p0 = 1 −k · p0 Q0 = Q1 = · · · = Qδ. Based on Theorem 1, we can derive the probability that an adversary successfully obtains measurements from all real devices through proactive attacks. When the adversary accesses k-th device, the probability of not being isolated is 1 −Qk or 1 −p0. We use m2 to represent the number of inaccessible virtual nodes and n the number of real devices. Because there are m2 −1 remaining inaccessible virtual nodes (excluding 16 device 0 that triggers the probabilistic dropping protocol), the chance that the adversary is accessing a real device at 1 the k-th access is , if the previous k −1 devices  n+m2−1 n−k+1 are also real devices. Consequently, the probability that the adversary has obtained measurements from δ real devices 1 Qδ is Sδ = pδ . If the adversary accesses all 0 k=1  n+m2−1 n−k+1 remaining real devices under this protocol, the probability that they can obtain all real measurements through proactive probing will be at least Sall = S⌈n δ ⌉ . δ B. Evaluation In Section IV, we divide all virtual nodes in two groups. One group is accessible by legitimate applications; we add random communication to accessible virtual nodes such that it is challenging for adversaries to identify real devices by passively monitoring communication pattern. The other group is inaccessible, and accessing them triggers the probabilistic dropping protocol. Effectiveness in RO1. In Figure 19, we show probabilities that an adversary successfully guesses whether a device is real based on randomized requests (see Section IV-A). In our experiment, we issue requests to 95% randomly selected real devices and to accessible virtual nodes, whose ratio to real devices is increased from 1% to 10% (in x-axis). Even with a small accessible-virtual-node to real-device ratio, the probability is always lower than 0.001% (10−5), making it challenging for adversaries to distinguish real devices from virtual ones based on the randomized requests. Identifying Real Devices 100 24-bus 30-bus Probability of 73-bus 10-20 118-bus 406-bus 1153-bus 10-40 10-60 1% 2% 3% 4% 5% 6% 7% 8% 9% 10% Accessible-Virtual-Node to Real-Device Ratio Fig. 19: Probabilities that an adversary identifies real devices based on randomized requests. In Figure 20, we show the accuracy of state estimation when we issue requests to 95% randomly selected real devices and retrieve their physical data. We observed negligible differ- ences, with less than 0.1%. In power grids, state estimation often uses redundant data, e.g., 100% more than necessary data, to ensure estimation accuracy. Even if we use 95% of physical data, the accuracy of state estimation is not affected. 100% Accuracy (Normalized) 50% 0% 24-bus 30-bus 73-bus 118-bus 406-bus 1153-bus Fig. 20: The accuracy of state estimation when we randomly retrieve 95% physical data from real devices. Effectiveness in RO2. In Figure 21, we show FN rates of the probabilistic dropping protocol, the chances that an adversary successfully obtains measurements of real devices by proactive probing. In this experiment, we set design parameters as δ = 4 and p0 = 0.18. From the figure, we can see that the chance to obtain all measurements through proactive probing is low, less than 10−30 for small- or medium-size power systems. Because FN rates are lower than 10−200 for large power systems, we did not include the rates in the figure. 100 False Negative Rate 24-bus 30-bus 73-bus 10-100 118-bus 406-bus 1153-bus 10-200 1% 2% 3% 4% 5% 6% 7% 8% 9% 10% Inaccessible-Virtual-Node to Real-Device Ratio Fig. 21: False negative rate of the probabilistic dropping protocol with δ = 4 and p0 = 0.18. Because only accesses to inaccessible virtual nodes trigger the probabilistic dropping protocol, there are no false positives (FP) for legitimate applications, which already know iden- tities of real devices. In rare cases, faulty devices (physical devices used by power grids usually have the probability of misconfiguration between 30 × 10−6 to 600 × 10−6 [55]) or devices unaware of DefRec can accidentally send requests to inaccessible virtual nodes. Assuming that there are n real devices and m2 inaccessible virtual nodes, the probability of accessing one of the inaccessible virtual nodes is m2/(n+m2). If we present m2 = r×n with 0 < r < 1, then this probability becomes r/(1+r), which is not related to the size of a power grid. Based on the analysis in Figure 12, we can achieve RO2 with r ≤10%, which makes the probability of accidentally accessing inaccessible virtual nodes 9.1% or less. Normalized Residual Error 24-bus 118-bus 106 30-bus 406-bus in State Estimation 73-bus 1153-bus 105 104 0 5% 10% 15% 20% 24% 30% Virtual-Node to Real-Device Ratio Fig. 22: Normalized residual errors of state estimation when adversaries use decoy data to prepare FDIAs (with 99% confidence interval). Effectiveness in RO3. In Section VII-A3, we demonstrate FP and FN rates of RO3. In Figure 22, we demonstrate the normalized residual errors of state estimation when adversaries use decoy data to prepare FDIAs. As discussed in Section V, if adversaries obtain correct knowledge about power grids, they can design active attacks on the FDIAs such that normalized residual errors are smaller than 1. However, if adversaries use decoy data crafted by DefRec, normalized residual errors are amplified to at least 5,000. As we increase the ratio of virtual nodes, adversaries will use more decoy data for attack reconnaissance. Correspondingly, normalized residual errors increase significantly, reaching around 10,000 for all six power grid cases. Variations in Power Systems. Figure 11 and Figure 12 show that DefRec can delay adversaries for a long latency, e.g., 100 years. In that span of time, operational environ- ments of power grids can experience significant changes. In Figure 23, we show normal variations of real communication networks or transmission networks in power systems from 17 8 # of nodes (normalized) Poland Power (1999-2008) France Power (2013) 6 Arpanet (1969-1972) Belnet (2003-2010) Cesnet (1993-2010) 4 Kentman (2005-2011) 2 0 Records at Different Time Stamps Fig. 23: Variations in communication networks or power systems: the x-axis represents a time span specified in the legend during which the data is recorded; the y-axis specifies the number of nodes normalized to the first record in the dataset. public datasets, including InternetZoo [34], Rocketfuel [66], and MATPOWER [79]. We select six of these networks that contain at least five records at different times. Because different networks can have various sizes, Fig- ure 23 normalizes the number of nodes in each network with the number appearing in the first record. We can observe signif- icant changes in communication networks, such as Arpanet and Cesnet. In transmission networks used by Polish and French national power grids, we can also see around 10% increase of physical devices in ten years. Variations in a long time interval make it difficult, if not impossible, for adversaries to achieve reconnaissance objectives. APPENDIX B GENERALIZATION OF DECOY DATA CONSTRUCTION In this section, we show how the decoy data construction procedure designed for FDIAs is applied to other attacks. Most power grid control operations are formulated as an optimization problem. For example, FDIAs aim at minimizing the errors of state estimation while optimal power flow analysis aims at minimizing operational costs [45]. Fig. 24: Formulating decoy data construction. Misleading adver- saries into targeting virtual nodes. In this work, we focus on intelligent adversaries causing physical damage by disrupting control operations, usually formulated in optimization problems. Compared to random disruptions, these attacks, determined based on theoretical analysis of control operations, can introduce severe physical damage without raising alerts [19], [61]. In Figure 24, we present a general format of those op- timization problems with the objective specified by g′. In FDIAs, adversaries' objectives are to minimize estimation errors, with compromised measurements leading to wrongly estimated system state (i.e., z+ a in the figure). In another at- tack that disrupts optimal power flow analysis, adversaries can maximize the costs of power generation instead of minimizing them, to reduce economical revenues [19], [61]. DefRec mixes decoy data with real one (specified by zd), such that (i) no solutions exist to achieve attack objectives; and/or (ii) achieving attack objectives requires modifying de- coy data with significant changes (indicated by a threshold |ad| ≥ϵ). In other words, adversaries will prepare attack strategies involving operations of virtual nodes that, when executed, will easily expose the adversaries. APPENDIX C STORAGE OVERHEAD OF DEVICE PROFILE AND CACHING In Table II, we show storage overhead of device profiles. By following meter deployment in [35], we assume that for each power grid, there are two meters measuring the active and reactive power injected at each substation and four meters measuring the active and reactive power flows at the receiving and sending ends of each transmission line. For each meter, we used ten 32-bit numbers to record the range of the measurements and their probability distribution. In Table II, we can see that even for an 1153-bus power grid, we can record a total of 367.8 KB in the machine implementing PFV. TABLE II: Storage overhead of device profile: classified based on power systems and the ratio of virtual nodes to physical devices. Ratio of Virtual Nodes to Power Grid Base Physical Devices 10% 15% 20% 25% IEEE 24-bus 8.1KB 8.9KB 9.3KB 9.7KB 10.1KB IEEE 30-bus 9.0KB 9.9KB 10.4KB 10.8KB 11.3KB RTS96 73-bus 25.1KB 27.6KB 28.9KB 30.1KB 31.4KB IEEE 118-bus 38.1KB 41.2KB 43.8KB 45.7KB 47.6KB Poland 406-bus 107.2KB 117.9KB 123.3KB 128.6KB 134.0KB Poland 1153-bus 301.4KB 331.5KB 346.6KB 361.7KB 367.8KB TABLE III: Storage overhead of caching network interactions. Supported Devices Function Codes SEL 751A AB 1400 ION 7550 CONFIRM READ (4) (2) (2) WRITE SELECT OPERATE DIRECT OPERATE COLD RESTART WARM RESTART ENABLE UNSOLICITED DISABLE UNSOLICITED Total ≤8KB ≤5KB ≤5KB Storage Overhead In Table III, we present storage overhead of caching network interactions with three physical devices used in our evaluations. We include all network interactions that are sup- ported by those devices and a DNP3 master implemented based on the openDNP3 library [49]. Even though the DNP3 protocol specifies a large amount of data formats, a physical device usually selects a single data format for each function code (see the DNP3 protocol specification for details [29]). Consequently, we cache one request and the corresponding response for each function code. One exception is the "READ" operation, for which we have cached multiple pairs of requests and responses (the amount is included in parentheses). To be compatible with legacy devices, the size of a single DNP3 packet cannot be more than 292 bytes [29]. Consequently, we estimate the total storage overhead for caching network interactions with those three devices, usually occupying less than 8 KB. 18
