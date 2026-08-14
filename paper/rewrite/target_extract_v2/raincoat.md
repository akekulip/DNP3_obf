# RAINCOAT: RAndomization of Network Communication in Power Grid Cyber INfrastructure to Mislead Attackers

(Printed title spells out the acronym via the capitalized letters: RA-ndomization ... N-etwork ... IN-frastructure ... "RAINCOAT".)

**Authors (as printed):** Hui Lin, Member, IEEE; Zbigniew Kalbarczyk, Member, IEEE; and Ravishankar K. Iyer, Fellow, IEEE. (End-of-paper biographies confirm Hui Lin -- Univ. of Nevada, Reno; Kalbarczyk and Iyer -- Univ. of Illinois, Urbana-Champaign.)

**Venue / year (as printed on the PDF):** IEEE Transactions on Smart Grid (early-access reprint). DOI 10.1109/TSG.2018.2870362. ISSN 1949-3053, (c) 2018 IEEE. Printed banner: 'accepted for publication in a future issue of this journal, but has not been fully edited.'

**Printed year:** 2018 (early access) / 2019 (published, TSG vol. 10)  
**Source file:** `target/RAINCOAT (2).pdf`  |  **Pages:** 14  |  **Re-extracted with:** PyMuPDF 1.28.2 (column-aware, reading-order)


---

## Section hierarchy (in reading order)

- I. INTRODUCTION  _(p1)_
- II. BACKGROUND & THREAT MODEL  _(p2)_
    - A. Threat model  _(p2)_
    - B. Learning the physical state  _(p3)_
- III. RAINCOAT APPROACH  _(p4)_
- IV. CRAFT DECOY MEASUREMENTS TO MISLEAD ATTACKERS  _(p5)_
    - A. Step 1.a: mislead FDIAs  _(p5)_
    - B. Step 1.b: mislead CRAs  _(p7)_
    - C. Step 2: refine measurements  _(p7)_
    - D. Case study  _(p8)_
- V. EVALUATION  _(p8)_
    - A. Security evaluation  _(p10)_
    - B. Performance evaluation  _(p10)_
- VI. DISCUSSION  _(p11)_
- VII. RELATED WORK  _(p11)_
- VIII. CONCLUSIONS  _(p12)_
- ACKNOWLEDGMENTS  _(p12)_
- REFERENCES  _(p13)_

## Figure / table captions (verbatim first sentence)

- **Figure 1** (p1): Three stages of attacks that introduce physical damage.
- **Figure 2** (p2): Control network setup in power systems.
- **TABLE 1** (p3): TARGETS AND PREPARATIONS OF FDIA AND CRA.
- **Figure 3** (p4): Raincoat approach.
- **Figure 4** (p6): Procedure to craft decoy measurements in a 5-bus power system.
- **Figure 5** (p7): Decoy measurements misleading attackers.
- **Figure 6** (p8): Cyber-physical testbed to evaluate Raincoat.
- **Figure 7** (p8): Recording of power generation on local campus.
- **Figure 8** (p9): Comparing the probabilities of successful attacks in different evaluation scenarios.
- **TABLE 2** (p10): IMPACT ON ACCURACY OF STATE ESTIMATION.
- **Figure 9** (p11): Comparing RTTs under three flow control mechanisms.

## References (40 entries)

[1]  R. Lee, M. Assante, and T. Conway. Analysis of the cyber attack on the Ukrainian power grid. SANS and E-ISAC technical report, Mar. 18, 2016.

[2]  N. Falliere, L. Murchu, and E. Chien. W32.Stuxnet dossier. Symantec Security Response, 2011.

[3]  H. Lin, A. Slagell, Z. Kalbarczyk, P. Sauer, and R. Iyer, "Runtime semantic security analysis to detect and mitigate control-related attacks in power grids," IEEE Trans. Smart Grid, March 2016.

[4]  R. Bobba, K. Rogers, Q. Wang, H. Khurana, K. Nahrstedt, and T. Overbye, "Detecting false data injection attacks on DC state estimation," In Proc. of Workshop on Secure Control Systems, 2010.

[5]  J. Valenzuela, J. Wang, and N. Bissinger, "Real-time intrusion detection in power system operations," IEEE Trans. Power Systems, vol. 28, no. 2, pp. 1052-1062, May 2013.

[6]  P. Berde et al., "ONOS: Towards an open, distributed SDN OS," In Proc. 3rd Workshop on Hot Topics in SDN, pp. 1-6, 2014.

[7]  Raytheon BBN Technologies. GENI (Global Environment for Network Innovations) exploring networks of the future. [Online] available at: www.geni.net.

[8]  D. Formby, S. Jung, J. Copeland, and R. Beyah, "An empirical study of TCIP vulnerabilities in critical power system devices," In Proc. 2nd Workshop on Smart Energy Grid Security, pp. 39-44, 2014.

[9] Y. Liu, P. Ning, and M. Reiter, "False data injection attacks against state estimation in electric power grids," In Proc. 16th ACM Conf. Computer and Communications Security (CCS '09), pp. 21-32, 2009.

[10] K. Oliver, L. Jia, R. J. Thomas, and L. Tong, "Malicious data attacks on the smart grid," IEEE Trans. Smart Grid (Dec. 2011), vol. 2, no. 4, pp. 645-658.

[11] A. Monticelli. "Electric power system state estimation," In Proc. of the IEEE (2000) , vol. 88, no. 2.

[12] Schweitzer Engineering Laboratories, Inc. SEL-2740S Software-Defined Network Switch. [Online]. Available: https://www.selinc.com/SEL- 2740S/

[13] IEEE standard communication delivery time performance requirements for electric power sub-station automation, IEEE Std. 1646-2004, 2005.

[14] R. Zimmerman, C. Murillo-Sánchez, and R. Thomas, "MATPOWER: Steady-state operations, planning and analysis tools for power systems research and education," IEEE Trans. Power Systems (Feb. 2011), vol. 26, no. 1, pp. 12-19.

[15] Y. Liao and M. Kezunovic, "Online Optimal Transmission Line Parameter Estimation for Relaying Applications," in IEEE Transactions on Power Delivery, vol. 24, no. 1, pp. 96-102, Jan. 2009.

[16] M. L. Crow, "State estimation" in Computational Methods for Electric Power Systems, 3rd. ed., Chapter 5, CRC Press, 2015.

[17] K. Morrow, E. Heine, K. Rogers, R. Bobba, and T. Overbye. "Topology perturbation for detecting malicious data injection," In Proc. 45th Hawaii Int. Conf. System Science (HICSS ‘12), pp. 2104-2113, 2012.

[18] S. Knight, H. Nguyen, N. Falkner, R. Bowden, and M. Roughan, "The internet topology zoo," IEEE Journal on Selected Areas in Communications (Oct. 2011), vol. 29, no. 9, pp. 1765-1775.

[19] Open DNP3 Group. (2012), "DNP3: Distributed Network Protocol 3.0 Google  Code  Archive,"  [Online].  Available: http://code.google.com/p/dnp3/.

[20] D. Kewley, R. Fink, J. Lowry and M. Dean, "Dynamic approaches to thwart adversary intelligence gathering," In Proc. DARPA Information Survivability Conf. & Exposition II, pp. 176-185, 2001.

[21] S. Antonatos, P. Akritidis, E. Markatos, and K. Anagnostakis, "Defending against hitlist worms using network address space randomization," Computer Networks (Aug. 2007), vol. 51, no. 12, Aug. 2007.

[22] J. Haadi Jafarian, E. Al-Shaer, and Q. Duan, "OpenFlow random host mutation: Transparent moving target defense using software defined networking," In Proc. 1st Workshop Hot Topics in Software Defined Networks(HotSDN ‘12), pp. 127-132, 2012.

[23] D. Formby, P. Srinivasan, A. Leonard, J. Rogers, and R. Beyah, "Who's in control of your control system? Device fingerprinting for cyber- physical systems," In Proc. Network and Distributed System Security Symposium. (NDSS ‘16), Feb. 2016.

[24] K. Davis, K. Morrow, R. Bobba, and E. Heine, "Power flow cyber attacks and perturbation-based defense," in Proceedings of 2012 IEEE Third International  Conference  on  Smart  Grid  Communications (SmartGridComm), Tainan, 2012, pp. 342-347.

[25] F. Miao, Q. Zhu, M. Pajic and G. J. Pappas, "Coding Schemes for Securing Cyber-Physical Systems Against Stealthy Data Injection Attacks," in IEEE Transactions on Control of Network Systems, vol. 4, no. 1, pp. 106-117, March 2017.

[26] M. Rahman, E. Al-Shaer, and R. Bobba, "Moving target defense for hardening the security of the power system state estimation," In Proc. 1st ACM Workshop on Moving Target Defense (MTD ‘14), 2014.

[27] M. Ali and E. Al-Shaer, "Randomization-based intrusion detection system for advanced metering infrastructure," ACM Trans. Information System and Security (Dec. 2015), vol. 2, 7.

[28] S. Weerakkody, Y. Mo and B. Sinopoli, "Detecting integrity attacks on control systems using robust physical watermarking," In Proc. 53rd IEEE Conference on Decision and Control, 2014, pp. 3757-3764.

[29] A. Cahn, J. Hoyos, M. Hulse and E. Keller, "Software-defined energy communication networks: From substation automation to future smart grids," In Proc. of IEEE Int. Conf. Smart Grid Communications, pp. 558- 563, 2013.

[30] X. Dong, H. Lin, R. Tan, R. Iyer, and Z. Kalbarczyk, "Software-defined networking for smart grid resilience: Opportunities and challenges," in Proc. 1st ACM Workshop on Cyber-Physical System Security, pp. 61-68, 2015.

[31] R. Sherwood, et al., "Can the production network be the testbed," In Proc. 9th USENIX Conf. Operating Systems Design and Implementation (OSDI ‘10), pp. 365-378, 2010.

[32] A. Goodney, S. Kumar, A. Ravi, and Y. Cho, "Efficient PMU networking with software defined networks," in Proc. IEEE Int. Conf. Smart Grid Communications, pp. 378-383, 2013.

[33] K. Nagananda, S. Kishore and R. Blum, "A PMU scheduling scheme for transmission of synchrophasor data in electric power systems," IEEE Trans. Smart Grid (Sept. 2015), vol. 6, no. 5, pp. 2519-2528.

[34] K. Wilhoit and S. Hilt, "The GasPot experiment: Unexamined perils in using gas-tank-monitoring systems," TrendLabs, Trend Micro Inc., August 2015. [Online]. Available: https://www.blackhat.com/docs/us- 15/materials/us-15-Wilhoit-The-Little-Pump-Gauge-That-Could- Attacks-Against-Gas-Pump-Monitoring-Systems-wp.pdf.

[35] D. Buza, F. Juhász, G. Miru, M. Félegyházi, and T. Holczer, "CryPLH: protecting smart energy systems from targeted attacks with a PLC honeypot," in Proc. Int. Workshop Smart Grid Security, pp. 181-192, 2014.

[36] C. Liu, J. Wu, C. Long and D. Kundur, "Reactance Perturbation for Detecting and Identifying FDI Attacks in Power System State Estimation," in IEEE Journal of Selected Topics in Signal Processing.

[37] J. Tian, R. Tan, X. Guan and T. Liu, "Enhanced Hidden Moving Target Defense in Smart Grids," in IEEE Transactions on Smart Grid.

[38] M. A. Rahman and H. Mohsenian-Rad, "False data injection attacks with incomplete information against smart power grids," 2012 IEEE Global Communications Conference (GLOBECOM), Anaheim, CA, 2012, pp. 3153-3158.

[39] J. Kim, L. Tong and R. J. Thomas, "Subspace Methods for Data Attack on State Estimation: A Data Driven Approach," in IEEE Transactions on Signal Processing, vol. 63, no. 5, pp. 1102-1114, March1, 2015.

[40] M. Esmalifalak, H. Nguyen, R. Zheng and Zhu Han, "Stealth false data injection using independent component analysis in smart grid," 2011 IEEE International Conference on Smart Grid Communications (SmartGridComm), Brussels, 2011, pp. 244-248.
