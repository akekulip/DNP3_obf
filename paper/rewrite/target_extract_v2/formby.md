# Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems

**Authors (as printed):** David Formby, Preethi Srinivasan (School of ECE, Georgia Tech); Andrew Leonard, Jonathan Rogers (School of Mechanical Engineering, Georgia Tech); Raheem Beyah (School of ECE, Georgia Tech)

**Venue / year (as printed on the PDF):** Network and Distributed System Security (NDSS) Symposium '16, 21-24 February 2016, San Diego, CA, USA. Copyright 2016 Internet Society, ISBN 1-891562-41-X. http://dx.doi.org/10.14722/ndss.2016.23142

**Printed year:** 2016  
**Source file:** `target/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf`  |  **Pages:** 15  |  **Re-extracted with:** PyMuPDF 1.28.2 (column-aware, reading-order)


---

## Section hierarchy (in reading order)

- I. INTRODUCTION  _(p1)_
- II. RELATED WORK  _(p2)_
- III. THREAT MODEL, ASSUMPTIONS, AND GOALS  _(p3)_
- IV. OVERVIEW OF DEVICE FINGERPRINTING METHODS  _(p4)_
    - A. Method 1: Cross-layer Response Times  _(p4)_
    - B. Method 2: Physical Fingerprinting  _(p7)_
- V. SYNTHETIC FINGERPRINT GENERATION  _(p10)_
- VI. DISCUSSION  _(p11)_
    - A. Performance  _(p11)_
    - B. Robustness Against Forgery  _(p12)_
    - C. Limitations  _(p13)_
- VII. CONCLUSIONS AND FUTURE WORK  _(p14)_
- ACKNOWLEDGMENTS  _(p14)_
- REFERENCES  _(p14)_
    - M. Masera. Modbus/dnp3 state-based intrusion detection system. In  _(p14)_
- APPENDIX  _(p14)_
    - A. Software Configuration Fingerprinting  _(p14)_
    - B. Modeling of a vacuum interrupter  _(p15)_

## Figure / table captions (verbatim first sentence)

- **Fig. 1** (p2): The two novel fingerprinting methods can work together to augment.
- **Fig. 2** (p4): Points of attack in a power substation network.
- **Fig. 3** (p4): Measurement of cross-layer response time.
- **Fig. 4** (p6): Network Architecture of First Substation.
- **Fig. 5** (p6): Network Architecture of Second Substation.
- **Fig. 6** (p6): Separability of device types based on CLRT.
- **Fig. 7** (p7): Fingerprint Classification Performance Using FF-ANN.
- **Fig. 8** (p7): Fingerprint classification performance.
- **Fig. 9** (p7): Randomly generated samples from the unsupervised learned clusters.
- **Fig. 10** (p7): Minor effects of network architecture on CLRT distributions.
- **Fig. 11** (p8): Classification Performance Across Networks.
- **Fig. 12** (p8): Classification Performance on Second Substation.
- **Fig. 13** (p8): Diagram of two different latching relays.
- **Fig. 14** (p8): Timing diagram to calculate Operation times.
- **Fig. 15** (p9): Experimental Test Setup-fingerprinting breakers.
- **Fig. 16** (p9): Circuits used in lab experiments.
- **Fig. 17** (p9): SER based response times.
- **Fig. 18** (p9): Classification Performance Based on Timestamped Close Operations.
- **Fig. 19** (p10): Difference between open and close.
- **Fig. 20** (p10): Potter and Brumfield Latch Relay (left), Mechanical Schematic of.
- **Fig. 21** (p11): Armature displacement and angular velocity.
- **Fig. 22** (p11): Comparison of simulated and experimental distributions for the.
- **Fig. 23** (p11): Performance using a combination of white box and black box.
- **Fig. 24** (p12): Forgery attempts against the CLRT technique.
- **Fig. 25** (p13): Forgery attempts against the physical fingerprinting technique.
- **Fig. 26** (p13): Forgery Detection.
- **TABLE I** (p15): VACUUM INTERRUPTER PARAMETERS.
- **Fig. 27** (p15): Effect of multiple settings enabled on CLRT distribution.
- **Fig. 28** (p15): Effect of one extra setting enabled on CLRT distribution.
- **Fig. 29** (p15): Vacuum interrupter.
- **Fig. 30** (p15): Simulated open and close response distributions for vacuum.

## References (26 entries)

[1] Advisory (icsa-15-041-02). https://ics-cert.us-cert.gov/advisories/ ICSA-15-041-02.

[2] Nmap - free security scanner for network exploration & security audits. http://nmap.org/. Accessed 2015-03-25.

[3] M. Abrams and J. Weiss. Malicious control system cyber security attack case study-maroochy water services, australia. http://csrc.nist.gov/groups/SMA/fisma/ics/documents/ Maroochy-Water-Services-Case-Study\ report.pdf, 2008.

[4] A. Bates, R. Leonard, H. Pruse, D. Lowd, and K. Butler. Leveraging usb to establish host identity using commodity devices. In Network and Distributed System Security (NDSS), NDSS '14, February 2014.

[5] A. Carcano, A. Coletta, M. Guglielmi, M. Masera, I. Fovino, and A. Trombetta. A multidimensional critical state analysis for detecting intrusions in scada systems. Industrial Informatics, IEEE Transactions on, 7(2):179-186, May 2011.

[6] A. A. C´ardenas, S. Amin, Z.-S. Lin, Y.-L. Huang, C.-Y. Huang, and S. Sastry. Attacks against process control systems: Risk assessment, detection, and response. In Proceedings of the 6th ACM Symposium on Information, Computer and Communications Security, ASIACCS '11, pages 355-366, New York, NY, USA, 2011. ACM.

[7] K. Davey. Calculation of magnetic remanence. Magnetics, IEEE Transactions on, 45(7):2907-2911, July 2009.

[8] H. Debar and A. Wespi. Aggregation and correlation of intrusion- detection alerts. In Proceedings of the 4th International Symposium on Recent Advances in Intrusion Detection, RAID '00, pages 85-103, London, UK, UK, 2001. Springer-Verlag.

[9] D. Formby, S. S. Jung, J. Copeland, and R. Beyah. An empirical study of tcp vulnerabilities in critical power system devices. In Proceedings of the 2Nd Workshop on Smart Energy Grid Security, SEGS '14, pages 39-44, New York, NY, USA, 2014. ACM.

[10] I. Fovino, A. Carcano, T. De Lacheze Murel, A. Trombetta, and M. Masera. Modbus/dnp3 state-based intrusion detection system. In Advanced Information Networking and Applications (AINA), 2010 24th IEEE International Conference on, pages 729-736, April 2010.

[11] J. Francois, H. Abdelnur, R. State, and O. Festor. Ptf: Passive temporal fingerprinting. In Integrated Network Management (IM), 2011 IFIP/IEEE International Symposium on, pages 289-296, May 2011.

[12] K. Gao, C. Corbett, and R. Beyah. A passive approach to wireless device fingerprinting. In Dependable Systems and Networks (DSN), 2010 IEEE/IFIP International Conference on, pages 383-392, June 2010.

[13] T. Kohno, A. Broido, and K. Claffy. Remote physical device finger- printing. Dependable and Secure Computing, IEEE Transactions on, 2(2):93-108, April 2005.

[14] O. Kosut, L. Jia, R. Thomas, and L. Tong. Limiting false data attacks on power system state estimation. In Information Sciences and Systems (CISS), 2010 44th Annual Conference on, pages 1-6, March 2010.

[15] R. Langner. To kill a centrifuge. http://www.langner.com/en/ wp-content/uploads/2013/11/To-kill-a-centrifuge.pdf.

[16] H. Lin, A. Slagell, C. Di Martino, Z. Kalbarczyk, and R. K. Iyer. Adapt- ing bro into scada: Building a specification-based intrusion detection system for the dnp3 protocol. In Proceedings of the Eighth Annual Cy- ber Security and Information Intelligence Research Workshop, CSIIRW '13, pages 5:1-5:4, New York, NY, USA, 2013. ACM.

[17] L. Ljung. Perspectives on system identification. Annual Reviews in Control, 34(1):1 - 12, 2010.

[18] S. Radhakrishnan, A. Uluagac, and R. Beyah. Gtid: A technique for physical device and device type fingerprinting. Dependable and Secure Computing, IEEE Transactions on, PP(99):1-1, 2014.

[19] G. Shu and D. Lee. Network protocol system fingerprinting - a formal approach. In INFOCOM 2006. 25th IEEE International Conference on Computer Communications. Proceedings, pages 1-12, April 2006.

[20] S. Sridhar, A. Hahn, and M. Govindarasu. Cyber-physical system secu- rity for the electric power grid. Proceedings of the IEEE, 100(1):210- 224, Jan 2012.

[21] O. Ureten and N. Serinken. Wireless security through rf fingerprinting. Electrical and Computer Engineering, Canadian Journal of, 32(1):27- 33, Winter 2007.

[22] F. Valeur, G. Vigna, C. Kruegel, and R. Kemmerer. Comprehensive approach to intrusion detection alert correlation. Dependable and Secure Computing, IEEE Transactions on, 1(3):146-169, July 2004.

[23] J. Verba and M. Milvich. Idaho national laboratory supervisory control and data acquisition intrusion detection system (scada ids). In Technologies for Homeland Security, 2008 IEEE Conference on, pages 469-473, May 2008.

[24] J.-W. Wang and L.-L. Rong. "cascade-based attack vulnerability on the us power grid ". Safety Science, 47(10):1332 - 1336, 2009.

[25] L. Watkins, W. Robinson, and R. Beyah. A passive solution to the cpu resource discovery problem in cluster grid networks. Parallel and Distributed Systems, IEEE Transactions on, 22(12):2000-2007, Dec 2011.

[26] M. Zalewski. p0f v3. http://lcamtuf.coredump.cx/p0f3/. Accessed 2015- 03-25.