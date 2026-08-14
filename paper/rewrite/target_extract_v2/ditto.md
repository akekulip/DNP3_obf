# ditto: WAN Traffic Obfuscation at Line Rate

**Authors (as printed):** Roland Meier (ETH Zurich); Vincent Lenders (armasuisse); Laurent Vanbever (ETH Zurich)

**Venue / year (as printed on the PDF):** Network and Distributed Systems Security (NDSS) Symposium 2022, 24-28 April 2022, San Diego, CA, USA. ISBN 1-891562-74-6. https://dx.doi.org/10.14722/ndss.2022.24056

**Printed year:** 2022  
**Source file:** `target/2022_NDSS_ditto WAN Traffic Obfuscation at Line Rate.pdf`  |  **Pages:** 17  |  **Re-extracted with:** PyMuPDF 1.28.2 (column-aware, reading-order)


---

## Section hierarchy (in reading order)

- I. INTRODUCTION  _(p1)_
- II. MODEL  _(p2)_
    - A. Network model  _(p2)_
    - B. Attacker model  _(p2)_
    - C. Security goals  _(p2)_
- III. BACKGROUND ON PROGRAMMABLE SWITCHES  _(p3)_
- V. COMPUTING EFFICIENT TRAFFIC PATTERNS  _(p5)_
- VI. TRAFFIC SHAPING IN THE DATA PLANE  _(p5)_
- VII. SECURITY ANALYSIS AND LIMITATIONS  _(p6)_
    - A. Security goals  _(p6)_
    - B. Limitations  _(p6)_
- VIII. IMPLEMENTATION  _(p7)_
- IX. EVALUATION  _(p8)_
    - A. Datasets and methodology  _(p8)_
    - B. Performance and efficiency in today's hardware  _(p9)_
    - C. Security in today's hardware  _(p11)_
    - D. Performance and efficiency in future hardware  _(p12)_
- X. RELATED WORK  _(p14)_
- XI. CONCLUSION  _(p15)_
- ACKNOWLEDGEMENTS  _(p15)_
- REFERENCES  _(p15)_

## Figure / table captions (verbatim first sentence)

- **Fig. 1** (p1): ditto adds padding and chaff packets such that the.
- **Fig. 2** (p2): Network model.
- **Fig. 3** (p4): ditto overview.
- **Fig. 4** (p8): ditto implements hierarchical queueing by sending.
- **TABLE I** (p8): Evaluation summary.
- **Fig. 5** (p9): Evaluation setup.
- **Fig. 6** (p10): Input vs.
- **Fig. 7** (p11): ditto compared to the baseline.
- **Fig. 8** (p11): IPG distributions.
- **Fig. 9** (p12): ditto performs round-robin scheduling up to an error.
- **Fig. 10** (p12): DF attack accuracy.
- **Fig. 11** (p13): Overhead depending
- **Fig. 13** (p13): Overhead for using the same pattern (length l) over 10.
- **Fig. 14** (p14): Packet reordering de-
- **TABLE II** (p15): Comparison of ditto's key properties with related work.

## References (101 entries)

[1] Alexa top sites in united states. https://www.alexa.com/topsite s/countries/US. (Accessed on 07/21/2020).

[2] Arista 7170 series. https://www.arista.com/en/products/7170- series.

[3] Barefoot networks, google cloud, onf and p4.org to showcase p4 runtime-based control of network switches. https://finance.yah oo.com/news/barefoot-networks-google-cloud-onf-120000 850.html. (Accessed on 04/15/2021).

[4] Barefoot networks wins deals from at&t, tencent, alibaba and baidu for programmable switches. https://www.thefastmode.com/tec hnology-solutions/10724-barefoot-networks-wins-deals-from -at-t-tencent-alibaba-and-baidu-for-programmable-switches. (Accessed on 04/15/2021).

[5] Earlystopping. https://keras.io/api/callbacks/early_stopping/.

[6] GnuTLS. https://gnutls.org.

[7] Ikt-systeme der armee. https://www.vtg.admin.ch/de/aktuell/t hemen/programme-projekte/ikt-systeme-der-armee.html#col lapse_id_content_vtg-internet_de_aktuell_themen_programm e-projekte_ikt-systeme-der-armee_jcr_content_contentPar_ac cordion_1. (Accessed on 06/10/2021).

[8] Intel® tofino™series programmable ethernet switch asic. https://w ww.intel.com/content/www/us/en/products/network-io/pro grammable-ethernet-switch/tofino-series/tofino.html.

[9] iperf. https://iperf.fr/.

[10] P4-16 portable switch architecture (PSA). https://p4.org/p4-spec /docs/PSA-v1.1.0.html.

[11] Passive fiber optic network tap | g-tap m series | gigamon. https: //www.gigamon.com/products/access-traffic/network-tap s/g-tap-m-series.html. (Accessed on 06/08/2021).

[12] Pjsip. https://www.pjsip.org/.

[13] RFC4253. https://datatracker.ietf.org/doc/html/rfc4253.

[14] RFC4301. https://datatracker.ietf.org/doc/html/rfc4301.

[15] RFC4303. https://datatracker.ietf.org/doc/html/rfc4303.

[16] Scapy. https://scapy.net/.

[17] SWAN scottish wide area network. https://www.scottishwan.com.

[18] Tcpdump & libpcap. https://www.tcpdump.org/.

[19] Tor project. https://www.torproject.org/.

[20] Wide area networks. https://portal.ct.gov/DAS/BEST/Networ k-Services/Wide-Area-Networks.

[21] IEEE standard for local and metropolitan area networks: Media access control (mac) security. IEEE Std 802.1AE-2006, 2006. 15

[22] Abbas Acar, Hossein Fereidooni, Tigist Abera, Amit Kumar Sikder, Markus Miettinen, Hidayet Aksu, Mauro Conti, Ahmad-Reza Sadeghi, and Selcuk Uluagac. Peek-a-boo: I see your smart home activities, even encrypted! In Proceedings of the 13th ACM Conference on Security and Privacy in Wireless and Mobile Networks, WiSec '20. ACM, 2020.

[23] Amazon. Global infrastructure. https://aws.amazon.com/about -aws/global-infrastructure/.

[24] Mikhail Andreev, Avi Klausner, Trishita Tiwari, Ari Trachtenberg, and Arkady Yerukhimovich. Nothing but net: Invading android user privacy using only network access patterns. arXiv preprint arXiv:1807.02719, 2018.

[25] APCON. Passive optical tap. https://www.apcon.com/hardwar e/network-taps/apcon-tap. (Accessed on 06/08/2021).

[26] Noah Apthorpe, Danny Yuxing Huang, Dillon Reisman, Arvind Narayanan, and Nick Feamster. Keeping the smart home private with smart(er) iot traffic shaping. Proceedings on Privacy Enhancing Technologies, 2019(3), 01 Jul. 2019.

[27] The Atlantic. The creepy, long-standing practice of undersea cable tapping. https://www.theatlantic.com/international/archive /2013/07/the-creepy-long-standing-practice-of-undersea-c able-tapping/277855/. (Accessed on 04/06/2021). Georgia Technology Authority. Wan service. https://gta.georgia

[28] .gov/gta-services/georgia-enterprise-technology-services- gets/managing-your-gets-services/wan-service. (Accessed on 06/15/2021).

[29] Aviatrix. Is amazon inter-region peering encrypted? https://aviatri x.com/learn-center/answered-access/is-amazon-inter-regio n-peering-encrypted/.

[30] Microsoft Azure. Backbone networking infrastructure. https://azure .microsoft.com/en-us/global-infrastructure/global-network.

[31] Michael Backes, Goran Doychev, Markus Dürmuth, and Boris Köpf. Speaker recognition in encrypted voice streams. In European Sympo- sium on Research in Computer Security. Springer, 2010.

[32] Ludovic Barman, Italo Dacosta, Mahdi Zamani, Ennan Zhai, Bryan Ford, Jean-Pierre Hubaux, and Joan Feigenbaum. Prifi: A low- latency local-area anonymous communication network. arXiv preprint arXiv:1710.10237, 2017.

[33] Pat Bosshart, Dan Daly, Glen Gibb, Martin Izzard, Nick McKe- own, Jennifer Rexford, Cole Schlesinger, Dan Talayco, Amin Vahdat, George Varghese, et al. P4: Programming protocol-independent packet processors. ACM SIGCOMM Computer Communication Review, 44(3), 2014.

[34] Jonas Bushart and Christian Rossow. Padding ain't enough: Assessing the privacy guarantees of encrypted DNS. In 10th USENIX Workshop on Free and Open Communications on the Internet (FOCI 20). USENIX Association, 2020.

[35] Arturo Cabanas. Managing security on AWS. https://d1.awsstatic .com/events/Summits/PublicSector2020/Managing_Security _on_AWS_MGMT104_ENGLISH.pdf, 2020.

[36] Xiang Cai, Rishab Nithyanand, and Rob Johnson. Cs-buflo: A congestion sensitive website fingerprinting defense. In Proceedings of the 13th Workshop on Privacy in the Electronic Society, 2014.

[37] Xiang Cai, Xin Cheng Zhang, Brijesh Joshi, and Rob Johnson. Touching from a distance: Website fingerprinting attacks and defenses. In Proceedings of the 2012 ACM conference on Computer and communications security, 2012.

[38] CAIDA. The CAIDA anonymized internet traces dataset (april 2008 - january 2019). https://www.caida.org/data/passive/passive _dataset.xml.

[39] CAIDA. Trace statistics for CAIDA passive oc48 and oc192 traces. https://www.caida.org/data/passive/trace_stats/.

[40] Catapult-project. catapult/web_page_replay_go at master. https://g ithub.com/catapult-project/catapult/tree/master/web_page_ replay_go.

[41] David Chaum. The dining cryptographers problem: Unconditional sender and recipient untraceability. Journal of cryptology, 1(1), 1988.

[42] Chen Chen, Daniele E Asoni, David Barrera, George Danezis, and Adrain Perrig. Hornet: High-speed onion routing at the network layer. In Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security, 2015.

[43] Chen Chen, Daniele E Asoni, Adrian Perrig, David Barrera, George Danezis, and Carmela Troncoso. TARANET: Traffic-Analysis Re- sistant Anonymity at the Network Layer. 2018 IEEE European Symposium on Security and Privacy (EuroS&P), 2018.

[44] Hong-Yen Chen and Tsung-Nan Lin. The challenge of only one flow problem for traffic classification in identity obfuscation environments. IEEE Access, 2021.

[45] Cisco. System security configuration guide for cisco 8000 series routers, ios xr release 7.0.x - implementing trustworthy systems. https://www.cisco.com/c/en/us/td/docs/iosxr/cisco80 00/security/70x/b-system-security-cg-cisco8000-70x/imple menting-trustworthy-systems.html.

[46] B. Coskun and N. Memon. Tracking encrypted voip calls via robust hashing of network flows. In 2010 IEEE International Conference on Acoustics, Speech and Signal Processing, 2010.

[47] Network Critical. Passive fiber taps. https://www.networkcritical .com/fiber-taps. (Accessed on 06/08/2021).

[48] Roger Dingledine, Nick Mathewson, and Paul Syverson. Tor: The second-generation onion router. Technical report, Naval Research Lab Washington DC, 2004.

[49] Gerard Draper-Gil, Arash Habibi Lashkari, Mohammad Saiful Islam Mamun, and Ali A Ghorbani. Characterization of encrypted and vpn traffic using time-related. In Proceedings of the 2nd international conference on information systems security and privacy (ICISSP), 2016.

[50] R. Dubin, A. Dvir, O. Pele, and O. Hadar. I know what you saw last minute—encrypted http adaptive video streaming title classification. IEEE Transactions on Information Forensics and Security, 12(12), 2017.

[51] K. P. Dyer, S. E. Coull, T. Ristenpart, and T. Shrimpton. Peek-a-boo, i still see you: Why efficient traffic analysis countermeasures fail. In 2012 IEEE Symposium on Security and Privacy, May 2012.

[52] Paul Emmerich, Sebastian Gallenmüller, Daniel Raumer, Florian Wohlfart, and Georg Carle. MoonGen: A Scriptable High-Speed Packet Generator. In Internet Measurement Conference 2015 (IMC'15), Tokyo, Japan, 2015.

[53] Don Fedyk. Ethernet-traffic flow security. https://www.ieee802.o rg/1/files/public/docs2019/new-fedyk-traffic-flow-security -0219.pdf, 2019.

[54] S. Feghhi and D. J. Leith. A web traffic analysis attack using only timing information. IEEE Transactions on Information Forensics and Security, 11(8), 2016.

[55] fmadio. 100% line rate 100g packet capture. https://www.f mad.io/products- 100G- packet- capture.html. (Accessed on 04/08/2021).

[56] Ya Gao and Zhenling Wang. A review of p4 programmable data planes for network security. Mobile Information Systems, 2021, 2021.

[57] David Goldschlag, Michael Reed, and Paul Syverson. Onion routing. Communications of the ACM, 42(2), 1999.

[58] Yong Guan, Xinwen Fu, Dong Xuan, P.U. Shenoy, R. Bettati, and Wei Zhao. Netcamo: camouflaging network traffic for qos-guaranteed mission critical applications. IEEE Transactions on Systems, Man, and Cybernetics, 31(4), 2001.

[59] The Guardian. Gchq taps fibre-optic cables for secret access to world's communications. https://www.theguardian.com/uk/2013/jun /21/gchq-cables-secret-world-communications-nsa. (Accessed on 06/08/2021).

[60] David Hancock and Jacobus Van der Merwe. Hyper4: Using p4 to virtualize the programmable data plane. In Proceedings of the 12th International on Conference on emerging Networking EXperiments and Technologies, 2016.

[61] Jamie Hayes and George Danezis. k-fingerprinting: A robust scalable website fingerprinting technique. In 25th USENIX Security Symposium (USENIX Security 16), Austin, TX, 2016. USENIX Association.

[62] Craig Hill and Stephen Orr. Innovations in ethernet encryption (802.1ae - MACsec) for securing high speed (1-100ge) wan deploy- ments. https://www.cisco.com/c/dam/en/us/td/docs/solutio ns/Enterprise/Security/MACsec/WP-High-Speed-WAN-Encr ypt-MACsec.pdf. 16

[63] Chi-Yao Hong, Srikanth Kandula, Ratul Mahajan, Ming Zhang, Vijay Gill, Mohan Nanduri, and Roger Wattenhofer. Achieving high utiliza- tion with software-driven wan. In Proceedings of the ACM SIGCOMM 2013 Conference on SIGCOMM, 2013.

[64] C. Hopps. Ip-tfs: Ip traffic flow security using aggregation and fragmentation. https://tools.ietf.org/id/draft- ietf- ipsecme- iptfs-06.html, 2021.

[65] North Dakota ITD. Wide area network (wan). https://www.nd.g ov/itd/services/wide-area-network-wan.

[66] Sushant Jain, Alok Kumar, Subhasree Mandal, Joon Ong, Leon Poutievski, Arjun Singh, Subbaiah Venkata, Jim Wanderer, Junlan Zhou, Min Zhu, et al. B4: Experience with a globally-deployed software defined wan. ACM SIGCOMM Computer Communication Review, 43(4), 2013.

[67] Marc Juarez, Mohsen Imani, Mike Perry, Claudia Diaz, and Matthew Wright. Toward an efficient website fingerprinting defense. In Ioan- nis Askoxylakis, Sotiris Ioannidis, Sokratis Katsikas, and Catherine Meadows, editors, Computer Security - ESORICS 2016, Cham, 2016. Springer International Publishing.

[68] Keysight. Flex tap passive fiber optical taps. https://www.keysigh t.com/ch/de/products/network-visibility/network-taps/flex- tap-fiber-optical.html. (Accessed on 06/08/2021).

[69] Elie F. Kfoury, Jorge Crichigno, and Elias Bou-Harb. An exhaustive survey on p4 programmable data plane switches: Taxonomy, applica- tions, challenges, and future trends. IEEE Access, 9, 2021.

[70] Stevens Le Blond, David Choffnes, William Caldwell, Peter Druschel, and Nicholas Merritt. Herd: A scalable, traffic analysis resistant anonymity network for voip systems. In ACM SIGCOMM Computer Communication Review, volume 45. ACM, 2015.

[71] Wen Ming Liu, Lingyu Wang, Pengsu Cheng, Kui Ren, Shunzhi Zhu, and Mourad Debbabi. Pptp: Privacy-preserving traffic padding in web- based applications. IEEE Trans. Dependable Sec. Comput., 11(6), 2014.

[72] Yaqun Liu, Jinlong Zhao, Guomin Zhang, and Changyou Xing. Netobfu: A lightweight and efficient network topology obfuscation defense scheme. Computers & Security, 110, 2021.

[73] Jon McLachlan, Andrew Tran, Nicholas Hopper, and Yongdae Kim. Scalable onion routing with torsk. In Proceedings of the 16th ACM conference on Computer and communications security, 2009.

[74] Roland Meier, David Gugelmann, and Laurent Vanbever. iTAP: In- network traffic analysis prevention using software-defined networks. In Proceedings of the Symposium on SDN Research. ACM, 2017.

[75] Roland Meier, Petar Tsankov, Vincent Lenders, Laurent Vanbever, and Martin Vechev. NetHide: Secure and practical network topology obfuscation. In 27th USENIX Security Symposium (USENIX Security 18), Baltimore, MD, 2018. USENIX Association.

[76] Microsoft. Azure encryption overview. https://docs.microsoft.com /en-us/azure/security/fundamentals/encryption-overview.

[77] Sandra Kay Miller. Hacking at the speed of light. Securitysolu- tions.com, 2006. Apr 1, 2006.

[78] J. Muehlstein, Y. Zion, M. Bahumi, I. Kirshenboim, R. Dubin, A. Dvir, and O. Pele. Analyzing https encrypted traffic to identify user's operating system, browser and application. In 2017 14th IEEE Annual Consumer Communications Networking Conference (CCNC), 2017.

[79] Netberg. Aurora 710. https://netbergtw.com/products/aurora- 710.

[80] Edgecore Networks. Wedge 100bf-65x. https://www.edge-core.c om/productsInfo.php?cls=1&cls2=180&cls3=181&id=334.

[81] Se Eun Oh, Shuai Li, and Nicholas Hopper. Fingerprinting keywords in search queries over tor. Proceedings on Privacy Enhancing Technologies, 2017(4), 2017. OVH. OVH tasks. http://travaux.ovh.net/?do=details&id=

[82] 10705&, 2014.

[83] Andriy Panchenko, Lukas Niessen, Andreas Zinnen, and Thomas Engel. Website fingerprinting in onion routing based anonymization networks. In Proceedings of the 10th annual ACM workshop on Privacy in the electronic society. ACM, 2011.

[84] Ania Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, and George Danezis. The Loopix Anonymity System. USENIX Security, 2017. Profitap. Fiber taps. https://www.profitap.com/fiber- taps/.

[85] (Accessed on 06/08/2021).

[86] Michael G Reed, Paul F Syverson, and David M Goldschlag. Anony- mous connections and onion routing. IEEE Journal on Selected areas in Communications, 16(4), 1998.

[87] Brendan Saltaformaggio, Hongjun Choi, Kristen Johnson, Yonghwi Kwon, Qi Zhang, Xiangyu Zhang, Dongyan Xu, and John Qian. Eavesdropping on fine-grained user activities within smartphone apps over encrypted network traffic. In WOOT, 2016.

[88] Roei Schuster, Vitaly Shmatikov, and Eran Tromer. Beauty and the burst: Remote identification of encrypted video streams. In 26th USENIX Security Symposium (USENIX Security 17), Vancouver, BC, 2017. USENIX Association.

[89] Tal Shapira and Yuval Shavitt. Flowpic: Encrypted internet traffic classification is as easy as image recognition. In IEEE INFOCOM 2019-IEEE Conference on Computer Communications Workshops (IN- FOCOM WKSHPS). IEEE, 2019.

[90] Naveen Kr Sharma, Chenxingyu Zhao, Ming Liu, Pravein G Kannan, Changhoon Kim, Arvind Krishnamurthy, and Anirudh Sivaraman. Programmable calendar queues for high-speed packet scheduling. In 17th USENIX Symposium on Networked Systems Design and Imple- mentation (NSDI 20), 2020.

[91] Y. Shi and S. Biswas. Website fingerprinting using traffic analysis of dynamic webpages. In 2014 IEEE Global Communications Confer- ence, 2014.

[92] Payap Sirinam, Mohsen Imani, Marc Juarez, and Matthew Wright. Deep fingerprinting: Undermining website fingerprinting defenses with deep learning. In Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security, CCS '18, New York, NY, USA, 2018. Association for Computing Machinery.

[93] Vincent F Taylor, Riccardo Spolaor, Mauro Conti, and Ivan Marti- novic. Robust smartphone app identification via encrypted network traffic analysis. IEEE Transactions on Information Forensics and Security, 13(1), 2018.

[94] Liang Wang, Hyojoon Kim, Prateek Mittal, and Jennifer Rexford. Programmable in-network obfuscation of traffic. arXiv preprint arXiv:2006.00097, 2020.

[95] Tao Wang, Xiang Cai, Rishab Nithyanand, Rob Johnson, and Ian Goldberg. Effective attacks and provable defenses for website fin- gerprinting. In 23rd USENIX Security Symposium (USENIX Security 14), San Diego, CA, 2014. USENIX Association.

[96] Tao Wang and Ian Goldberg. Walkie-talkie: An efficient defense In 26th USENIX against passive website fingerprinting attacks. Security Symposium (USENIX Security 17), Vancouver, BC, 2017. USENIX Association.

[97] Tao Wang and Ian Goldberg. Walkie-talkie: An efficient defense against passive website fingerprinting attacks. In 26th USENIX Security Symposium (USENIX Security 17), 2017.

[98] Wei Wang, Mehul Motani, and Vikram Srinivasan. Dependent link padding algorithms for low latency anonymity systems. In Proceed- ings of the 15th ACM conference on Computer and communications security. ACM, 2008.

[99] X. Wang, S. Chen, and S. Jajodia. Network flow watermarking attack In 2007 IEEE on low-latency anonymous communication systems. Symposium on Security and Privacy (SP '07), 2007.

[100] Charles V Wright, Scott E Coull, and Fabian Monrose. Traffic morphing: An efficient defense against statistical traffic analysis. In NDSS, volume 9. Citeseer, 2009.

[101] Fan Zhang, Wenbo He, Xue Liu, and Patrick G Bridges. Inferring users' online activities through traffic analysis. In Proceedings of the fourth ACM conference on Wireless network security. ACM, 2011. 17
