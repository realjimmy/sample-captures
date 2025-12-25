# Wireshark samples

[中文版 (Chinese)](index_cn.md) | [English](index_en.md)

- [Wireshark samples](#wireshark-samples)
  - [General / Unsorted](#general--unsorted)
  - [ADSL CPE](#adsl-cpe)
  - [Viruses and worms](#viruses-and-worms)
  - [Crack Traces](#crack-traces)
  - [PROTOS Test Suite Traffic](#protos-test-suite-traffic)
  - [Specific Protocols and Protocol Families](#specific-protocols-and-protocol-families)
    - [AirTunes](#airtunes)
    - [Apache Cassandra](#apache-cassandra)
    - [ARP/RARP](#arprarp)
    - [ATSC3 Protocols](#atsc3-protocols)
      - [ALP Protocol](#alp-protocol)
      - [LLS (Low Level Signalling) Protocol](#lls-low-level-signalling-protocol)
      - [MP4 init segments and segments](#mp4-init-segments-and-segments)
      - [ALC/LCT ROUTE/DASH, MMTP](#alclct-routedash-mmtp)
    - [Spanning Tree Protocol](#spanning-tree-protocol)
    - [Bluetooth](#bluetooth)
    - [CredSSP](#credssp)
    - [UDP-Lite](#udp-lite)
    - [NFS Protocol Family](#nfs-protocol-family)
    - [Server Message Block (SMB)/Common Internet File System (CIFS)](#server-message-block-smbcommon-internet-file-system-cifs)
    - [Legacy Implementations of SMB](#legacy-implementations-of-smb)
    - [Browser Elections](#browser-elections)
    - [SMB-Locking](#smb-locking)
    - [SMB-Direct](#smb-direct)
    - [SMB3.1 handshake](#smb31-handshake)
    - [SMB3 encryption](#smb3-encryption)
    - [SMB3.1.1 encryption](#smb311-encryption)
      - [Intial value](#intial-value)
      - [Negotiate protocol request](#negotiate-protocol-request)
      - [Negotiate protocol response](#negotiate-protocol-response)
      - [Session setup request (1st)](#session-setup-request-1st)
      - [Session setup response (1st)](#session-setup-response-1st)
      - [Session setup request (2nd)](#session-setup-request-2nd)
    - [TCP](#tcp)
    - [MPTCP](#mptcp)
    - [Parallel Virtual File System (PVFS)](#parallel-virtual-file-system-pvfs)
    - [HyperText Transport Protocol (HTTP)](#hypertext-transport-protocol-http)
    - [Telnet](#telnet)
    - [TFTP](#tftp)
    - [UFTP](#uftp)
    - [Routing Protocols](#routing-protocols)
    - [SNMP](#snmp)
    - [Network Time Protocol](#network-time-protocol)
    - [SyncE Protocol](#synce-protocol)
    - [PostgreSQL v3 Frontend/Backend Protocol](#postgresql-v3-frontendbackend-protocol)
    - [MySQL protocol](#mysql-protocol)
    - [MS SQL Server protocol - Tabular Data Stream (TDS)](#ms-sql-server-protocol---tabular-data-stream-tds)
    - [Netgear NSDP](#netgear-nsdp)
    - [VendorLanProtocolFamily](#vendorlanprotocolfamily)
    - [Cisco](#cisco)
    - [DECT](#dect)
    - [DECT-MITEL-RFP](#dect-mitel-rfp)
    - [Sigtran Protocol Family](#sigtran-protocol-family)
    - [Stream Control Transmission Protocol (SCTP)](#stream-control-transmission-protocol-sctp)
    - [IPMI](#ipmi)
    - [IPMB](#ipmb)
    - [SIP and RTP](#sip-and-rtp)
    - [RTSP Protocol](#rtsp-protocol)
    - [H.223](#h223)
    - [H.265/HEVC](#h265hevc)
    - [MGCP](#mgcp)
    - [USB Raw (dlt 186)](#usb-raw-dlt-186)
    - [USB with Linux encapsulation (dlt 189)](#usb-with-linux-encapsulation-dlt-189)
    - [USB with USBPcap encapsulation](#usb-with-usbpcap-encapsulation)
    - [USB Link Layer](#usb-link-layer)
    - [USB packets with Darwin (macOS, etc.) headers](#usb-packets-with-darwin-macos-etc-headers)
    - [FreeBSD usbdump format file](#freebsd-usbdump-format-file)
    - [WAP Protocol Family](#wap-protocol-family)
    - [X.509 Digital Certificates](#x509-digital-certificates)
    - [Lightweight Directory Access Protocol (LDAP)](#lightweight-directory-access-protocol-ldap)
    - [Link Layer Discovery Protocol (LLDP)](#link-layer-discovery-protocol-lldp)
    - [SAN Protocol Captures (iSCSI, ATAoverEthernet, FibreChannel, SCSI-OSD and other SAN related protocols)](#san-protocol-captures-iscsi-ataoverethernet-fibrechannel-scsi-osd-and-other-san-related-protocols)
    - [Peer-to-peer protocols](#peer-to-peer-protocols)
      - [MANOLITO Protocol](#manolito-protocol)
      - [BitTorrent Protocol](#bittorrent-protocol)
      - [SoulSeek Protocol](#soulseek-protocol)
      - [JXTA Protocol](#jxta-protocol)
      - [SMPP (Short Message Peer-to-Peer) Protocol](#smpp-short-message-peer-to-peer-protocol)
    - [Kaspersky Update Protocol](#kaspersky-update-protocol)
    - [Kerberos and keytab file for decryption](#kerberos-and-keytab-file-for-decryption)
    - [mDNS \& Apple Rendezvous](#mdns--apple-rendezvous)
    - [Point-To-Point (PPP)](#point-to-point-ppp)
    - [Point-To-Point over Ethernet](#point-to-point-over-ethernet)
    - [X.400](#x400)
    - [Direct Message Protocol](#direct-message-protocol)
    - [STANAG 5066 SIS](#stanag-5066-sis)
    - [STANAG 5066 DTS](#stanag-5066-dts)
    - [RTP Norm](#rtp-norm)
    - [DCE/RPC and MSRPC-based protocols](#dcerpc-and-msrpc-based-protocols)
      - [DSSETUP MSRPC interface](#dssetup-msrpc-interface)
      - [NSPI MSRPC Interface](#nspi-msrpc-interface)
      - [ROP MSRPC Interface](#rop-msrpc-interface)
      - [WINREG Interface](#winreg-interface)
      - [WITNESS Interface](#witness-interface)
      - [MS-TSCH Interface](#ms-tsch-interface)
    - [IPsec](#ipsec)
      - [Example 1: ESP Payload Decryption and Authentication Checking Examples](#example-1-esp-payload-decryption-and-authentication-checking-examples)
      - [Example 2: Dissection of encrypted (and UDP-encapsulated) IKEv2 and ESP messages](#example-2-dissection-of-encrypted-and-udp-encapsulated-ikev2-and-esp-messages)
    - [Pro-MPEG FEC - Professional video FEC data over RTP](#pro-mpeg-fec---professional-video-fec-data-over-rtp)
    - [SSL with decryption keys](#ssl-with-decryption-keys)
    - [SSH with decryption keys](#ssh-with-decryption-keys)
    - [MCPE/RakNet](#mcperaknet)
    - [NDMP](#ndmp)
    - [Kismet Client/Server protocol](#kismet-clientserver-protocol)
    - [Kismet Drone/Server protocol](#kismet-droneserver-protocol)
    - [DTLS with decryption keys](#dtls-with-decryption-keys)
    - [DTLS JPAKE as used in ThreadGroup Commissioning](#dtls-jpake-as-used-in-threadgroup-commissioning)
    - [ETHERNET Powerlink v1](#ethernet-powerlink-v1)
    - [ETHERNET Powerlink v2](#ethernet-powerlink-v2)
    - [Architecture for Control Networks (ACN)](#architecture-for-control-networks-acn)
    - [Intellon Homeplug (INT51X1)](#intellon-homeplug-int51x1)
    - [Wifi / Wireless LAN captures / 802.11](#wifi--wireless-lan-captures--80211)
    - [TrunkPack Network Control Protocol (TPNCP)](#trunkpack-network-control-protocol-tpncp)
    - [EtherCAT](#ethercat)
    - [iWARP Protocol Suite](#iwarp-protocol-suite)
    - [IPv6 (and tunneling mechanism)](#ipv6-and-tunneling-mechanism)
    - [TTEthernet (TTE)](#ttethernet-tte)
    - [GSM](#gsm)
    - [UMTS](#umts)
      - [IuB interface](#iub-interface)
      - [Iu-CS over IP interface(MoC)](#iu-cs-over-ip-interfacemoc)
      - [Iu-CS over IP interface(MtC)](#iu-cs-over-ip-interfacemtc)
    - [X11](#x11)
    - [Gopher](#gopher)
    - [InfiniBand](#infiniband)
    - [Network News Transfer Protocol (NNTP)](#network-news-transfer-protocol-nntp)
    - [FastCGI (FCGI)](#fastcgi-fcgi)
    - [Lontalk (EIA-709.1) encapsulated in EIA-852](#lontalk-eia-7091-encapsulated-in-eia-852)
    - [DVB-CI (Common Interface)](#dvb-ci-common-interface)
    - [ANSI C12.22 (c1222)](#ansi-c1222-c1222)
    - [HDCP](#hdcp)
    - [openSAFETY](#opensafety)
    - [Radio Frequency Identification (RFID), and Near-Field Communication (NFC)](#radio-frequency-identification-rfid-and-near-field-communication-nfc)
    - [IEC 60870-5-104](#iec-60870-5-104)
    - [IEC 61850 9-2](#iec-61850-9-2)
    - [SISO-STD-002](#siso-std-002)
    - [STANAG-5602 SIMPLE](#stanag-5602-simple)
    - [S7COMM - S7 Communication](#s7comm---s7-communication)
    - [Harman Pro HiQnet](#harman-pro-hiqnet)
    - [DJI Drones control Protocol](#dji-drones-control-protocol)
    - [HCrt (Hotline Command-response Transaction) Protocol](#hcrt-hotline-command-response-transaction-protocol)
    - [DOF (Distributed Object Framework) Protocols](#dof-distributed-object-framework-protocols)
    - [CBOR (Concise Binary Object Representation)](#cbor-concise-binary-object-representation)
    - [RADIUS (RFC 2865)](#radius-rfc-2865)
    - [Distributed Interactive Simulation (IEEE 1278)](#distributed-interactive-simulation-ieee-1278)
    - [Financial Information eXchange (FIX)](#financial-information-exchange-fix)
    - [UserLog](#userlog)
    - [OpenFlow](#openflow)
    - [ISO 8583-1](#iso-8583-1)
    - [DNP3](#dnp3)
    - [System Calls](#system-calls)
    - [Linux netlink](#linux-netlink)
    - [Oracle TNS / SQLnet / OCI / OPI](#oracle-tns--sqlnet--oci--opi)
    - [Lawo EmberPlus S101/Glow](#lawo-emberplus-s101glow)
    - [HP ERM](#hp-erm)
    - [Automotive Protocols](#automotive-protocols)
    - [Steam In-Home Streaming Protocol](#steam-in-home-streaming-protocol)
    - [Wi-SUN low power RF Protocol](#wi-sun-low-power-rf-protocol)
    - [Nano / RaiBlocks Cryptocurrency Protocol](#nano--raiblocks-cryptocurrency-protocol)
    - [ua/udp, ua3g and noe protocols (Alcatel-Lucent Enterprise)](#uaudp-ua3g-and-noe-protocols-alcatel-lucent-enterprise)
    - [DICOM](#dicom)
    - [ETSI Intelligent Transport Systems (ITS) Protocols](#etsi-intelligent-transport-systems-its-protocols)
    - [NetBIOS](#netbios)
    - [Dynamic Link Exchange Protocol (DLEP)](#dynamic-link-exchange-protocol-dlep)
    - [Asphodel Protocol](#asphodel-protocol)
    - [Protobuf](#protobuf)
    - [MessagePack](#messagepack)
    - [gRPC](#grpc)
    - [AllJoyn](#alljoyn)
    - [Thrift](#thrift)
    - [Huawei's GRE bonding control (RFC8157)](#huaweis-gre-bonding-control-rfc8157)
    - [ADWS](#adws)
    - [NTLMSSP](#ntlmssp)
    - [Zabbix Protocol](#zabbix-protocol)
    - [DHCPFO Protocol](#dhcpfo-protocol)
    - [COTP (ISO 8073)](#cotp-iso-8073)
    - [MDB](#mdb)
    - [TPM 2.0](#tpm-20)
  - [Captures in specific file formats](#captures-in-specific-file-formats)
  - [Captures used in Wireshark testing](#captures-used-in-wireshark-testing)


## General / Unsorted
[rpl-dio-mc-nsa-optional-tlv-dissector-sample.pcap.gz](files/pcap.gz/rpl-dio-mc-nsa-optional-tlv-dissector-sample.pcap.gz) (libpcap) ICMPv6 IPv6 Routing Protocol for Low-Power and Lossy Networks (RPL) DODAG Information Object (DIO) control messages with optional type-length-value (TLV) in an Node State and Attributes (NSA) object in a Metric Container (MC).

[ipv4frags.pcap](files/pcap/ipv4frags.pcap) (libpcap) ICMP Echo request (1400B) response with Fragments (MTU=1000 on one side).

[tfp_capture.pcapng](files/pcapng/tfp_capture.pcapng) (libpcap) Tinkerforge protocol captures over TCP/IP and USB.

[Obsolete_Packets.cap](files/cap/Obsolete_Packets.cap) (libpcap) Contains various obscure/no longer in common use protocols, including Banyan VINES, [AppleTalk](https://wiki.wireshark.org/AppleTalk) and DECnet.

[Apple_IP-over-IEEE_1394_Packet.pcap](files/pcap/Apple_IP-over-IEEE_1394_Packet.pcap) (libpcap) An ICMP packet encapsulated in Apple's IP-over-1394 (ap1394) protocol

[SkypeIRC.cap](files/cap/SkypeIRC.cap) (libpcap) Some Skype, IRC and DNS traffic.

[ipp.pcap](files/pcap/ipp.pcap) (libpcap) CUPS printing via IPP (test page)

[IrDA_Traffic.ntar](files/ntar/IrDA_Traffic.ntar) (pcapng) Various IrDA packets, use Wireshark 1.3.0 (SVN revision 28866 or higher) to view

[9p.cap](files/cap/9p.cap) (libpcap) Plan 9 9P protocol, various message types.

[EmergeSync.cap](files/cap/EmergeSync.cap) (libpcap) rsync packets, containing the result of an "emerge sync" operation on a Gentoo system

[afs.cap.gz](files/cap.gz/afs.cap.gz) (libpcap) Andrew File System, based on RX protocol. Various operations.

[ancp.pcap.gz](files/pcap.gz/ancp.pcap.gz) (libpcap) Access Node Control Protocol (ANCP).

[ascend.trace.gz](files/gz/ascend.trace.gz) (Ascend WAN router) Shows how Wireshark parses special Ascend data

[atm_capture1.cap](files/cap/atm_capture1.cap) (libpcap) A trace of ATM Classical IP packets.

[bacnet-arcnet-linux.cap](files/cap/bacnet-arcnet-linux.cap) (libpcap) Some BACnet packets encapsulated in ARCnet framing

[bfd-raw-auth-simple.pcap](files/pcap/bfd-raw-auth-simple.pcap) (libpcap) BFD packets using simple password authentication.

[bfd-raw-auth-md5.pcap](files/pcap/bfd-raw-auth-md5.pcap) (libpcap) BFD packets using md5 authentication.

[bfd-raw-auth-sha1.pcap](files/pcap/bfd-raw-auth-sha1.pcap) (libpcap) BFD packets using SHA1 authentication.

[BT_USB_LinCooked_Eth_80211_RT.ntar.gz](files/gz/BT_USB_LinCooked_Eth_80211_RT.ntar.gz) (pcapng) A selection of Bluetooth, Linux mmapped USB, Linux Cooked, Ethernet, IEEE 802.11, and IEEE 802.11 [RadioTap](https://wiki.wireshark.org/RadioTap) packets in a pcapng file, to showcase the power of the file format, and Wireshark's support for it. Currently, Wireshark doesn't support files with multiple Section Header Blocks, which this file has, so it cannot read it. In addition, the first packet in the file, a Bluetooth packet, is corrupt - it claims to be a packet with a Bluetooth pseudo-header, but it contains only 3 bytes of data, which is too small for a Bluetooth pseudo-header.

[bootparams.cap.gz](files/cap.gz/bootparams.cap.gz) (libpcap) A couple of rpc.bootparamsd 'getfile' and 'whoami' requests.

[chargen-udp.pcap](files/pcap/chargen-udp.pcap) (libpcap) Chargen over UDP.

[chargen-tcp.pcap](files/pcap/chargen-tcp.pcap) (libpcap) Chargen over TCP.

[cmp_IR_sequence_OpenSSL-Cryptlib.pcap](files/pcap/cmp_IR_sequence_OpenSSL-Cryptlib.pcap) (libpcap) Certificate Management Protocol (CMP) version 2 encapsulated in HTTP. Full "Initialization Request".

[cmp_IR_sequence_ OpenSSL-EJBCA.pcap](files/pcap/cmp_IR_sequence_-OpenSSL-EJBCA.pcap) (libpcap) Certificate Management Protocol (CMP) version 2 encapsulated in HTTP. Full "Initialization Request". Authentication with CRMF regToken.

[cmp-trace.pcap.gz](files/pcap.gz/cmp-trace.pcap.gz) (libpcap) Certificate Management Protocol (CMP) certificate requests.

[cmp-in-http-with-errors-in-cmp-protocol.pcap.gz](files/pcap.gz/cmp-in-http-with-errors-in-cmp-protocol.pcap.gz) (libpcap) Certificate Management Protocol (CMP) version 2 encapsulated in HTTP. Full "Initialization Request" and rejected "Key Update Request". There are some errors in the CMP packages.

[cmp_in_http_with_pkixcmp-poll_content_type.pcap.gz](files/pcap.gz/cmp_in_http_with_pkixcmp-poll_content_type.pcap.gz) (libpcap) Certificate Management Protocol (CMP) version 2 encapsulated in HTTP. The CMP messages are of the deprecated but used content-type "pkixcmp-poll", so they are using the TCP transport style. In two of the four CMP messages, the content type is not explicitly set, thus they cannot be dissected correctly.

[cigi2.pcap.gz](files/pcap.gz/cigi2.pcap.gz) (libpcap) Common Image Generator Interface (CIGI) version 2 packets.

[cigi3.pcap.gz](files/pcap.gz/cigi3.pcap.gz) (libpcap) Common Image Generator Interface (CIGI) version 3 packets.

[cisco-nexus92-erspan-marker.pcap](files/pcap/cisco-nexus92-erspan-marker.pcap) A marker packet sent from a Cisco Nexus switch running NXOS 9.2, with a non-zero ASIC relative timestamp and the corresponding UTC absolute timestamp.

[cisco-nexus10-erspan-marker.pcap](files/pcap/cisco-nexus10-erspan-marker.pcap) A marker packet sent from a Cisco Nexus switch running NXOS 10, with a zero ASIC relative timestamp and the corresponding UTC absolute timestamp.

[ciscowl.pcap.gz](files/pcap.gz/ciscowl.pcap.gz) (libpcap) Cisco Wireless LAN Context Control Protocol ([WLCCP](https://wiki.wireshark.org/WLCCP)) version 0x0

[ciscowl_version_0xc1.pcap.gz](files/pcap.gz/ciscowl_version_0xc1.pcap.gz) (libpcap) Cisco Wireless LAN Context Control Protocol ([WLCCP](https://wiki.wireshark.org/WLCCP)) version 0xc1. Includes following base message types: SCM Advertisements, EAP Auth., Path Init, Registration

[configuration_test_protocol_aka_loop.pcap](files/pcap/configuration_test_protocol_aka_loop.pcap) (libpcap) Example of an Ethernet loopback with a 'third party assist'

[cops-pr.cap.gz](files/cap.gz/cops-pr.cap.gz) (libpcap) A sample of COPS traffic.

[couchbase_subdoc_multi.pcap](files/pcap/couchbase_subdoc_multi.pcap) (libpcap) A sample Couchbase binary protocol file including sub-document multipath request/responses.

[couchbase-create-bucket.pcapng](files/pcapng/couchbase-create-bucket.pcapng) (libpcap) A sample Couchbase binary protocol file that includes a create_bucket command.

[couchbase-lww.pcap](files/pcap/couchbase-lww.pcap) (libpcap) A sample Couchbase binary protocol file including set_with_meta, del_with_meta and get_meta commands with last write wins support.

[couchbase-xattr.pcapng](files/pcapng/couchbase-xattr.pcapng) (libpcap) A sample capture of the XATTR features in the Couchbase binary protocol.

[dct2000_test.out](files/out/dct2000_test.out) (dct2000) A sample [DCT2000](https://wiki.wireshark.org/DCT2000) file with examples of most supported link types

[dhcp.pcap](files/pcap/dhcp.pcap) (libpcap) A sample of DHCP traffic.

[dhcp-and-dyndns.pcap.gz](files/pcap.gz/dhcp-and-dyndns.pcap.gz) (libpcap) A sample session of a host doing dhcp first and then dyndns.

[dhcp-auth.pcap.gz](files/pcap.gz/dhcp-auth.pcap.gz) (libpcap) A sample packet with dhcp authentication information.

[PRIV_bootp-both_overload.pcap](files/pcap/PRIV_bootp-both_overload.pcap) (libpcap) A DHCP packet with sname and file field overloaded.

[PRIV_bootp-both_overload_empty-no_end.pcap](files/pcap/PRIV_bootp-both_overload_empty-no_end.pcap) (libpcap) A DHCP packet with overloaded field and all end options missing.

[dccp_trace.pcap.gz](files/pcap.gz/dccp_trace.pcap.gz) (libpcap) A trace of [DCCP](https://wiki.wireshark.org/DCCP) packet types.

[dns.cap](files/cap/dns.cap) (libpcap) Various DNS lookups.

[dualhome.iptrace](files/iptrace/dualhome.iptrace) (AIX iptrace) Shows Ethernet and Token Ring packets captured in the same file.

[dvmrp-conv.cap](files/cap/dvmrp-conv.cap) Shows Distance Vector Multicast Routing Protocol packets.

[eapol-mka.pcap](files/pcap/eapol-mka.pcap) (libpcap) EAPoL-MKA (MKA, IEEE 802.1X) traffic.

[epmd.pcap](files/pcap/epmd.pcap) Two Erlang Port Mapper Daemon ([EPMD](https://wiki.wireshark.org/EPMD)) messages.

[Ethernet_Pause_Frame.cap](files/cap/Ethernet_Pause_Frame.cap) Ethernet Pause Frame packets.

[exablaze_trailer.pcap](files/pcap/exablaze_trailer.pcap) (libpcap) A sample capture with Exablaze timestamp trailers.

[exec-sample.pcap](files/pcap/exec-sample.pcap) The [exec](https://wiki.wireshark.org/Exec) (rexec) protocol

[fw1_mon2018.cap](files/cap/fw1_mon2018.cap) (Solaris snoop) [CheckPoint](https://wiki.wireshark.org/CheckPoint) FW-1 fw monitor file (include new Encryption check points). Enable FW-1 interpretation in Ethernet protocol interpretation

[genbroad.snoop](files/snoop/genbroad.snoop) (Solaris snoop) Netware, Appletalk, and other broadcasts on an ethernet network.

[Mixed1.cap](files/cap/Mixed1.cap) (MS [NetMon](https://wiki.wireshark.org/NetMon)) Some Various, Mixed Packets.

[small-system-misc-ping.etl](files/etl/small-system-misc-ping.etl) (MS ETL) Various events, ping and browser packets.

[gryphon.cap](files/cap/gryphon.cap) (libpcap) A trace of Gryphon packets. This is useful for testing the Gryphon plug-in.

[hart_ip.pcap](files/pcap/hart_ip.pcap) (libpcap) Some HART-IP packets, including both an UDP and TCP session.

[hsrp.pcap](files/pcap/hsrp.pcap) (libpcap) Some Cisco HSRP packets, including some with Opcode 3 (Advertise) .

[hsrp-and-ospf-in-LAN](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/hsrp-and-ospf-in-LAN) (libpcap) HSRP state changes and OSPF LSAs sent during link up/down/up.

[ieee802154-association-data.pcap.gz](files/pcap.gz/ieee802154-association-data.pcap.gz) (libpcap) A device associates to a coordinator, and transmits some data frames.

[ipv4_cipso_option.pcap](files/pcap/ipv4_cipso_option.pcap) (libpcap) A few IP packets with CIPSO option.

[imap.cap](files/cap/imap.cap) (libpcap) A short IMAP session using Mutt against an MSX server.

[RawPacketIPv6Tunnel-UK6x.cap](files/cap/RawPacketIPv6Tunnel-UK6x.cap) (libpcap) - Some IPv6 packets captured from the 'sit1' interface on Linux. The IPv6 packets are carried over the UK's UK6x network, but what makes this special, is the fact that it has a Link-Layer type of "Raw packet data" - which is something that you don't see everyday.

[iseries.cap](files/cap/iseries.cap) (IBM iSeries communications trace) FTP and Telnet traffic between two AS/400 LPARS.

[FTPv6-1.cap](files/cap/FTPv6-1.cap) (Microsoft Network Monitor) FTP packets (IPv6)

[FTPv6-2.cap](files/cap/FTPv6-2.cap) (Microsoft Network Monitor) Some more FTP packets (IPv6)

[gearman.pcap](files/pcap/gearman.pcap) Gearman Protocol packets

[isl-2-dot1q.cap](files/cap/isl-2-dot1q.cap) (libpcap) A trace including both ISL and 802.1q-tagged Ethernet frames. Frames 1 through 381 represent traffic encapsulated using Cisco's ISL, frames 382-745 show traffic sent by the same switch after it had been reconfigured to support 802.1Q trunking.

[kafka-testcases-v4.tar.gz](files/gz/kafka-testcases-v4.tar.gz) (libpcap) Apache Kafka dissector testcases (generated with [this scripts](https://github.com/laz2/genpcap)).

[lacp1.pcap.gz](files/pcap.gz/lacp1.pcap.gz) (libpcap) Link Aggregation Control Protocol (LACP, IEEE 802.3ad) traffic.

[linx-setup-pingpong-shutdown.pcap](files/pcap/linx-setup-pingpong-shutdown.pcap) (libpcap) Successive setup of LINX on two hosts, exchange of packets and shutdown.

[llrp.cap](files/cap/llrp.cap) EPCglobal [Low-Level Reader Protocol (LLRP)](https://wiki.wireshark.org/LLRP)

[llt-sample.pcap](files/pcap/llt-sample.pcap) Veritas [Low Latency Transport (LLT)](https://wiki.wireshark.org/LLT) frames

[lustre-lnet_sample.cap.gz](files/cap.gz/lustre-lnet_sample.cap.gz) (libpcap) Lustre Filesystem with Lustre Fileystem Network under it (tcp)

[macsec_cisco_trunk.pcap](files/pcap/macsec_cisco_trunk.pcap) (libpcap) MACsec/802.1AE session, manual keys, 3750X switch-to-switch (Trustsec) forced across a half-duplex 10M hub connection, destination mac addresses can be seen for Cisco VTP, RSTP (RPVST+), CDP, EIGRP etc.

[messenger.pcap](files/pcap/messenger.pcap) (libpcap) a few messenger example packets.

[metamako_trailer.pcap](files/pcap/metamako_trailer.pcap) (libpcap) the Metamako timestamp trailer format.

[mms.pcap.gz](files/pcap.gz/mms.pcap.gz) (libpcap) Manufacturing Message Specification traffic.

[SITA-Protocols.cap](files/cap/SITA-Protocols.cap) (libpcap) Some SITA WAN (Societe Internationale de Telecommunications Aeronautiques sample packets (contains X.25, International Passenger Airline Reservation System, Unisys Transmittal System and Frame Relay packets)

[msnms.pcap](files/pcap/msnms.pcap) (libpcap) MSN Messenger packets.

[MSN_CAP.xlsx](files/xlsx/MSN_CAP.xlsx) (xlsx) MSN Messenger packets in xlsx format.

[monotone-netsync.cap.gz](files/cap.gz/monotone-netsync.cap.gz) (libpcap) Some fragments (the full trace is > 100MB gzipped) of a checkout of the monotone sources.

[mpeg2_mp2t_with_cc_drop01.pcap](files/pcap/mpeg2_mp2t_with_cc_drop01.pcap) (libpcap) MPEG2 (RFC 2250) Transport Stream example with a dropped CC packet (anonymized with tcpurify).

[mpls-basic.cap](files/cap/mpls-basic.cap) (libpcap) A basic sniff of MPLS-encapsulated IP packets over Ethernet.

[mpls-exp.cap](files/cap/mpls-exp.cap) (libpcap) IP packets with EXP bits set.

[mpls-te.cap](files/cap/mpls-te.cap) (libpcap) MPLS Traffic Engineering sniffs. Includes RSVP messages with MPLS/TE extensions and OSPF link updates with MPLS LSAs.

[mpls-twolevel.cap](files/cap/mpls-twolevel.cap) (libpcap) An IP packet with two-level tagging.

[netbench_1.cap](files/cap/netbench_1.cap) (libpcap) A capture of a reasonable amount of NetBench traffic. It is useful to see some of the traffic a NetBench run generates.

[NMap Captures.zip](files/zip/NMap-Captures.zip) (libpcap) Some captures of various [NMap](http://nmap.org/%E2%80%8E) port scan techniques.

[OptoMMP.pcap](files/pcap/OptoMMP.pcap) A capture of some OptoMMP read/write quadlet/block request/response packets. [OptoMMP documentation](http://www.opto22.com/site/documents/doc_drilldown.aspx?aid=1875).

[pana.cap](files/cap/pana.cap) (libpcap) PANA authentication session (pre-draft-15a so Wireshark 0.99.5 or before is required to view it correctly).

[pana-draft18.cap](files/cap/pana-draft18.cap) (libpcap) PANA authentication session (draft-18 so Wireshark 0.99.7 or later is required to view it correctly).

[pana-rfc5191.cap](files/cap/pana-rfc5191.cap) (libpcap) PANA authentication and re-authentication sequences.

[pim-reg.cap](files/cap/pim-reg.cap) (libpcap) Protocol Independent Multicast, with IPv6 tunnelled within IPv6

[ptpv2.pcap](files/pcap/ptpv2.pcap) (libpcap) various Precision Time Protocol (IEEE 1588) version 2 packets.  
[ptpv2_anon.pcapng](files/pcapng/ptpv2_anon.pcapng) ptpv2.pcap modified with [TraceWrangler](http://www.tracewrangler.com/) to use non-standard ports (42319,42320)

[Public_nic](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/Public_nic) (libpcap) A bunch of SSDP (Universal Plug and Play protocol) announcements.

[rpl_sample.cap.gz](files/cap.gz/rpl_sample.cap.gz) (libpcap) A RIPL sample capture.

[rtp_example.raw.gz](files/gz/rtp_example.raw.gz) (libpcap) A VoIP sample capture of a [H323](https://wiki.wireshark.org/H323) call (including [H225](https://wiki.wireshark.org/H225), [H245](https://wiki.wireshark.org/H245), [RTP](https://wiki.wireshark.org/RTP) and [RTCP](https://wiki.wireshark.org/RTCP)).

[RTP_L16_monaural_sample.pcapng](files/pcapng/RTP_L16_monaural_sample.pcapng) (libpcap) A sample L16 monaural (44100Hz) [RTP](https://wiki.wireshark.org/RTP) stream

[rtps_cooked.pcapng](files/pcapng/rtps_cooked.pcapng) (libpcap) Manually generated RTPS traffic covering a range of submessages and parameters.

[rsvp-PATH-RESV.pcap](files/pcap/rsvp-PATH-RESV.pcap) (libpcap) A sample RSVS capture with PATH and RESV messages.

[sbus.pcap](files/pcap/sbus.pcap) (libpcap) An [EtherSBus](https://wiki.wireshark.org/EtherSBus) (sbus) sample capture showing some traffic between the programming tool (PG5) and a PCD (Process Control Device, a PLC; Programmable Logic Controller).

[Ether-S-IO_traffic_01.pcap.gz](files/pcap.gz/Ether-S-IO_traffic_01.pcap.gz) (libpcap) An [EtherSIO](https://wiki.wireshark.org/EtherSIO) (esio) sample capture showing some traffic between a PLC from Saia-Burgess Controls AG and some remote I/O stations (devices called PCD3.T665).

[simulcrypt.pcap](files/pcap/SIMULCRYPT.pcap) (libpcap) A SIMULCRYPT sample capture, [SIMULCRYPT](https://wiki.wireshark.org/SIMULCRYPT) over [TCP](https://wiki.wireshark.org/TCP)) on ports 8600, 8601, and 8602.

[TeamSpeak2.pcap](files/pcap/TeamSpeak2.pcap) (libpcap) A [TeamSpeak2](https://wiki.wireshark.org/TeamSpeak2) capture

[tipc-publication-payload-withdrawal.pcap](files/pcap/tipc-publication-payload-withdrawal.pcap) (libpcap) TIPC port name publication, payload messages and port name withdrawal.

[tipc-bundler-messages.pcap](files/pcap/tipc-bundler-messages.pcap) (libpcap) TIPCv2 Bundler Messages

[tipc_v2_fragmenter_messages.pcap.gz](files/pcap.gz/tipc_v2_fragmenter_messages.pcap.gz) (libpcap) TIPCv2 Fragmenter Messages

[TIPC-over-TCP_disc-publ-inventory_sim-withd.pcap.gz](files/pcap.gz/TIPC-over-TCP_disc-publ-inventory_sim-withd.pcap.gz) (libpcap) TIPCv2 over TCP (port 666) traffic generated by the inventory simulation of the TIPC demo package.

[TIPC-over-TCP_MTU-discovery.pcap.gz](files/pcap.gz/TIPC-over-TCP_MTU-discovery.pcap.gz) (libpcap) TIPCv2 over TCP (port 666) - Link State messages with filler bytes for MTU discovery.

[toshiba.general.gz](files/gz/toshiba.general.gz) (Toshiba) Just some general usage of a Toshiba ISDN router. There are three link types in this trace: PPP, Ethernet, and LAPD.

[uma_ho_req_bug.cap](files/cap/uma_ho_req_bug.cap) (libpcap) A "UMA URR HANDOVER REQUIRED" packet.

[unistim_phone_startup.pcap](files/pcap/unistim_phone_startup.pcap) (libpcap) Shows a phone booting up, requesting ip address and establishing connection with cs2k server.

[unistim-call.pcap](files/pcap/unistim-call.pcap) (libpcap) Shows one phone calling another via cs2k server over unistim

[v6.pcap](files/pcap/v6.pcap) (libpcap) Shows IPv6 (6-Bone) and ICMPv6 packets.

[v6-http.cap](files/cap/v6-http.cap) (libpcap) Shows IPv6 (SixXS) HTTP.

[vlan.cap.gz](files/cap.gz/vlan.cap.gz) (libpcap) Lots of different protocols, all running over 802.1Q virtual lans.

[vms_tcptrace.txt](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/vms_tcptrace.txt) (VMS TCPtrace) Sample output from VMS TCPtrace. Mostly NFS packets.

[vms_tcptrace-full.txt](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/vms_tcptrace-full.txt) (VMS TCPtrace) Sample output from VMS TCPtrace/full. Mostly NFS packets.

[vnc-sample.pcap](files/pcap/vnc-sample.pcap) Virtual Networking Computing (VNC) session trace

[vxi-11.pcap.gz](files/pcap.gz/vxi-11.pcap.gz) (libpcap) Scan for instruments attached to an Agilent E5810A VXI-11-to-GPIB adapter.

[WINS-Replication-01.cap.gz](files/cap.gz/WINS-Replication-01.cap.gz) (libpcap) WINS replication trace.

[WINS-Replication-02.cap.gz](files/cap.gz/WINS-Replication-02.cap.gz) (libpcap) WINS replication trace.

[WINS-Replication-03.cap.gz](files/cap.gz/WINS-Replication-03.cap.gz) (libpcap) WINS replication trace.

[wpsdata.cap](files/cap/wpsdata.cap) (libpcap) WPS expanded EAP trace.

[openwire_sample.tar.gz](files/gz/openwire_sample.tar.gz) (libpcap) ActiveMQ [OpenWire](https://wiki.wireshark.org/OpenWire) trace.

[drda_db2_sample.tgz](files/tgz/drda_db2_sample.tgz) (libpcap) DRDA trace from DB2.

[starteam_sample.tgz](files/tgz/starteam_sample.tgz) (libpcap) [StarTeam](https://wiki.wireshark.org/StarTeam) trace.

[rtmp_sample.tgz](files/tgz/rtmp_sample.tgz) (libpcap) RTMP (Real Time Messaging Protocol) trace.

[rtmpt.pcap.bz2](files/pcap.bz2/rtmpt.pcap.bz2) (libpcap) RTMPT trace with macromedia-fsc TCP-stuff.

[sample-imf.pcap.gz](files/pcap.gz/sample-imf.pcap.gz) (libpcap) [SMTP](https://wiki.wireshark.org/SMTP) and [IMF](https://wiki.wireshark.org/IMF) capture. Also shows some [MIME_multipart](https://wiki.wireshark.org/MIME_multipart).

[smtp.pcap](files/pcap/smtp.pcap) (libpcap) [SMTP](https://wiki.wireshark.org/SMTP) simple example.

[captura.NNTP.cap](files/cap/captura.NNTP.cap) (libpcap) [NNTP](https://wiki.wireshark.org/NNTP) News simple example.

[sample-TNEF.pcap.gz](files/pcap.gz/sample-TNEF.pcap.gz) (libpcap) [TNEF](https://wiki.wireshark.org/TNEF) trace containing two attachments as well as message properties. Also shows some [SMTP](https://wiki.wireshark.org/SMTP), [IMF](https://wiki.wireshark.org/IMF) and [MIME_multipart](https://wiki.wireshark.org/MIME_multipart) trace.

[wol.pcap](files/pcap/wol.pcap) (libpcap) [WakeOnLAN](https://wiki.wireshark.org/WakeOnLAN) sample packets generated from both ether-wake and a Windows-based utility.

[zigbee-join-authenticate.pcap.gz](files/pcap.gz/zigbee-join-authenticate.pcap.gz) (libpcap) Two devices join a [ZigBee](https://wiki.wireshark.org/ZigBee) network and authenticate with the trust center. Network is encrypted using network keys and trust center link keys.

[IGMP dataset.pcap](files/pcap/IGMP-dataset.pcap) (igmp) igmp version 2 dataset

[yami.pcap](files/pcap/yami.pcap) (yami) sample packets captured when playing with YAMI4 library

[DHCPv6.pcap](files/pcap/DHCPv6.pcap) (dhcpv6) sample dhcpv6 client server transaction solicit(fresh lease)/advertise/request/reply/release/reply.

[dhcpv6_1.pcap](files/pcap/dhcpv6_1.pcap) (dhcpv6) sample dhcpv6 client server transaction solicit(requesting-old-lease)/advertise/request/reply/release/reply.

[ecpri.pcap](files/pcap/ecpri.pcap) (libpcap)[eCPRI](https://wiki.wireshark.org/eCPRI) sample file.

[iperf3-udp.pcapng.gz](files/pcapng.gz/iperf3-udp.pcapng.gz) (pcapng) sample capture for iPerf3 in reverse UDP mode using `iperf3 -u -t 3 -c ping.online.net -p5208 -R`

[220614_ip_flags_google.pcapng](files/pcapng/220614_ip_flags_google.pcapng) IPv4 ICMP traffic showing various ip.flags bits. Includes Reserved Bit / Evil Bit packets. ([Nping: add support to set Reserved/Evil bit in ip flags](https://github.com/nmap/nmap/issues/2486))

[ultimate_wireshark_protocols_pcap_220213.pcap.zip](files/pcap.zip/ultimate_wireshark_protocols_pcap_220213.pcap.zip) Capture file containing a wide variety of protocols, useful for fuzzing. Created by Sharon Brizinov. (This is not the same as Johannes Weber's [Ultimate PCAP](https://weberblog.net/the-ultimate-pcap/))

[The-Ultimate-PCAP.7z](files/7z/The-Ultimate-PCAP.7z) Ultimate PCAP file made by Johannes Weber.

[irdma-sample.pcap](https://gitlab.com/-/project/7898047/uploads/b2ed13ee46b1028d90aa271e9181aad7/irdma-sample.pcap) [15440: irdma: IBM i TRCCNN RDMA dissector](https://gitlab.com/wireshark/wireshark/-/merge_requests/15440)

[sample.pcapng](https://gitlab.com/-/project/7898047/uploads/ac7df8335b967e5f1d5eb735574002ee/sample.pcapng) [17808: FR: Add possibility to define custom UUIDs, Chars & Handles to BTLE dissector](https://gitlab.com/wireshark/wireshark/-/issues/17808)

## ADSL CPE
Here are some captures of the data sent on an ADSL line by the Neufbox 6, the CPE provided by french ISP SFR. Capturing was done by running tcpdump via SSH on the 8/35 ATM VC.

Sensitive informations like passwords, phone numbers, personal IP/MAC addresses... were redacted and replaced by equivalent ones (checksums were recalculated too).

Used protocols includes DHCP, PPP, Ethernet, IP, ARP, L2TP, SIP, RTP, DNS, ICMP, DHCPv6, NTP, IGMPv2, ICMPv6, HTTP, HTTPS, Syslog, RADIUS...

[nb6-startup.pcap](files/pcap/nb6-startup.pcap) Includes etablishement of IPv4 and IPv6 connections, download of configuration, connection to a VoIP server...

[nb6-http.pcap](files/pcap/nb6-http.pcap) Three different HTTP requests: first was sent on the private IPv4 network (IPoE), second was sent on the public IPv4 network, third was sent on the public IPv6 network (L2TP tunnel).

[nb6-telephone.pcap](files/pcap/nb6-telephone.pcap) A brief phone call to SFR's voicemail service.

[nb6-hotspot.pcap](files/pcap/nb6-hotspot.pcap) Someone connecting to SFR's wireless community network.

A detailed analysis of these captures, along with an explanation of how these captures were realized, is available in French [here](https://lafibre.info/sfr-tutoriels/captures-reseau-du-demarrage-et-fonctionnement-de-la-neufbox-6/).

## Viruses and worms
[slammer.pcap](files/pcap/slammer.pcap) Slammer worm sending a DCE RPC packet. bnb

[dns-remoteshell.pcap](files/pcap/dns-remoteshell.pcap) Watch frame 22 Ethereal detecting DNS Anomaly caused by remoteshell riding on DNS port - DNS Anomaly detection made easy by ethereal .. Anith Anand

## Crack Traces
[teardrop.cap](files/cap/teardrop.cap) Packets 8 and 9 show the overlapping IP fragments in a Teardrop attack.

[zlip-1.pcap](files/pcap/zlip-1.pcap) DNS exploit, endless, pointing to itself message decompression flaw.

[zlip-2.pcap](files/pcap/zlip-2.pcap) DNS exploit, endless cross referencing at message decompression.

[zlip-3.pcap](files/pcap/zlip-3.pcap) DNS exploit, creating a very long domain through multiple decompression of the same hostname, again and again.

[can-2003-0003.pcap](files/pcap/can-2003-0003.pcap) Attack for [CERT advisory CA-2003-03](http://www.cert.org/advisories/CA-2003-03.html)

## PROTOS Test Suite Traffic
The files below are captures of traffic generated by the [PROTOS](http://www.ee.oulu.fi/research/ouspg/protos/) test suite developed at the University of Oulu. They contain malformed traffic used to test the robustness of protocol implementations; they also test the robustness of protocol analyzers such as Wireshark.

[c04-wap-r1.pcap.gz](files/pcap.gz/c04-wap-r1.pcap.gz) Output from c04-wap-r1.jar

[c05-http-reply-r1.pcap.gz](files/pcap.gz/c05-http-reply-r1.pcap.gz) Output from c05-http-reply-r1.jar

[c06-ldapv3-app-r1.pcap.gz](files/pcap.gz/c06-ldapv3-app-r1.pcap.gz) Output from c06-ldapv3-app-r1.jar

[c06-ldapv3-enc-r1.pcap.gz](files/pcap.gz/c06-ldapv3-enc-r1.pcap.gz) Output from c06-ldapv3-enc-r1.jar

[c06-snmpv1-req-app-r1.pcap.gz](files/pcap.gz/c06-snmpv1-req-app-r1.pcap.gz) Output from c06-snmpv1-req-app-r1.jar

[c06-snmpv1-req-enc-r1.pcap.gz](files/pcap.gz/c06-snmpv1-req-enc-r1.pcap.gz) Output from c06-snmpv1-req-enc-r1.jar

[c06-snmpv1-trap-app-r1.pcap.gz](files/pcap.gz/c06-snmpv1-trap-app-r1.pcap.gz) Output from c06-snmpv1-trap-app-r1.jar

[c06-snmpv1-trap-enc-r1.pcap.gz](files/pcap.gz/c06-snmpv1-trap-enc-r1.pcap.gz) Output from c06-snmpv1-trap-enc-r1.jar

[c07-sip-r2.cap](files/cap/c07-sip-r2.cap) Output from c07-sip-r2.jar

## Specific Protocols and Protocol Families
3GPP [3gpp_mc.cap](files/cap/3gpp_mc.cap) (libpcap) 3gpp cn mc interface capture file, include megaco and ranap packet

### AirTunes
Apple [AirTunes](https://wiki.wireshark.org/AirTunes) protocol as used by [AirPort](https://wiki.wireshark.org/AirPort). See [http://git.zx2c4.com/Airtunes2/about/](http://git.zx2c4.com/Airtunes2/about/) [airtunes-1.pcap](files/pcap/airtunes-1.pcap)

### Apache Cassandra
[apache-cassandra-cql-v3.pcapng.gz](files/pcapng.gz/apache-cassandra-cql-v3.pcapng.gz) - CQL binary protocol version 3. Specification at [https://raw.githubusercontent.com/apache/cassandra/cassandra-2.1/doc/native_protocol_v3.spec](https://raw.githubusercontent.com/apache/cassandra/cassandra-2.1/doc/native_protocol_v3.spec).

### ARP/RARP
[arp-storm.pcap](files/pcap/arp-storm.pcap) (libpcap) More than 20 ARP requests per second, observed on a cable modem connection.  
([220703_arp-storm.pcapng](files/pcapng/220703_arp-storm.pcapng) arp-storm.pcap saved as pcapng including Name Resolution Block to speed up display)

[rarp_request.cap](files/cap/rarp_request.cap) (libpcap) A reverse ARP request.

[rarp_req_reply.pcapng](files/pcapng/rarp_req_reply.pcapng) (pcapng) RARP request and reply.

### ATSC3 Protocols
Standards/Specifications at [https://www.atsc.org/atsc-documents/type/3-0-standards/](https://www.atsc.org/atsc-documents/type/3-0-standards/)

#### ALP Protocol
Standard/Specification: ATSC3 A/330

[alp-sample1.pcap](files/pcap/alp-sample1.pcap) (libpcap) - Collected using SiliconDust box (Multiple PLP channel). Includes LLS (Link Layer Signalling) with LMT table (packet [#6 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/6)), packets with Sony PLP header extension (packets [#1 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/1),3,5,...) and data packets

[alp-sample2.pcap](files/pcap/alp-sample2.pcap) (libpcap) - Collected using SiliconDust box (Single PLP channel). Includes LLS (Link Layer Signalling) with LMT table (packet [#2 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/2)), packet with Sony L1D Time Info header extension (packet [#84 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/84)) and data packets

#### LLS (Low Level Signalling) Protocol
Standard/Specification: ATSC3 A/331

[lls-tables-alp.pcap](files/pcap/lls-tables-alp.pcap) (libpcap) - Collected using SiliconDust box from three ATSC3 stations. Packets [#1 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/1), [#3 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/3) - Signed Multi Table (contains SLT and SystemTime tables). Packet [#2 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/2), [#4 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/4) - CDT (Certification Data Table). Packet [#5 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/5) - System Time table. Packet [#6 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/6) - SLT (Service List Table). Packet [#7 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/7) - AEAT (Advanced Emergency Information Table). Packet [#8 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/8) - User Defined table.

#### MP4 init segments and segments
Standards/Specifications: ATSC3 A/331, ISO/IEC 14496-12, ISO/IEC 14496-14, 3GPP TS 26.244

Encapsulation: alp:ip:udp:alc:rmt-lct:mp4

[mp4-ftyp-styp-sidx.pcap](files/pcap/mp4-ftyp-styp-sidx.pcap) (libpcap) - Collected using SiliconDust from different ATSC3 stations (closed captions segments) Packet [#1 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/1) - MP4 segment (styp mp4 box). Extracted mp4: [styp](https://wiki.wireshark.org/uploads/0ee4c561b9c17098957fa9fcb5f2d756/styp.mp4). Packet [#2 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/2) - MP4 truncated segment (styp mp4 box). Extracted mp4: [styp-trunc](https://wiki.wireshark.org/uploads/d43f871dea86caebad5a834d2be1e0ca/styp-trunc.mp4). Packet [#3 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/3) - MP4 init segment (ftyp mp4 box). Extracted mp4: [ftyp](https://wiki.wireshark.org/uploads/fe86a796525ff6599d3c06f363031437/ftyp.mp4). Packet [#4 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/4) - MP4 truncated segment (sidx mp4 box). Extracted mp4: [sidx](https://wiki.wireshark.org/uploads/f980161e5d7b81f29c3eebbc2ea29806/sidx.mp4). Packet [#5 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/5) - MP4 segment (sidx mp4 box). Extracted mp4: [sidx-trunc](https://wiki.wireshark.org/uploads/e7ae787bec782917058013cb79e12ed0/sidx-trunc.mp4).

#### ALC/LCT ROUTE/DASH, MMTP
Standards/Specifications: ATSC3 A/331, RFC 5651, RFC 5775, ISO/IEC 23008-1

Encapsulation: alp:ip:udp:alc

[ch11-25-slt.pcap](files/pcap/ch11-25-slt.pcap) (libpcap) - Collected using SiliconDust from different ATSC3 stations. Includes signalling and data packets (ROUTE/DASH and MMTP)

### Spanning Tree Protocol
[stp.pcap](files/pcap/stp.pcap) (libpcap)

[STP_UplinkFast.pcapng](files/pcapng/STP_UplinkFast.pcapng) (pcapng) Cisco STP UplinkFast proxy multicast frames sent to 0100.0ccd.cdcd. This file contains a capture of proxy (also called dummy) multicast frames sent after a root port switchover on behalf of 3 dynamic unicast MAC addresses to update the "upstream" part of the network about the new path toward them. For each of the MAC addresses (001d.e50a.d740, 0800.2774.b2c5, e4be.ede3.f013), the switch sends out 4 frames using the particular MAC address as a source, and the 0100.0ccd.cdcd as a destination, with each frame using a different type: SNAP (OUI 0x00000c, PID 0x0115), AppleTalk (EtherType 0x809b), IPX (EtherType 0x8137), and ARP (EtherType 0x0806). The frame payload is just a stuffing to the minimal frame length; it has no meaning.

### Bluetooth
[l2ping.cap](files/cap/l2ping.cap) (Linux BlueZ hcidump) Contains some [Bluetooth](https://wiki.wireshark.org/Bluetooth) packets captured using hcidump, the packets were from the l2ping command that's included with the Linux BlueZ stack.

[Bluetooth1.cap](files/cap/Bluetooth1.cap) (Linux BlueZ hcidump) Contains some [Bluetooth](https://wiki.wireshark.org/Bluetooth) packets captured using hcidump.

### CredSSP
[ws-cssp.tgz](files/tgz/ws-cssp.tgz) Contains RDP sessions from Windows and freerdp clients, featuring CredSSP over TLS, GSS-KRB5, SPNEGO and U2U (user-to-user). Certificate key and Kerberos keytab included.

[TSRemoteGuardCreds.tgz](files/tgz/TSRemoteGuardCreds.tgz) Contains an RDP session using remoteguard (TSRemoteGuardCreds).

### UDP-Lite
Several [UDP-Lite](https://wiki.wireshark.org/UDP-Lite) packets, some correct, some wrong.

[udp_lite_full_coverage_0.pcap](files/pcap/udp_lite_full_coverage_0.pcap) If coverage=0, the full packet is checksummed over.

[udp_lite_illegal_1-7.pcap](files/pcap/udp_lite_illegal_1-7.pcap) Coverage values between 1..7 (illegal).

[udp_lite_normal_coverage_8-20.pcap](files/pcap/udp_lite_normal_coverage_8-20.pcap) Normal ones with correct checksums (legal).

[udp_lite_illegal_large-coverage.pcap](files/pcap/udp_lite_illegal_large-coverage.pcap) Three traces with coverage lengths greater than the packet length.

[udp_lite_checksum_0.pcap](files/pcap/udp_lite_checksum_0.pcap) checksum 0 is illegal.

### NFS Protocol Family
[nfs_bad_stalls.cap](files/cap/nfs_bad_stalls.cap) (libpcap) An NFS capture containing long stalls (about 38ms) in the middle of the responses to many read requests. This is useful for seeing the staircase effect in TCP Time Sequence Analysis.

[nfsv2.pcap.gz](files/pcap.gz/nfsv2.pcap.gz) (libpcap) Fairly complete trace of all [NFS](https://wiki.wireshark.org/NFS) v2 packet types.

[nfsv3.pcap.gz](files/pcap.gz/nfsv3.pcap.gz) (libpcap) Fairly complete trace of all [NFS](https://wiki.wireshark.org/NFS) v3 packet types.

[klm.pcap.gz](files/pcap.gz/klm.pcap.gz) (libpcap) A "fake" trace containing all [KLM](https://wiki.wireshark.org/KLM) functions.

[rquota.pcap.gz](files/pcap.gz/rquota.pcap.gz) (libpcap) A "fake" trace containing all [RQUOTA](https://wiki.wireshark.org/RQUOTA) functions.

[nsm.pcap.gz](files/pcap.gz/nsm.pcap.gz) (libpcap) A "fake" trace containing all [NSM](https://wiki.wireshark.org/NSM) functions.

[getsetacl.cap](files/cap/getsetacl.cap) (libpcap) A trace containing NFSACL functions.

[nfsv4.1_pnfs.cap](files/cap/nfsv4.1_pnfs.cap) NFSv4.1 trace containing pNFS.

### Server Message Block (SMB)/Common Internet File System (CIFS)
[smbtorture.cap.gz](files/cap.gz/smbtorture.cap.gz) (libpcap) Capture showing a wide range of SMB features. The capture was made using the Samba4 smbtorture suite, against a Windows Vista beta2 server.

See [SMB2#Example_capture_files](https://wiki.wireshark.org/SMB2#Example_capture_files) for more captures.

### Legacy Implementations of SMB
[smb-legacy-implementation.pcapng](files/pcapng/smb-legacy-implementation.pcapng) NetBIOS traffic from Windows for Workgroups v3.11. Shows NetBIOS over LLC and NetBIOS over IPX.

### Browser Elections
[smb-browser-elections.pcapng](files/pcapng/smb-browser-elections.pcapng) NetBIOS requires that a Master Browser tracks host announcements and responds to Browser Requests. Master Browser a elected by a list of criteria. The role of a master browser should be taken by a stable system, as browser elections can have a serious performance impact. This trace shows the a client with a misconfigured firewall, blocking incoming UDP port 138. Since the client can not find a master browser, it stalls all other systems by repeated browser elections.

### SMB-Locking
[SMB-locking.pcapng.gz](files/pcapng.gz/SMB-locking.pcapng.gz) (libpcap) SMB and SMB2 support opportunistic locking. Clients can send a lock request. If necessary, the server has to break conflicting locks by sending a lock request to the client. This is a bit unusual: We see requests from the server. A large number of lock requests is usually an indicator for poor performance. If lock requests are made as blocking IOs, users will experience that their application freezes in a seemingly random manner.

### SMB-Direct
[smb-direct-manin-the-middle-02-reassemble-frames9.pcap.gz](files/pcap.gz/smb-direct-man-in-the-middle-02-reassemble-frames9.pcap.gz) (libpcap) SMB-Direct over iWarp between two Windows 2012 machines proxied via a port redirector in order to capture the traffic.

### SMB3.1 handshake
[smb-on-windows-10.pcapng](files/pcapng/smb-on-windows-10.pcapng) (libpcap) Short sample of a SMB3 handshake between two workstations running Windows 10.

### SMB3 encryption
[smb3-aes-128-ccm.pcap](files/pcap/smb3-aes-128-ccm.pcap) short sample of a SMB3 connection to an encrypted (AES-128-CCM) share (session id 3d00009400480000, session key 28f2847263c83dc00621f742dd3f2e7b).

### SMB3.1.1 encryption
[smb311-aes-128-ccm-filt.pcap](files/pcap/smb311-aes-128-ccm-filt.pcap) short sample of a SMB3.1.1 connection to an encrypted (AES-128-CCM) share (session id 690000ac1c280000, session key b25a135fc3dc14269f20d7cbc8716b6b).

Preauth hash takes these values over the course of the session establishement:

#### Intial value
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

#### Negotiate protocol request
19 a0 81 73 9c 67 12 6a 6a 5a 68 52 39 63 fb d7 a5 84 cd 40 d5 7d ce af b6 1c c4 06 08 e5 e2 86 9d f7 04 1f 42 4d 39 a6 e1 11 d4 8c 8b 70 a0 51 5a 1d ea ae 7e 29 49 b0 1a 95 d8 b9 ae 22 1c bb

#### Negotiate protocol response
9b 8f 4c 61 dc 66 40 4c 40 1d 09 49 25 c9 9e 20 84 bb 39 15 1e 19 73 ff 65 b0 53 21 f1 da 9f d7 51 d1 9f 3d 90 9d 86 85 cd 1a 6d 5b 94 88 58 61 9f b9 c8 b8 4b ab 8b 59 77 91 89 bd c4 97 26 32

#### Session setup request (1st)
95 31 5f 50 0c 9f 5d c5 d4 a8 39 07 3b 58 02 12 bb 69 b7 cb 40 9e 70 73 ab 8f 3a d0 85 bf 62 ce a5 86 6d 7b 33 79 0f 56 c2 0a cb 38 be 3c 6a 05 48 38 f5 b4 44 a0 1f b5 a0 c1 d2 ce db b5 75 74

#### Session setup response (1st)
b5 00 d2 9c ae e7 8d 7e 75 73 94 c3 e2 41 15 8a bc 53 51 d0 bf c0 d7 89 b9 04 97 d8 15 9b 8a 40 0f 95 91 64 e0 cc 84 2e 32 7d 81 84 c8 53 19 dc e0 39 0c 1d 25 80 f9 d8 bc 1a bc 16 f5 f7 c6 79

#### Session setup request (2nd)
fb 11 6c 80 20 e2 3f d8 e4 e3 07 01 f1 da d7 af d8 e3 ff 22 0d c4 5b ff 1d 7f fb 92 ee a3 a6 89 5f 7f 49 39 b9 75 7e ed 97 a8 1e c4 fa d9 75 91 e8 81 73 de 78 1f 32 82 33 a6 f5 37 45 59 f1 2a

The final server decryption key is: F8 C1 A6 B5 44 E8 22 6F 98 EE 44 77 8E AF 31 6B

The final client decryption key is: 39 40 71 F1 A2 1D B5 BA 68 3E FA 86 8C 36 AE DF

### TCP
See the MPTCP section for MPTCP pcaps.

[200722_win_scale_examples_anon.pcapng](files/pcapng/200722_win_scale_examples_anon.pcapng) TCP Window Scaling examples - available, no scaling and missing/unknown.

[200722_tcp_anon.pcapng](files/pcapng/200722_tcp_anon.pcapng) Netcat - string, file and characters.

### MPTCP
[iperf-mptcp-0-0.pcap](files/pcap/iperf-mptcp-0-0.pcap) iperf between client and hosts with 2 interfaces and the linux implementation. There are 4 subflows, 2 of them actually successfully connected.

[redundant_stream1.pcapng](files/pcapng/redundant_stream1.pcapng) iperf with a redundant scheduler, i.e., the same data is sent across several subflows at the same time. Enable all the MPTCP options and you should be able to see Wireshark detect reinjections across subflows. For instance try the filter "tcp.options.mptcp.rawdataseqno == 1822294653": you should see 3 packets sending the same data on 3 different TCP connections.

[mptcp_v1.pcapng](files/pcapng/mptcp_v1.pcapng) This pcap was generated with the kernel 5.6 and shows the version 1 of MPTCP.

### Parallel Virtual File System (PVFS)
[pvfs2-sample.pcap](files/pcap/pvfs2-sample.pcap) (libpcap) PVFS2 copy operation (local file to PVFS2 file system)

### HyperText Transport Protocol (HTTP)
[http.cap](files/cap/http.cap) A simple HTTP request and response.

[http_gzip.cap](files/cap/http_gzip.cap) A simple HTTP request with a one packet gzip Content-Encoded response.

[http-chunked-gzip.pcap](files/pcap/http-chunked-gzip.pcap) A single HTTP request and response for [www.wireshark.org](http://www.wireshark.org/) (proxied using socat to remove SSL encryption). Response is gzipped and used chunked encoding. Added in January 2016.

[http_with_jpegs.cap.gz](files/cap.gz/http_with_jpegs.cap.gz) A simple capture containing a few JPEG pictures one can reassemble and save to a file.

[tcp-ethereal-file1.trace](files/trace/tcp-ethereal-file1.trace) (libpcap) A large POST request, taking many TCP segments.

[tcp-ecn-sample.pcap](files/pcap/tcp-ecn-sample.pcap) A sample TCP/HTTP of a file transfer using ECN (Explicit Congestion Notification) feature per RFC3168. Frame 48 experienced Congestion Encountered.

[http_redirects.pcapng](files/pcapng/http_redirects.pcapng) A sample TCP/HTTP with many 302 redirects per RFC 3986 ( [https://tools.ietf.org/html/rfc3986#section-5.4](https://tools.ietf.org/html/rfc3986#section-5.4)).

For captures using SSL/TLS, see [#SSL_with_decryption_keys](https://wiki.wireshark.org/SampleCaptures#ssl-with-decryption-keys).

### Telnet
[telnet-cooked.pcap](files/pcap/telnet-cooked.pcap) (libpcap) A telnet session in "cooked" (per-line) mode.

[telnet-raw.pcap](files/pcap/telnet-raw.pcap) (libpcap) A telnet session in "raw" (per-character) mode.

### TFTP
[tftp_rrq.pcap](files/pcap/tftp_rrq.pcap) (libpcap) A TFTP Read Request.

[tftp_wrq.pcap](files/pcap/tftp_wrq.pcap) (libpcap) A TFTP Write Request.

### UFTP
[UFTP_v3_transfer.pcapng](files/pcapng/UFTP_v3_transfer.pcapng) (pcapng) An UFTP v3 file transfer (unencrypted).

[UFTP_v4_transfer.pcapng](files/pcapng/UFTP_v4_transfer.pcapng) (pcapng) An UFTP v4 file transfer (unencrypted).

[UFTP_v5_transfer.pcapng](files/pcapng/UFTP_v5_transfer.pcapng) (pcapng) An UFTP v5 file transfer (unencrypted and encrypted).

### Routing Protocols
[bgp.pcapng.gz](files/pcapng.gz/bgp.pcapng.gz) (pcapng) BGP packets between three peers using communities and announcing six networks. The BGP implementation is FRRouting.

[bgp.pcap.gz](files/pcap.gz/bgp.pcap.gz) (libpcap) BGP packets, including AS path attributes.

[bgp_shutdown_communication.pcap](files/pcap/bgp_shutdown_communication.pcap) (libpcap) Sample packet for BGP Shutdown communication [https://tools.ietf.org/html/draft-ietf-idr-shutdown-01](https://tools.ietf.org/html/draft-ietf-idr-shutdown-01).

[bgpsec.pcap](files/pcap/bgpsec.pcap) (libpcap) Sample BGPsec OPEN and UPDATE messages. See [https://tools.ietf.org/html/rfc8205](https://tools.ietf.org/html/rfc8205) for the protocol specification and [https://tools.ietf.org/html/rfc8208#appendix-A](https://tools.ietf.org/html/rfc8208#appendix-A) for more packet examples.

[bmp.pcap](files/pcap/bmp.pcap) (libpcap) BGP Monitoring Protocol, including Init, Peer Up, Route Monitoring

[EIGRP_Neighbors.cap](files/cap/EIGRP_Neighbors.cap) Two Cisco EIGRP peers forming an adjacency.

[eigrp-for-ipv6-auth.pcap](files/pcap/eigrp-for-ipv6-auth.pcap) Cisco EIGRP packets, including Authentication TLVs

[eigrp-for-ipv6-stub.pcap](files/pcap/eigrp-for-ipv6-stub.pcap) Cisco EIGRP packets, including Stub routing TLVs

[eigrp-for-ipv6-updates.pcap](files/pcap/eigrp-for-ipv6-updates.pcap) Cisco EIGRP packets, including IPv6 internal and external route updates

[eigrp-ipx.pcap](files/pcap/eigrp-ipx.pcap) Cisco EIGRP packets, including IPX internal and external route updates

[ipv6-ripng.gz](files/gz/ipv6-ripng.gz) (libpcap) RIPng packets (IPv6)

[ospf.cap](files/cap/ospf.cap) (libpcap) Simple OSPF initialization.

[ospf-md5.cap](files/cap/ospf-md5.cap) (libpcap) Simple OSPF-MD5 Authentication.

[RIP_v1](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/RIP_v1) A basic route exchange between two RIP v1 routers.

### SNMP
[b6300a.cap](files/cap/b6300a.cap) A collection of SNMP GETs and RESPONSEs

[snmp_usm.pcap](files/pcap/snmp_usm.pcap) A series of authenticated and some encrypted SNMPv3 PDUS

+ the authPassword for all users is pippoxxx and the privPassword is PIPPOxxx.
+ pippo uses MD5 and DES
+ pippo2 uses SHA1 and DES
+ pippo3 uses SHA1 and AES
+ pippo4 uses MD5 and AES

### Network Time Protocol
[NTP_sync.pcap](files/pcap/NTP_sync.pcap) (4KB, showing the [NetworkTimeProtocol](https://wiki.wireshark.org/NetworkTimeProtocol))  
Contributor: Gerald Combs  
Description: After reading about the round robin [DNS](https://wiki.wireshark.org/DNS) records set up by the folks at [pool.ntp.org](http://www.pool.ntp.org/), I decided to use their service to sync my laptop's clock. The attached file contains the result of running

```plain
net time /setsntp:us.pool.ntp.org
net stop w32time
net start w32time
```

at the command prompt. Something to note is that each pool.ntp.org DNS record contains multiple addresses. The Windows time client appears to query all of them.

[MicrosoftNTP.cap](files/cap/MicrosoftNTP.cap) (Microsoft Network Monitor) 2 Packets containing a synchronisation to the Microsoft NTP server.

### SyncE Protocol
[SyncE_bidirectional.pcapng](files/pcapng/SyncE_bidirectional.pcapng) (1.5KB, showing the [syncE](https://wiki.wireshark.org/syncE) protocol)  
Contributor: [RadhaKrishna](https://wiki.wireshark.org/RadhaKrishna). courtesy:Karsten, RAD, Germany  
Description: SyncE is a synchronization mechanism for Ethernet networks. This mechanism uses SSM packets to qualify the synchronization signal quality.

### PostgreSQL v3 Frontend/Backend Protocol
[pgsql.cap.gz](files/cap.gz/pgsql.cap.gz) (2KB, showing a brief [PostgresProtocol](https://wiki.wireshark.org/PostgresProtocol) session)  
Contributor: Abhijit Menon-Sen

[pgsql-jdbc.pcap.gz](files/pcap.gz/pgsql-jdbc.pcap.gz) (584KB, showing a PostgreSQL JDBC test session)  
Contributors: Kris Jurka and Abhijit Menon-Sen\

### MySQL protocol
File: [mysql_complete.pcap](files/pcap/mysql_complete.pcap) (6 KB, from bug 2691)

For MySQL captures using SSL, see [#SSL_with_decryption_keys](https://wiki.wireshark.org/SampleCaptures#ssl-with-decryption-keys).

### MS SQL Server protocol - Tabular Data Stream (TDS)
[ms-sql-tds-rpc-requests.cap](files/cap/ms-sql-tds-rpc-requests.cap) (17 KB) RPC requests and a few SQL queries  
Contributor: Emil Wojak

### Netgear NSDP
[ndsp_v2.pcapng.gz](files/pcapng.gz/ndsp_v2.pcapng.gz) [https://en.wikipedia.org/wiki/Netgear_NSDP](https://en.wikipedia.org/wiki/Netgear_NSDP) upload a new Firmware via Netgear [SmartUtility](https://wiki.wireshark.org/SmartUtility). Switch Netgear GS748Tv3 is 192.168.0.239.

### VendorLanProtocolFamily
Extreme Networks

[edp.trace.gz](files/gz/edp.trace.gz) General EDP traffic

[edp1.trace.gz](files/gz/edp1.trace.gz)

[edp.esrp.gz](files/gz/edp.esrp.gz) EDP/ESRP traffic

[edp.eaps.mirror1.trace.gz](files/gz/edp.eaps.mirror1.trace.gz)

[edp.eaps.mirror2.trace.gz](files/gz/edp.eaps.mirror2.trace.gz)

### Cisco
[cdp.pcap](files/pcap/cdp.pcap) CDP v2 frame from a Cisco router.

[cdp_v2.pcap](files/pcap/cdp_v2.pcap) CDP v2 frame from a Cisco switch.

[DTP.pcapng](files/pcapng/DTP.pcapng) DTP frames from a Cisco switch.

[cdp-BCM1100.cap](files/cap/cdp-BCM1100.cap)

Mikrotiks [mndp.pcap](files/pcap/mndp.pcap)

### DECT
[dump_2009-02-02_23_17_18_RFPI_00_4e_b4_bd_50.pcap.gz](files/pcap.gz/dump_2009-02-02_23_17_18_RFPI_00_4e_b4_bd_50.pcap.gz) A trace of an unencrypted DECT phonecall with the original Ethernet pseudoheader (see README.DECT). Called number 0800-1507090 (DTMF only?)

### DECT-MITEL-RFP
[new_rfp.pcap](files/pcap/new_rfp.pcap) First boot up and configuration of a new RFP into the DECT system.

[new_rfp_on_wire.pcap](files/pcap/new_rfp_on_wire.pcap) Same as above but without external decryption.

### Sigtran Protocol Family
Captures of protocols belonging to the [SIGTRAN](https://wiki.wireshark.org/SIGTRAN) family.

[isup.cap](files/cap/isup.cap) A single call's signalling sequence using ISUP/MTP3/M3UA/SCTP/IP. NOTE: The M3UA version preference must be set to "Draft 6" to successfully view this file (Edit->Preferences->Protocols->M3UA->M3UA Version->Internet Draft version 6).

[isup_load_generator.pcap](files/pcap/isup_load_generator.pcap) ISUP/MTP3/MTP2 made by a call load generator and captured from an E1 line. The capture includes the frame check sequence at the end of each packet.

[bicc.pcap](files/pcap/bicc.pcap) Sample [BICC](https://wiki.wireshark.org/BICC) PDUs.

[camel.pcap](files/pcap/camel.pcap) A single call using CAMEL/TCAP/SCCP/MTP3/M2UA/SCTP/IP. This "capture" has been generated using [text2pcap](http://www.wireshark.org/docs/man-pages/text2pcap.1.html) tool, from MTP3 raw data trace. The capture contains the following Camel operations: InitialDP, RequestReportBCSMEvent, ApplyCharging, Continue, EventReportBCSM, ApplyChargingReport, ReleaseCall.

[camel2.pcap](files/pcap/camel2.pcap) Same as camel.pcap capture, except that the it is using another Camel phase. The other difference is that the call is rejected. The capture contains the following Camel operations: InitialDP, RequestReportBCSMEvent, Connect, [ReleaseCall](https://wiki.wireshark.org/ReleaseCall).

[gsm_map_with_ussd_string.pcap](files/pcap/gsm_map_with_ussd_string.pcap) This "capture" has been generated using [text2pcap](http://www.wireshark.org/docs/man-pages/text2pcap.1.html) tool, from MTP3 raw data trace. It contains a GSM MAP processUnstructuredSS-Request MAP operation with a USSD String (GSM 7 bit encoded).

[ansi_map_ota.pcap](files/pcap/ansi_map_ota.pcap) ANSI MAP OTA trace.

[ansi_map_win.pcap](files/pcap/ansi_map_win.pcap) ANSI MAP over ANSI MTP3 with WIN messages.

[packlog-example.cap](files/cap/packlog-example.cap) Example capture of Cisco ITP's Packet Logging Facility packets (SS7 MSU encapsulated in syslog messages). It contains a few random MSUs: MTP3MG, TCAP and GSM_MAP. There aren't any complete dialogs in the capture.

[japan_tcap_over_m2pa.pcap](files/pcap/japan_tcap_over_m2pa.pcap) Example of TCAP over Japan SCCP/MTP over M2PA (RFC version).

[ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap](files/pcap/ansi_tcap_over_itu_sccp_over_mtp3_over_mtp2.pcap) Example of ANSI TCAP carried over ITU SCCP/MTP3/MTP2. Really this should be in an "SS7" section of the SampleCaptures page.

### Stream Control Transmission Protocol (SCTP)
[sctp.cap](files/cap/sctp.cap) Sample [SCTP](https://wiki.wireshark.org/SCTP) PDUs, Megaco.

[sctp-test.cap](files/cap/sctp-test.cap) Sample [SCTP](https://wiki.wireshark.org/SCTP) handshaking and DATA/SACK chunks.

[sctp-addip.cap](files/cap/sctp-addip.cap) Sample [SCTP](https://wiki.wireshark.org/SCTP) ASCONF/ASCONF-ACK Chunks that perform Vertical Handover.

[sctp-www.cap](files/cap/sctp-www.cap) Sample [SCTP](https://wiki.wireshark.org/SCTP) DATA Chunks that carry HTTP messages between Apache2 HTTP Server and Mozilla.

[SCTP-INIT-Collision.cap](files/cap/SCTP-INIT-Collision.cap) Sample [SCTP](https://wiki.wireshark.org/SCTP) trace showing association setup collision (both peers trying to connect to each other).

### IPMI
[ipmi.SDR.FRU.SEL.pcap](files/pcap/ipmi.SDR.FRU.SEL.pcap) Opens and closes a session and retrieves the SDR, SEL and FRU. This "capture" has been generated using [text2pcap](http://www.wireshark.org/docs/man-pages/text2pcap.1.html) tool, from RMCP raw data trace.

[ipmi.sensor.event.RR.pcap](files/pcap/ipmi.sensor.event.RR.pcap) Opens and closes a session and does different Sensor/Event requests and responses. This "capture" has been generated using [text2pcap](http://www.wireshark.org/docs/man-pages/text2pcap.1.html) tool, from RMCP raw data trace.

### IPMB
[ipmb.multi.packets.pcap](files/pcap/ipmb.multi.packets.pcap) (libpcap). IPMB interface capture file, include multiple request and response packets.

### SIP and RTP
[aaa.pcap](files/pcap/aaa.pcap) Sample SIP and RTP traffic.

[SIP_CALL_RTP_G711](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/SIP_CALL_RTP_G711) Sample SIP call with RTP in G711.

[SIP_DTMF2.cap](files/cap/SIP_DTMF2.cap) Sample SIP call with RFC 2833 DTMF

[DTMFsipinfo.pcap](files/pcap/DTMFsipinfo.pcap) Sample SIP call with SIP INFO DTMF

[h223-over-rtp.pcap.gz](files/pcap.gz/h223-over-rtp.pcap.gz) (libpcap) A sample of H.223 running over RTP, following negotiation over SIP.

[h263-over-rtp.pcap](files/pcap/h263-over-rtp.pcap) (libpcap) A sample of RFC 2190 H.263 over RTP, following negotiation over SIP.

[metasploit-sip-invite-spoof.pcap](files/pcap/metasploit-sip-invite-spoof.pcap) Metasploit 3.0 SIP Invite spoof capture.

[FAX-Call-t38-CA-TDM-SIP-FB-1.pcap](files/pcap/FAX-Call-t38-CA-TDM-SIP-FB-1.pcap) Fax call from TDM to SIP over Mediagateway with declined T38 request, megaco H.248.

[Asterisk_ZFONE_XLITE.pcap](files/pcap/Asterisk_ZFONE_XLITE.pcap) Sample SIP call with ZRTP protected media.

[MagicJack+ Power On sequence](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/MagicJack-_pwr_up.pcap) SIP and RTP traffic generated by power on the MagicJack+ (Note: Original file returns 404)

[MagicJack+ short test call](files/pcap/MagicJack-_short_call.pcap) A complete telephone call example

[sip-rtp-opus-hybrid.pcap](files/pcap/sip-rtp-opus-hybrid.pcap) SIP and OPUS hybrid payloads, include OPUS-multiple frames packets.

[rtp-opus-only.pcap](files/pcap/rtp-opus-only.pcap) RTP Opus payloads only (without SIP/SDP).

SIP calls between SIPp ([scenario file](https://git.lekensteyn.nl/peter/wireshark-notes/tree/sipsim/uac_media.xml)) and FreeSWITCH 1.6.12, playing [ivr-on_hold_indefinitely.wav](https://freeswitch.org/stash/projects/FS/repos/freeswitch-sounds/commits/d55f6602be073fda2138febf286954ad125c6878#sounds/trunk/fr/ca/june/48000/ivr/ivr-on_hold_indefinitely.wav) in one direction using various codecs:

+ [sip-rtp-dvi4.pcap](files/pcap/sip-rtp-dvi4.pcap)
+ [sip-rtp-g711.pcap](files/pcap/sip-rtp-g711.pcap) - has both G.711A (PCMA) and G.711U (PCMU)
+ [sip-rtp-g722.pcap](files/pcap/sip-rtp-g722.pcap)
+ [sip-rtp-g726.pcap](files/pcap/sip-rtp-g726.pcap) - has eight variants: (AAL2-)G726-16/24/40/40
+ [sip-rtp-gsm.pcap](files/pcap/sip-rtp-gsm.pcap)
+ [sip-rtp-ilbc.pcap](files/pcap/sip-rtp-ilbc.pcap)
+ [sip-rtp-l16.pcap](files/pcap/sip-rtp-l16.pcap) - four variants: 8000/2, 16000/2, 11025, 48000
+ [sip-rtp-lpc.pcap](files/pcap/sip-rtp-lpc.pcap)
+ [sip-rtp-opus.pcap](files/pcap/sip-rtp-opus.pcap) - Opus mono session with 48kHz clock rate
+ [sip-rtp-speex.pcap](files/pcap/sip-rtp-speex.pcap) - three sample rates: 8/16/32kHz
+ [sip-rtp-g729a.pcap](files/pcap/sip-rtp-g729a.pcap)

[sip-tls-1.3-and-rtcp.zip](files/zip/sip-tls-1.3-and-rtcp.zip) SIP call over TLS 1.3 transport with enabled RTCP. Used [openssl 1.1.1 prerelease version](https://github.com/openssl/openssl/commit/bdcacd93b14ed7381a922b41d74c481224ef9fa1)

### RTSP Protocol
Here's a few RTSP packets in Microsoft Network Monitor format: [RTSPPACKETS1.cap](files/cap/RTSPPACKETS1.cap)

[rtsp_with_data_over_tcp.cap](files/cap/rtsp_with_data_over_tcp.cap) (libpcap) An RTSP reply packet.

### H.223
[h223-over-iax.pcap.gz](files/pcap.gz/h223-over-iax.pcap.gz) (libpcap) A sample of H.223 running over IAX, including H.263 and AMR payloads.

[h223-over-tcp.pcap.gz](files/pcap.gz/h223-over-tcp.pcap.gz) (libpcap) A sample of H.223 running over TCP. You'll need to select 'Decode as... H.223'.

[h223-over-rtp.pcap.gz](files/pcap.gz/h223-over-rtp.pcap.gz) (libpcap) A sample of H.223 running over RTP, following negotiation over SIP.

### H.265/HEVC
[1920x1080_H.265.pcapng](files/pcapng/1920x1080_H.265.pcapng) (libpcap) A sample of H.265 running over RTP, following negotiation over RTSP.

### MGCP
[MGCP.pcap](files/pcap/MGCP.pcap) (libpcap) A sample of the Media Gateway Control Protocol (MGCP).

### USB Raw (dlt 186)
[VariousUSBDevices.pcap](files/pcap/VariousUSBDevices.pcap) (libpcap) Various USB devices on a number of busses

Usb packets exchanged while unpluggin and replugging a mouse: [mouse_replug2.pcap](files/pcap/mouse_replug2.pcap)

[usbstick3.pcap.gz](files/pcap.gz/usbstick3.pcap.gz) (libpcap) Plug in a USB2.0 stick, mount it, list the contents.

[usbhub.pcap.gz](files/pcap.gz/usbhub.pcap.gz) (libpcap) Plug in a usb2.0 4-port hub without external powersupply, plugin a logitech presenter into one of the ports, press a button, unplug presenter, unplug hub. Repeat with externally powered hub.

### USB with Linux encapsulation (dlt 189)
[usb_memory_stick.pcap](files/pcap/usb_memory_stick.pcap) Plug in an usb stick and mount it

[usb_memory_stick_create_file.pcap](files/pcap/usb_memory_stick_create_file.pcap) Create a new file in a previusly mounted memory stick and write some text into it

[usb_memory_stick_delete_file.pcap](files/pcap/usb_memory_stick_delete_file.pcap) Delete the file previusly created from the memory stick.

[Bluetooth_HCI_and_OBEX_Transaction_over_USB.ntar.gz](files/gz/Bluetooth_HCI_and_OBEX_Transaction_over_USB.ntar.gz) contains a Bluetooth session (including connecting the USB adaptor used, pairing with a mobile phone, receiving a file over RFCOMM/L2CAP/OBEX, and finally removing the USB Bluetooth adaptor) over USB

[xrite-i1displaypro-argyllcms-1.9.2-spotread.pcapng](files/pcapng/xrite-i1displaypro-argyllcms-1.9.2-spotread.pcapng) ArgyllCMS 1.9.2 making a single measurement (spotread) using an X-Rite i1 Display Pro color sensor. Some other sensors, such as the near-identical ColorMunki Display, use the same protocol.

### USB with USBPcap encapsulation
[usb_u3v_sample.pcapng](files/pcapng/usb_u3v_sample.pcapng) Sample control and video traffic with a USB3Vision camera

[xrite-i1displaypro-i1profiler.pcap.gz](files/pcap.gz/xrite-i1displaypro-i1profiler.pcap.gz) X-Rite i1Profiler v1.6.6.19864 measuring a display profile using an X-Rite i1 Display Pro color sensor, captured using USBPcap 1.0.0.7. Some other sensors, such as the near-identical ColorMunki Display, use the same protocol.

### USB Link Layer
[SB1240-via-hub_usbll.7z](files/7z/SB1240-via-hub_usbll.7z) USB Audio class device SB1240 (Full-Speed) connected via High-Speed USB Hub to host. Contains simultaneous captures on the HS link between Hub and Host, FS link between SB1240 and Hub and usbmon capture on the USB Host.

[STM32L053-Nucleo-via-hub.7z](files/7z/STM32L053-Nucleo-via-hub.7z) Composite device (ST-LINK Vendor specific protocol, Mass Storage class, CDC Class) STM32L053 Nucleo (Full-Speed) connected via High-Speed USB Hub to host. Contains simultaneous captures on the HS link between Hub and Host, FS link between SB1240 and Hub and usbmon capture on the USB Host. Only the Mass Storage class interface was actively used.

[USBMSC-USBLL.7z](files/7z/USBMSC-USBLL.7z) USB memory stick connected and mounted on Windows. Includes both link layer capture and matching USBPcap capture.

### USB packets with Darwin (macOS, etc.) headers
[XHC1-SanDiskExtremePortableSSD.pcapng](files/pcapng/XHC1-SanDiskExtremePortableSSD.pcapng)

[XHC20-LogitechUnifying.pcapng.gz](files/pcapng.gz/XHC20-LogitechUnifying.pcapng.gz)

[XHC20-MicrosoftKeyboard.pcapng.gz](files/pcapng.gz/XHC20-MicrosoftKeyboard.pcapng.gz)

[XHC20-OpenVizsla.pcapng.gz](files/pcapng.gz/XHC20-OpenVizsla.pcapng.gz)

### FreeBSD usbdump format file
[test.usbdump](files/usbdump/test.usbdump) Sample FreeBSD usbdump capture file.

### WAP Protocol Family
[WAP_WBXML_Provisioning_Push.pcap](files/pcap/WAP_WBXML_Provisioning_Push.pcap) contains a [WSP](https://wiki.wireshark.org/WSP) Push PDU with a Client Provisioning document encoded in [WBXML](https://wiki.wireshark.org/WBXML). This example comes from the WAP Provisioning specifications.

[wap_google.pcap](files/pcap/wap_google.pcap) contains two [WSP](https://wiki.wireshark.org/WSP) request-response dialogs.

### X.509 Digital Certificates
[x509-with-logo.cap](files/cap/x509-with-logo.cap) contains (packet 18) an X.509 digital certificate containing RFC3709 [LogotypeCertificateExtensions](https://wiki.wireshark.org/LogotypeCertificateExtensions).

### Lightweight Directory Access Protocol (LDAP)
[ldap-controls-dirsync-01.cap](files/cap/ldap-controls-dirsync-01.cap) Sample [LDAP](https://wiki.wireshark.org/LDAP) PDU with DIRSYNC CONTROLS

[ldap-krb5-sign-seal-01.cap](files/cap/ldap-krb5-sign-seal-01.cap) Sample [GSSAPI](https://wiki.wireshark.org/GSSAPI)-[KRB5](https://wiki.wireshark.org/KRB5) signed and sealed [LDAP](https://wiki.wireshark.org/LDAP) PDU

[ldap-and-search.pcap](files/pcap/ldap-and-search.pcap) Sample search filter with AND filter, filter

[ldap-attribute-value-list.pcap](files/pcap/ldap-attribute-value-list.pcap) Sample search filter with an attribute value list

[ldap-extensible-match-with-dn.pcap](files/pcap/ldap-extensible-match-with-dn.pcap) Sample search filter with an extensible match with dnAttributes

[ldap-extensible-match.pcap](files/pcap/ldap-extensible-match.pcap) Sample search filter with a simple extensible match

[ldap-substring.pcap](files/pcap/ldap-substring.pcap) Sample search filter with substring matches

[ldap-ssl.pcapng](files/pcapng/ldap-ssl.pcapng) Encrypted LDAP traffic, see [#SSL_with_decryption_keys](https://wiki.wireshark.org/SampleCaptures#ssl-with-decryption-keys) for more details.

### Link Layer Discovery Protocol (LLDP)
[lldp.minimal.pcap](files/pcap/lldp.minimal.pcap) (libpcap) Simple LLDP packets.

[lldp.detailed.pcap](files/pcap/lldp.detailed.pcap) (libpcap) LLDP packets with more details.

[lldpmed_civicloc.pcap](files/pcap/lldpmed_civicloc.pcap) (libpcap) LLDP-MED packet with TLV entries, including civic address location ID, network policy and extended power-via-MDI.

[D-Link Ethernet Switch Smart Console Utility LLDP](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/D-Link-Ethernet-Switch-Smart-Console-Utility-LLDP) (libpcap) D-Link LLDP [SmartConsole](https://wiki.wireshark.org/SmartConsole) Utility.

[lldp-shutdown-pdu.pcapng.gz](files/pcapng.gz/lldp-shutdown-pdu.pcapng.gz) (libpcap) LLDP capture in GNS3 between two SONiC devices while configuring `no lldp enable` on an interface.

### SAN Protocol Captures (iSCSI, ATAoverEthernet, FibreChannel, SCSI-OSD and other SAN related protocols)
[iscsi-scsi-data-cdrom.zip](files/zip/iscsi-scsi-data-cdrom.zip) contains a complete log of iSCSI traffic between MS iSCSI Initiator and Linux iSCSI Enterprise Target with a real SCSI CD-ROM exported. The CD-ROM has a Fedora Core 3 installation CD in it.

[iscsi-scsi-10TB-data-device.zip](files/zip/iscsi-scsi-10TB-data-device.zip) contains a complete log of iSCSI traffic between MS iSCSI Initiator and Linux iSCSI Enterprise Target with a 10TB block device exported. See the use of READ_CAPACITY_16, READ_16, and WRITE_16.

[iscsi-tapel.gz](files/gz/iscsi-tapel.gz) contains some operation log of iSCSI traffic between Linux open-iscsi initiator and Linux iSCSI Enterprise Target. The target is a EXABYTE EXB480 Tape library. Various mtx operations are executed.

[fcip_trace.cap](files/cap/fcip_trace.cap) from [http://www.wireshark.org/lists/ethereal-dev/200212/msg00080.html](http://www.wireshark.org/lists/ethereal-dev/200212/msg00080.html) containing fcip traffic but unfortunately no SCSI over FCP over FCIP

[fcoe-t11.cap.gz](files/cap.gz/fcoe-t11.cap.gz) has the FCoE encapsulation, showing a host adapter doing fabric and port logins, discovery and SCSI Inquiries, etc. This uses the August 2007 T11 converged frame format.

[fcoe1.cap](files/cap/fcoe1.cap) has a similar set of frames using an older FCoE frame format proposed prior to the August 2007 version.

[fcoe-t11-short.cap](files/cap/fcoe-t11-short.cap) is a trace of part of a SCSI write with only the first 64 bytes of each frame captured.

[fcoe-drop-rddata.cap](files/cap/fcoe-drop-rddata.cap) is a trace of a SCSI read with REC and SRR recovery performed.

FIP is the FCoE Initialization Protocol. [fip-adv.cap.gz](files/cap.gz/fip-adv.cap.gz) shows advertisement, discovery and FLOGI. [fip-ka.cap.gz](files/cap.gz/fip-ka.cap.gz) shows keep-alives and a clear-virtual-link. Note that the host and gateway are not necessarily using FIP correctly.

[scsi-osd-example-001.pcap](files/pcap/scsi-osd-example-001.pcap) is a trace of the IBM osd_initiator_3_1_1 (an OSD tester application) exercising IBM's ibm-osd-sim (an emulation of an OSD target device). The transport involved is iSCSI, and makes use of the relatively unusual new SCSI feature of bidirectional data transfer. The trace captures the initial iSCSI Logins, through INQUIRY and REPORT LUNS, followed by a number of commands from the SCSI-OSD command set such as FORMAT OSD, LIST, CREATE PARTITION, CREATE, WRITE, READ, REMOVE, REMOVE PARTITION, and SET ROOT KEY.

### Peer-to-peer protocols
#### MANOLITO Protocol
[PioletSearch.Manolito.cap](files/cap/PioletSearch.Manolito.cap) (Microsoft Network Monitor) Here's a Piolet/Blubster (MANOLITO) capture for your enjoyment: It is a few packets I captured whilst looking for some Dr. Alban songs using Piolet.

[Manolito2.cap](files/cap/Manolito2.cap) (Microsoft Network Monitor) Here's some more Manolito packets (this time, it's just general sign-in).

#### BitTorrent Protocol
[BitTorrent.Transfer1.cap](files/cap/BitTorrent.Transfer1.cap) (Microsoft Network Monitor) Here's a capture with a few [BitTorrent](https://wiki.wireshark.org/BitTorrent) packets; it contains some small packets I got whilst downloading something on [BitTorrent](https://wiki.wireshark.org/BitTorrent).

[BITTORRENT.pcap](files/pcap/BITTORRENT.pcap) (libpcap) Capture file of two torrent clients communicationg without DHT or peer exch.

#### SoulSeek Protocol
[SoulSeekRoom.cap](files/cap/SoulSeekRoom.cap) (Microsoft Network Monitor) Here's a capture with a few [SoulSeek](https://wiki.wireshark.org/SoulSeek) packets; it contains some small packets I got whilst browsing through some [SoulSeek](https://wiki.wireshark.org/SoulSeek) rooms.

#### JXTA Protocol
[jxta-sample.pcap](files/pcap/jxta-sample.pcap) (libpcap) A trace of a JXTA client and rendezvous doing some chatting using several JXTA pipes.

[jxta-mcast-sample.pcap](files/pcap/jxta-mcast-sample.pcap) (libpcap) A trace of a JXTA client and rendezvous doing some chatting using several JXTA pipes with UDP multicast enabled.

#### SMPP (Short Message Peer-to-Peer) Protocol
[smpp.cap](files/cap/smpp.cap) (libpcap) An SMPP capture showing a Bind_transmitter, Submit_sm and Unbind request flow.

### Kaspersky Update Protocol
Some examples of packets used by the Kaspersky AntiVirus Updater: [KasperskyPackets.CAP](files/CAP/KasperskyPackets.CAP)

### Kerberos and keytab file for decryption
[krb-816.zip](files/zip/krb-816.zip) An example of Kerberos traffic when 2 users logon domain from a Windows XP. keytab file is included. With Kerberos decryption function in wireshark 0.10.12, some encrypted data can be decrypted.

[kpasswd_tcp.cap](files/cap/kpasswd_tcp.cap) An example of a Kerberos password change, sent over TCP.

[kerberos-Delegation.zip](files/zip/kerberos-Delegation.zip) An example of Kerberos Delegation in Windows Active Diretory.Keytaf file is also included.Please use Wireshark 0.10.14 SVN 17272 or above to open the trace.

[constained-delegation.zip](files/zip/constained-delegation.zip) An example of Kerberos constrained delegation (s4U2Proxy) in Windows 2003 domain.

[win_s4u2self.pcap](files/pcap/win_s4u2self.pcap) An example of Kerberos protocol transition (s4U2Self) with W2k8 server and Win7 client (no keys).

[s4u2self_with_keys.tgz](files/tgz/s4u2self_with_keys.tgz) Another example of Kerberos protocol transition (s4U2Self) with W2k16 server and MIT client (with keys).

[S4U2Self_with_certificate.tgz](files/tgz/S4U2Self_with_certificate.tgz) Kerberos protocol transition (s4U2Self) using X509 certificate (with keys).

[rbcd_win_with_keys.tgz](files/tgz/rbcd_win_with_keys.tgz) Kerberos s4U2Proxy resource-based-constrained-delegation (with keys).

[rbcd_win_two_transits_with_keys.tgz](files/tgz/rbcd_win_two_transits_with_keys.tgz) Kerberos s4U2Proxy resource-based-constrained-delegation two transit (with keys).

[krb5_tgs_fast.tgz](files/tgz/krb5_tgs_fast.tgz) Kerberos TGS with FAST padata.

### mDNS & Apple Rendezvous
ZIP Compressed mDNS (Apple Rendezvous) Dumps - MS [NetMon](https://wiki.wireshark.org/NetMon) Format: [mDNS1.zip](files/zip/mDNS1.zip)

### Point-To-Point (PPP)
[PPPHandshake.cap](files/cap/PPPHandshake.cap) PPP Handshake using Microsoft Windows VPN - MS [NetMon](https://wiki.wireshark.org/NetMon) Format

[PPP-config.cap](files/cap/PPP-config.cap) LCP and IPCP configuration of a Direct Cable Connection (WinXP)

[ppp-dialup-munged.pppd](files/pppd/ppp-dialup-munged.pppd) Linux pppd async dialup connect/disconnect; (The capture file generated by pppd has been munged slightly to hide login info, thus certain HDLC checksums are incorrect)

[ppp_lcp_ipcp.pcap](files/pcap/ppp_lcp_ipcp.pcap) PPP LCP and IPCP traffic w/a protocol reject for CCP.

### Point-To-Point over Ethernet
File: [telecomitalia-pppoe.pcap](files/pcap/telecomitalia-pppoe.pcap)

PPPoE exchange between a Telecom Italia ADSL CPE and one of their Juniper (ex-Unisphere) BNASes.

1. CPE sends a discovery initiation frame (PADI) and receives an offer (PADO).
2. CPE sends an authentication request with dummy credentials "aliceadsl" both for username and password. These are useless, since the actual authentication is performed thanks to the DSLAM intercepting the PPPoE discovery frames and adding in a Circuit-ID/NAS-Port-ID tag, which is unique for the customer DSLAM port. This tag is then verified against a RADIUS server on Telecom Italia's premises. This process is hidden and transparent to the user and cannot be shown here.
3. Post-authentication, our CPE receives back IPCP messages containing configuration information, such as public IP, default gateway and DNS configuration.
4. We're now on the Internet. PPP LCP Echo requests and Echo replies are sent as session keep-alive check.

Contributed by [Lorenzo Cafaro](https://github.com/lcafaro).

### X.400
These captures exercise the Session (SES), Presentation(PRES), Assocation Control (ACSE), Reliable Transfer (RTSE), Remote Operations (ROSE), X.400 P1 Transfer (X411), X.400 Information Object [X420](https://wiki.wireshark.org/X420) and STANAG 4406 [S4406](https://wiki.wireshark.org/S4406) dissectors.

Contributor: Graeme Lunt

File: [x400-ping-refuse.pcap](files/pcap/x400-ping-refuse.pcap) (2KB)  
Description: An X.400 bind attempt using RTS in normal mode generating an authentication error from the responder.

File: [x400-ping-success.pcap](files/pcap/x400-ping-success.pcap) (2KB)  
Description: An X.400 bind attempt using RTS in normal mode with a bind result from the responder.

File: [p772-transfer-success.pcap](files/pcap/p772-transfer-success.pcap) (4KB)  
Description: An X.400 bind attempt using RTS in normal mode with a bind result from the responder, and then the successful transfer of a P772 message.

### Direct Message Protocol
Contributor: Stig Bjorlykke

File: [dmp-examples.pcap.gz](files/pcap.gz/dmp-examples.pcap.gz) (667B)  
Description: Some example [DMP](https://wiki.wireshark.org/DMP) messages. Note that the examples uses port number 24209, which must be configured in the protocol page.

### STANAG 5066 SIS
These captures show a succeful and unsuccesful transfer of a simple line of text with STANAG 5066 Subnetwork Interface Sublayer (S5066_SIS).

Contributor: Menno Andriesse

File: [S5066-HFChat-1.pcap](files/pcap/S5066-HFChat-1.pcap) (4KB)  
Description: A line of text is send and acknowledged

File: [S5066-HFChat-Rejected.pcap](files/pcap/S5066-HFChat-Rejected.pcap) (2KB)  
Description: A line of text is send and rejected because the other node does not respond.

Contributor: Taner Kurtulus

File: [S5066-Expedited.pcap](files/pcap/S5066-Expedited.pcap) (2KB)  
Description: A line of text is sent/received with Expedited S_Prims and confirmed

### STANAG 5066 DTS
These captures show a successful BFTP transfer over a hardlink between two peers.

Contributor: İbrahim Can Yüce

File: [Stanag5066-TCP-ENCAP-Bftp-Exchange-tx-rx.pcapng](files/pcapng/Stanag5066-TCP-ENCAP-Bftp-Exchange-tx-rx.pcapng)  
Description: BFTP file transfer exchange D_PDUs captured directly from the line.

File: [Stanag5066-RAW-ENCAP-Bftp-Exchange-tx.pcap](files/pcap/Stanag5066-RAW-ENCAP-Bftp-Exchange-tx.pcap)  
Description: BFTP file transfer exchange D_PDUs encapsulated in TCP, then handed off to S5066 dissector.

### RTP Norm
These captures show samples of RTP NORM transfers.

Contributor: Julian Onions

File: [rtp-norm-transfer.pcap](files/pcap/rtp-norm-transfer.pcap) (291.2 KB)  
Description: A norm file transfer over multicast (to one acking host).

File: [rtp-norm-stream.zip](files/zip/rtp-norm-stream.zip) (673.4 KB)  
Description: A portion of a NORM stream transfer.

### DCE/RPC and MSRPC-based protocols
Captures in this section show traffic related to various DCE/RPC-based and MSRPC-based interfaces.

File: [dcerpc-fault-stub-data-02.pcap.gz](files/pcap.gz/dcerpc-fault-stub-data-02.pcap.gz)  
Description: A DCERPC Fault pdu with extended error information (MS-EERR).

#### DSSETUP MSRPC interface
File: [dssetup_DsRoleGetPrimaryDomainInformation_standalone_workstation.cap](files/cap/dssetup_DsRoleGetPrimaryDomainInformation_standalone_workstation.cap) (1.0 KB)  
Description: [DsRoleGetPrimaryDomainInformation](https://wiki.wireshark.org/DsRoleGetPrimaryDomainInformation) operation (DSSETUP) against a standalone workstation.

File: [dssetup_DsRoleGetPrimaryDomainInformation_ad_member.cap](files/cap/dssetup_DsRoleGetPrimaryDomainInformation_ad_member.cap) (1.5 KB)  
Description: [DsRoleGetPrimaryDomainInformation](https://wiki.wireshark.org/DsRoleGetPrimaryDomainInformation) operation (DSSETUP) against an Active Directory domain member workstation.

File: [dssetup_DsRoleGetPrimaryDomainInformation_ad_dc.cap](files/cap/dssetup_DsRoleGetPrimaryDomainInformation_ad_dc.cap) (1.0 KB)  
Description: [DsRoleGetPrimaryDomainInformation](https://wiki.wireshark.org/DsRoleGetPrimaryDomainInformation) operation (DSSETUP) against an Active Directory DC.

File: [dssetup_DsRoleDnsNameToFlatName_w2k3_op_rng_error.cap](files/cap/dssetup_DsRoleDnsNameToFlatName_w2k3_op_rng_error.cap) (1.0 KB)  
Description: In Windows Server 2003, there is only one operation ([DsRoleGetPrimaryDomainInformation](https://wiki.wireshark.org/DsRoleGetPrimaryDomainInformation)) in the DSSETUP interface. This capture shows that the [DsRoleDnsNameToFlatName](https://wiki.wireshark.org/DsRoleDnsNameToFlatName) is not supported in Windows Server 2003.

File: [dssetup_DsRoleDnsNameToFlatName_w2k.cap](files/cap/dssetup_DsRoleDnsNameToFlatName_w2k.cap) (1.0 KB)  
Description: [DsRoleDnsNameToFlatName](https://wiki.wireshark.org/DsRoleDnsNameToFlatName) operation against a Windows 2000 system without MS04-011 applied

File: [dssetup_DsRoleUpgradeDownlevelServer_MS04-011_exploit.cap](files/cap/dssetup_DsRoleUpgradeDownlevelServer_MS04-011_exploit.cap) (5.0 KB)  
Description: traffic of an exploit for the security vulnerabillity exploitable using the [DsRoleUpgradeDownlevelServer](https://wiki.wireshark.org/DsRoleUpgradeDownlevelServer) operation (Windows 2000 and Windows XP systems without MS04-011 applied)

#### NSPI MSRPC Interface
File [nspi.pcap](files/pcap/nspi.pcap) (7.2 KB)  
Description: MAPI Profile creation between Microsoft Exchange 2003 and the mail applet in the configuration panel (Windows 2003 Server and Windows XP Professional) Name Service Provider Interface is a MAPI:ROP MSRPC protocol.

#### ROP MSRPC Interface
File [ShortMAPI.pcapng](files/pcapng/ShortMAPI.pcapng) Description: This is a short (failed) MAPI conversation, showing connect, ROP, and disconnect. The conversation fails because of an authentication/encryption mismatch. (Windows 2003 SBS Server and Outlook 2003 on Win10)

File [mapi.cap.gz](files/cap.gz/mapi.cap.gz) (libpcap) MAPI session w/ Outlook and MSX server, not currently decoded by Wireshark.

#### WINREG Interface
File [dcerpc-winreg-with-rpc-sec-verification-trailer.pcap](files/pcap/dcerpc-winreg-with-rpc-sec-verification-trailer.pcap)  
Description: smbtorture in Samba's make test. Frame 34 contains a rpc_sec_verification_trailer.

#### WITNESS Interface
File [dcerpc_witness.pcapng](files/pcapng/dcerpc_witness.pcapng)  
Description: Sample Witness traffic

#### MS-TSCH Interface
Create two scheduled tasks with the `SchRpcRegisterTask` method, then listing all the tasks using the `SchRpcEnumTasks` methods. Trafic is in cleartext. See equivalent files with encrypted trafic [#ntlmssp](https://wiki.wireshark.org/below)

[create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_CONNECT_NTLMv2.pcapng](files/pcapng/create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_CONNECT_NTLMv2.pcapng)

### IPsec
#### Example 1: [ESP](https://wiki.wireshark.org/ESP) Payload Decryption and Authentication Checking Examples
Archive: [ipsec_esp.tgz](files/tgz/ipsec_esp.tgz)

Some examples for ESP payload decryption and authentication checking from 2006. The four archives have been joined and the SAs have been converted from the Ethereal preferences format into an `esp_sa` uat file. Other from that, the examples are unchanged.

Contents:

+ ipsec_esp_capture_1: ESP payload decryption and authentication checking for simple transport mode in v4/v6.
+ ipsec_esp_capture_2: ESP payload decryption and authentication checking for tunnel mode in v4.
+ ipsec_esp_capture_3: ESP payload decryption with authentication checking for some more encryption algorithms not defined in RFC4305.
+ ipsec_esp_capture_5: Authentication checking and decryption using binary keys specified as hexadecimal values

Contributors: Frederic Roudaut (2006), Matthias St. Pierre (2021)

#### Example 2: Dissection of encrypted (and UDP-encapsulated) [IKEv2](https://wiki.wireshark.org/IKEv2) and [ESP](https://wiki.wireshark.org/ESP) messages
Archive: [ipsec_ikev2+esp_aes-gcm_aes-ctr_aes-cbc.tgz](files/tgz/ipsec_ikev2+esp_aes-gcm_aes-ctr_aes-cbc.tgz)

A VPN client (192.168.245.131) behind a NAT device connects three times to a VPN gateway (172.16.15.92) using IKEv2, the user sends some pings through the VPN tunnel (192.168.225.0/24) to the gateway (192.168.225.1), which are returned successfully, and disconnects. The three connections differ by the AES operation modes (AES-GCM, AES-CTR, and AES-CBC, in that order) used for encrypting the IKE_AUTH and ESP messages:

| Nr | Encryption | Authentication |
| --- | --- | --- |
| 1 | AES-GCM with 16 octet ICV [RFC4106] | NULL |
| 2 | AES-CTR [RFC3686] | HMAC-SHA-256-128 [RFC4868] |
| 3 | AES-CBC [RFC3602] | HMAC-SHA-256-128 [RFC4868] |


The entire conversation (IKE+ESP) is sent UDP-encapsulated on port 4500.

Contents:

+ capture.pcap: packet capture file
+ esp_sa: decryption table for the ESP SAs (requires [Merge Request !3444](https://gitlab.com/wireshark/wireshark/-/merge_requests/3444))
+ esp_sa.no_icv decryption table for the ESP SAs (without AES-GCM ICV length; for current releases of Wireshark)
+ ikev2_decryption_table: decryption table for the IKEv2 SAs

Contributor: Matthias St. Pierre

### Pro-MPEG FEC - Professional video FEC data over RTP
See protocol description, [2dParityFEC](https://wiki.wireshark.org/2dParityFEC) for details.  
File: [2dParityFEC-Example.cap.gz](files/cap.gz/2dParityFEC-Example.cap.gz)  
Description: Example of row and column FEC data mixed with MPEG2 transport stream data in standard [RTP](https://wiki.wireshark.org/RTP) packets.

### SSL with decryption keys
File: [snakeoil2_070531.tgz](files/tgz/snakeoil2_070531.tgz)  
Description: Example of [SSL](https://wiki.wireshark.org/SSL) encrypted HTTPS traffic and the key to decrypt it. (example taken from the dev mailinglist)

Files: [dump.pcapng](https://bugs.wireshark.org/bugzilla/attachment.cgi?id=11612), [premaster.txt](https://bugs.wireshark.org/bugzilla/attachment.cgi?id=11616)  
Description: Capture and related keylog file of a openssl's s_client/s_server HTTP GET request over TLSv1.2 with 73 different cipher suites (generated using [openssl-connect](https://git.lekensteyn.nl/peter/wireshark-notes/tree/openssl-connect) for [Bug 9144 - Update TLS ciphers](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9144))

File: [mysql-ssl.pcapng](files/pcapng/mysql-ssl.pcapng) (11 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/mysql-ssl.pcapng?id=8cfd2f667e796e4c0e3bdbe117e515206346f74a](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/mysql-ssl.pcapng?id=8cfd2f667e796e4c0e3bdbe117e515206346f74a), SSL keys in capture file comments)

File: [mysql-ssl-larger.pcapng](files/pcapng/mysql-ssl-larger.pcapng) (`show variables` response in two TLS records and multiple TCP segments) (22 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/mysql-ssl-larger.pcapng?id=818f97811ee7d9b4c5b2d0d14f8044e88787bc01](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/mysql-ssl-larger.pcapng?id=818f97811ee7d9b4c5b2d0d14f8044e88787bc01), SSL keys in capture file comments)

File: [smtp-ssl.pcapng](files/pcapng/smtp-ssl.pcapng) (8.8 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/smtp-ssl.pcapng?id=9615a132638741baa2cf839277128a32e4fc34f2](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/smtp-ssl.pcapng?id=9615a132638741baa2cf839277128a32e4fc34f2), SSL keys in capture file comments)

File: [smtp2525-ssl.pcapng](files/pcapng/smtp2525-ssl.pcapng) (SMTP over non-standard port 2525) (8.8 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/smtp2525-ssl.pcapng?id=d448482c095363191ff5b5b312fa8f653e482425](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/smtp2525-ssl.pcapng?id=d448482c095363191ff5b5b312fa8f653e482425), SSL keys in capture file comments)

File: [xmpp-ssl.pcapng](files/pcapng/xmpp-ssl.pcapng) (15 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/xmpp-ssl.pcapng?id=fa979120b060be708e3e752e559e5878524be133](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/xmpp-ssl.pcapng?id=fa979120b060be708e3e752e559e5878524be133), SSL keys in capture file comments)

File: [pop-ssl.pcapng](files/pcapng/pop-ssl.pcapng) (POP3) (9.2 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/pop-ssl.pcapng?id=860c55ba8449a877e21480017e16cfae902b69fb](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/pop-ssl.pcapng?id=860c55ba8449a877e21480017e16cfae902b69fb), SSL keys in capture file comments)

File: [imap-ssl.pcapng](files/pcapng/imap-ssl.pcapng) (10 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/imap-ssl.pcapng?id=1123e936365c89d43e9f210872778d81223af36d](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/imap-ssl.pcapng?id=1123e936365c89d43e9f210872778d81223af36d), SSL keys in capture file comments)

File: [pgsql-ssl.pcapng](files/pcapng/pgsql-ssl.pcapng) (7.7 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/pgsql-ssl.pcapng?id=836b6f746df24aa04fa29b71806d8d0e496c2a68](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/pgsql-ssl.pcapng?id=836b6f746df24aa04fa29b71806d8d0e496c2a68), SSL keys in capture file comments)

File: [ldap-ssl.pcapng](files/pcapng/ldap-ssl.pcapng) (8.3 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/ldap-ssl.pcapng?id=d931120107e7429a689a8350d5e49c1f1147316f](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/ldap-ssl.pcapng?id=d931120107e7429a689a8350d5e49c1f1147316f), SSL keys in capture file comments)

File: [http2-16-ssl.pcapng](files/pcapng/http2-16-ssl.pcapng) (HTTP2 with ALPN h2-16 extension) (5.1 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/http2-16-ssl.pcapng?id=a24c03ce96e383faf2a624bfabd5cc843e78ab2a](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/http2-16-ssl.pcapng?id=a24c03ce96e383faf2a624bfabd5cc843e78ab2a), SSL keys in capture file comments)

File: [amqps.pcapng](files/pcapng/amqps.pcapng) (AMQP using RabbitMQ server and Celery client) (5.1 KB, from [https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/amqps.pcapng?id=3c00336b07f1fec0fb13af3c7d502d51fab732b7](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/amqps.pcapng?id=3c00336b07f1fec0fb13af3c7d502d51fab732b7), SSL keys in capture file comments)

The `*-ssl.pcapng` capture files above can be found at [https://git.lekensteyn.nl/peter/wireshark-notes/tree/tls/](https://git.lekensteyn.nl/peter/wireshark-notes/tree/tls/) with the pre-master key secrets being available in the capture file comments. See the commit log for further details. The keys have been extracted from the OpenSSL library using a LD_PRELOAD interposing library, libsslkeylog.so ([sslkeylog.c](https://git.lekensteyn.nl/peter/wireshark-notes/tree/src/sslkeylog.c)).

For TLS 1.3 captures and keys, see [Bug 12779](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12779). For example, Chromium 61 (TLS 1.3 draft -18) connecting to enabled.tls13.com using HTTP/2 can be found in [this comment](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12779#attach_15867).

### SSH with decryption keys
File: [ssh_curve25519-aes128-gcm_opensshS.pcapng](files/pcapng/ssh_curve25519-aes128-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes128-cbc_opensshS.pcapng](files/pcapng/ssh_curve25519-aes128-cbc_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes128-ctr_opensshS.pcapng](files/pcapng/ssh_curve25519-aes128-ctr_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes192-cbc_opensshS.pcapng](files/pcapng/ssh_curve25519-aes192-cbc_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes192-ctr_opensshS.pcapng](files/pcapng/ssh_curve25519-aes192-ctr_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes256-gcm_opensshS.pcapng](files/pcapng/ssh_curve25519-aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes256-cbc_opensshS.pcapng](files/pcapng/ssh_curve25519-aes256-cbc_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_curve25519-aes256-ctr_opensshS.pcapng](files/pcapng/ssh_curve25519-aes256-ctr_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhgex-sha256_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhgex-sha256_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhg14-sha256_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhg14-sha256_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhg14-sha256_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhg14-sha256_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhg16-sha512_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhg16-sha512_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhg18-sha512_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhg18-sha512_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhg1-sha1_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhg1-sha1_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [ssh_dhgex-sha1_aes256-gcm_opensshS.pcapng](files/pcapng/ssh_dhgex-sha1_aes256-gcm_opensshS.pcapng)  
Description: Example of a simple SSH session.

File: [sftp_curve25519-chacha20-poly1305_openssh-reassembleS.pcapng](files/pcapng/sftp_curve25519-chacha20-poly1305_openssh-reassembleS.pcapng)  
Description: Example of SFTP transfer with packet reassembly.

File: [sftp_curve25519-aes128-ctr_reassembleS.pcapng](files/pcapng/sftp_curve25519-aes128-ctr_reassembleS.pcapng)  
Description: Example of SFTP transfer with packet reassembly.

File: [sftp_dhgex-sha1_aes128-ctr-reassembledS.pcapng](files/pcapng/sftp_dhgex-sha1_aes128-ctr-reassembledS.pcapng)  
Description: Example of SFTP transfer with packet reassembly.

File: [sftp_dhgex-sha1_aes256-gcm_openssh-reassembleS.pcapng](files/pcapng/sftp_dhgex-sha1_aes256-gcm_openssh-reassembleS.pcapng)  
Description: Example of SFTP transfer with packet reassembly.

### MCPE/RakNet
File: [MCPE-0.15.pcapng](files/pcapng/MCPE-0.15.pcapng)  
Description: Example of [Minecraft Pocket Edition](http://wiki.vg/Pocket_Edition_Protocol_Documentation) 0.15.x on [RakNet](http://www.raknet.com/) protocol.

### NDMP
File: [ndmp.pcap.gz](files/pcap.gz/ndmp.pcap.gz)  
Description: Example of NDMP connection using MD5 method. Capture shows some additonal NDMP traffic not recognized by wireshark (ndmfs extension).

### Kismet Client/Server protocol
File: [kismet-client-server-dump-1.pcap](files/pcap/kismet-client-server-dump-1.pcap)  
Description: Example traffic beetwen Kismet GUI and Kismet Sever (begining of kismet session).

File: [kismet-client-server-dump-2.pcap.gz](files/pcap.gz/kismet-client-server-dump-2.pcap.gz)  
Description: Example traffic beetwen Kismet GUI and Kismet Sever (after new wireless network has been detected).

### Kismet Drone/Server protocol
File: [kdsp.pcap.gz](files/pcap.gz/kdsp.pcap.gz)  
Description: Example traffic between Kismet drone and Kismet sever. See [KDSP](https://wiki.wireshark.org/KDSP)

### DTLS with decryption keys
File: [snakeoil.tgz](files/tgz/snakeoil.tgz)  
Description: Example of [DTLS](https://wiki.wireshark.org/DTLS) simple encrypted traffic and the key to decrypt it. (Simple example made with OpenSSLv0.9.8b)

### DTLS JPAKE as used in ThreadGroup Commissioning
File: [ThreadCommissioning-JPAKE-DTLS-1.pcapng](files/pcapng/ThreadCommissioning-JPAKE-DTLS-1.pcapng)  
Description: Example 1 of [DTLS-JPAKE](https://wiki.wireshark.org/DTLS-JPAKE) traffic. (Thread reference application (DTLS client) against mbedTLS server)

File: [ThreadCommissioning-JPAKE-DTLS-2.pcapng](files/pcapng/ThreadCommissioning-JPAKE-DTLS-2.pcapng)  
Description: Example 2 of [DTLS-JPAKE](https://wiki.wireshark.org/DTLS-JPAKE) traffic. (Thread reference application (DTLS client) against mbedTLS server)

File: [ThreadCommissioning-JPAKE-DTLS-NSS](https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/ThreadCommissioning-JPAKE-DTLS-NSS)  
Description: NSS file for decryption of the two example files.

### ETHERNET Powerlink v1
File: [epl_v1.cap.gz](files/cap.gz/epl_v1.cap.gz)  
Description: Example traffic of [EPL V1](https://wiki.wireshark.org/EPL-V1). Capture shows the traffic of an EPLv1 [ManagingNode](https://wiki.wireshark.org/ManagingNode) and three [ControlledNodes](https://wiki.wireshark.org/ControlledNodes).

### ETHERNET Powerlink v2
File: [epl.cap.gz](files/cap.gz/epl.cap.gz)  
Description: Example traffic of [EPL](https://wiki.wireshark.org/EPL). Capture shows the boot up of an EPLv2 [ManagingNode](https://wiki.wireshark.org/ManagingNode) and one [ControlledNode](https://wiki.wireshark.org/ControlledNode).

File: [epl_sdo_udp.cap](files/cap/epl_sdo_udp.cap)  
Description: Example traffic of [EPL](https://wiki.wireshark.org/EPL). Capture shows an access to the object dictionary of a [ControlledNode](https://wiki.wireshark.org/ControlledNode) within an EPL-Network from outside via [ServiceDataObject](https://wiki.wireshark.org/ServiceDataObject) (SDO) by UDP.

### Architecture for Control Networks (ACN)
File: [acn_capture_example_1.cap](files/cap/acn_capture_example_1.cap)  
Description: Example traffic of [ACN](https://wiki.wireshark.org/ACN). Capture shows just a few examples.

### Intellon Homeplug (INT51X1)
File: [homeplug_request_channel_estimation.pcap](files/pcap/homeplug_request_channel_estimation.pcap)  
Description: Example traffic of [Homeplug](https://wiki.wireshark.org/Homeplug). Capture of Request Channel Estimation (RCE) frame. File: [homeplug_request_parameters_and_statistics.pcap](files/pcap/homeplug_request_parameters_and_statistics.pcap)  
Description: Example traffic of [Homeplug](https://wiki.wireshark.org/Homeplug). Capture of Request Parameters and Statistics (RPS) frame. File: [homeplug_network_statistics_basic.pcap](files/pcap/homeplug_network_statistics_basic.pcap)  
Description: Example traffic of [Homeplug](https://wiki.wireshark.org/Homeplug). Capture of Network Statistics basic (NS) frame.

### Wifi / Wireless LAN captures / 802.11
File: [Network_Join_Nokia_Mobile.pcap](files/pcap/Network_Join_Nokia_Mobile.pcap)  
Description: 802.11 capture of a new client joining the network, authenticating and activating WPA ciphering

File: [wpa-Induction.pcap](files/pcap/wpa-Induction.pcap)  
Description: 802.11 capture with WPA data encrypted using the password "Induction".

File: [wpa-eap-tls.pcap.gz](files/pcap.gz/wpa-eap-tls.pcap.gz)  
Description: 802.11 capture with WPA-EAP. PSK's to decode: a5001e18e0b3f792278825bc3abff72d7021d7c157b600470ef730e2490835d4 79258f6ceeecedd3482b92deaabdb675f09bcb4003ef5074f5ddb10a94ebe00a 23a9ee58c7810546ae3e7509fda9f97435778d689e53a54891c56d02f18ca162

File: [http_PPI.cap](files/cap/http_PPI.cap)  
Description: 802.11n capture with PPI encapsulation containing HTTP data.

File: [mesh.pcap](files/pcap/mesh.pcap)  
Description: 802.11s capture with Radiotap encapsulation.

File: [mesh_assoc_truncated.pcapng](files/pcapng/mesh_assoc_truncated.pcapng) Description: 802.11s capture of an association and beacon packets

File:[wpa2linkuppassphraseiswireshark](files/pcap/wpa2linkuppassphraseiswireshark.pcap)  
Description: Typical WPA2 PSK linked up process (SSID is ikeriri-5g and passphrase is wireshark so you may input wireshark:ikeriri-5g choosing wpa-pwd in decryption key settings in IEEE802.11 wireless LAN settings)

### TrunkPack Network Control Protocol (TPNCP)
File: [tpncp_udp.pcap](files/pcap/tpncp_udp.pcap)  
Description: Example traffic of [TPNCP](https://wiki.wireshark.org/TPNCP) over [UDP](https://wiki.wireshark.org/UDP).

File: [tpncp_tcp.pcap](files/pcap/tpncp_tcp.pcap)  
Description: Example traffic of [TPNCP](https://wiki.wireshark.org/TPNCP) over [TCP](https://wiki.wireshark.org/TCP).

### EtherCAT
File: [ethercat.cap.gz](files/cap.gz/ethercat.cap.gz)  
Description: Example traffic of [Ethercat](https://wiki.wireshark.org/Ethercat). Capture shows the boot up of an network with Beckhoff 1100, 1014, 2004, 3102 and 4132 modules.

### iWARP Protocol Suite
These captures show MPA/DDP/RDMAP communication.

Contributor: Philip Frey

File: [iwarp_connect.tar.gz](files/gz/iwarp_connect.tar.gz) (1.4KB)  
Description: MPA connection setup without data exchange.

File: [iwarp_send_recv.tar.gz](files/gz/iwarp_send_recv.tar.gz) (1.9KB)  
Description: MPA connection setup followed by RDMA Send/Receive data exchange.

File: [iwarp_rdma.tar.gz](files/gz/iwarp_rdma.tar.gz) (7KB)  
Description: MPA connection setup followed by RDMA Write/Read data exchange.

### IPv6 (and tunneling mechanism)
File: [Teredo.pcap](files/pcap/Teredo.pcap)  
Description: Example of [IPv6](https://wiki.wireshark.org/IPv6) traffic using Teredo for encapsulation.

File: [6to4.pcap](files/pcap/6to4.pcap)  
Description: Example of [IPv6](https://wiki.wireshark.org/IPv6) traffic using 6to4 for encapsulation.

File: [6in4.pcap.gz](files/pcap.gz/6in4.pcap.gz)  
Description: Example of [IPv6](https://wiki.wireshark.org/IPv6) traffic using 6in4 for encapsulation.

File: [6LoWPAN.pcap.gz](files/pcap.gz/6LoWPAN.pcap.gz)  
Description: [IPv6](https://wiki.wireshark.org/IPv6) over IEEE 802.15.4.

File: [6lowpan-rfrag-icmpv6.pcapng](files/pcapng/6lowpan-rfrag-icmpv6.pcapng)  
Description: Example of [6LoWPAN Selective Fragment Recovery (RFRAG)](https://tools.ietf.org/html/draft-ietf-6lo-fragment-recovery-02) packets. Payload is ICMPv6 echo request in 6LoWPAN RFRAGs.

File: [sr-header.pcap](files/pcap/sr-header.pcap)  
Description: [IPv6](https://wiki.wireshark.org/IPv6) Segment Routing header.

### TTEthernet (TTE)
File: [TTE_mix_small.pcap](files/pcap/TTE_mix_small.pcap)  
Description: Example of [TTEthernet](https://wiki.wireshark.org/TTEthernet) traffic showing different traffic classes.

### GSM
File: [abis-accept-network.pcap](files/pcap/abis-accept-network.pcap)  
Description: Abis: Setup + Location Updating Request + Accept + SMS. Note: Set "Use GSM SAPI Values" in LAPD preferences.

File: [abis-reject-network.pcap](files/pcap/abis-reject-network.pcap)  
Description: Abis: Setup + Location Updating Request + Reject. Note: Set "Use GSM SAPI Values" in LAPD preferences.

File: [gsm_call_1525.xml](files/xml/gsm_call_1525.xml)  
Description: Um: Mobile phone called the number 1525 and stayed connected for 2-3 seconds.

File: [gsm_sms2.xml](files/xml/gsm_sms2.xml)  
Description: Um: SMS containing "abc"

File: [gsm-r.uus1.pcap](files/pcap/gsm-r.uus1.pcap)  
Description: GSM-R specific messages in the user-user signalling

### UMTS
#### IuB interface
File: [UMTS_FP_MAC_RLC_RRC_NBAP.pcap](files/pcap/UMTS_FP_MAC_RLC_RRC_NBAP.pcap)  
Description: IuB: Mobile Originating Video Call Signaling and traffic. Contains all common IuB protocols: NBAP, FP, MAC, RLC, RRC

#### Iu-CS over IP interface(MoC)
File: [Mobile Originating Call(AMR).pcap](files/pcap/Mobile-Originating-Call(AMR).pcap)  
Description: Iu-CS: Mobile Originating Call Signaling and Bearer in IP network AMR(12.2).

#### Iu-CS over IP interface(MtC)
File: [Mobile Terminating Call(AMR).pcap](files/pcap/Mobile-Terminating-Call(AMR).pcap)  
Description: Iu-CS: Mobile Terminating Call Signaling and Bearer in IP network AMR(12.2)

### X11
File: [x11-gtk.pcap.gz](files/pcap.gz/x11-gtk.pcap.gz) A GTK app opening only an error dialog. Exercises a surprising portion of the RENDER extension.

File: [x11-shape.pcap.gz](files/pcap.gz/x11-shape.pcap.gz) vtwm, xcalc, and xeyes. Multiple SHAPE extension requests and one [ShapeNotify](https://wiki.wireshark.org/ShapeNotify) event.

File: [x11-composite.pcap.gz](files/pcap.gz/x11-composite.pcap.gz) vtwm, 2x xlogo, and xcompmgr. Exercises parts of Composte, Damage, and XFixes extensions.

File: [x11-glx.pcap.gz](files/pcap.gz/x11-glx.pcap.gz) A couple of frames of glxgears, to demonstrate GLX/glRender dissection.

File: [x11-xtest.pcap.gz](files/pcap.gz/x11-xtest.pcap.gz) An xtest test run, uses the XTEST extension.

File: [x11-res.pcap.gz](files/pcap.gz/x11-res.pcap.gz) xlogo and one iteration of xrestop, to demonstrate the X-Resource extension.

File: [x11-xinput.pcapng](files/pcapng/x11-xinput.pcapng)`xinput list`, to demonstrate the XInputExtension extension.

### Gopher
File: [gopher.pcap](files/pcap/gopher.pcap) A capture of the Gopher protocol (a gopher browser retrieving few files and directories).

### InfiniBand
File [infiniband.pcap](files/pcap/infiniband.pcap) (8.7KB)  
Description A libpcap trace file of low level [InfiniBand](https://wiki.wireshark.org/InfiniBand) frames in DLT_ERF format.

### Network News Transfer Protocol (NNTP)
File: [nntp.pcap](files/pcap/nntp.pcap) A capture of the NNTP protocol (a KNode client retrieving few messages from two groups on a Leafnode server).

### FastCGI (FCGI)
File: [fcgi.pcap.gz](files/pcap.gz/fcgi.pcap.gz) A capture of the FCGI protocol (a single HTTP request being processed by an FCGI application).

### Lontalk (EIA-709.1) encapsulated in EIA-852
File: [eia709.1-over-eia852.pcap](files/pcap/eia709.1-over-eia852.pcap) A capture of the Lontalk homeautomation protocol. Lots of button presses, temperature sensors, etc.

### DVB-CI (Common Interface)
File: [dvb-ci_1.pcap](files/pcap/dvb-ci_1.pcap)

A DVB-CI module is plugged into a receiver and initialized. The receiver asks the module to descramble a Pay-TV service. After a moment, there’s a service change and another request to descramble the newly selected service. After some seconds, the module is removed from the receiver.

File: [dvb-ci_2.pcap](files/pcap/dvb-ci_2.pcap)

Communication between a DVB-CI host and module where the maximum message size on the link layer is 16 bytes. Larger messages from upper layers must be fragmented and reassembled.

### ANSI C12.22 (c1222)
File: [c1222overIPv4.cap.gz](files/cap.gz/c1222overIPv4.cap.gz) ([ANSI C12.22](https://wiki.wireshark.org/C12.22)) C12.22 read of Standard Table 1 with response. This communication was using Ciphertext with Authenticaton mode with key 0 = 6624C7E23034E4036FE5CB3A8B5DAB44

File: [c1222_over_ipv6.pcap](files/pcap/c1222_over_ipv6.pcap) ([ANSI C12.22](https://wiki.wireshark.org/C12.22)) C12.22 read of Standard Tables 1 and 2 with response. This communication was using Ciphertext with Authenticaton mode with key 0 = 000102030405060708090A0B0C0D0E0F

### HDCP
File: [hdcp_authentication_sample.pcap](files/pcap/hdcp_authentication_sample.pcap)

HDCP authentication between a DVB receiver and a handheld device

### openSAFETY
File: [opensafety_udp_trace.pcap](files/pcap/opensafety_udp_trace.pcap) openSAFETY communication using UDP as transport protocol

File: [opensafety_epl_trace.pcap](files/pcap/opensafety_epl_trace.pcap) openSAFETY communication using Ethernet Powerlink V2 as transport protocol

File: [opensafety_sercosiii_trace.pcap](files/pcap/opensafety_sercosiii_trace.pcap) openSAFETY communication using SercosIII as transport protocol

### Radio Frequency Identification (RFID), and Near-Field Communication (NFC)
File: [Read-FeliCa-Lite-NDEF-Tags.cap](files/cap/Read-FeliCa-Lite-NDEF-Tags.cap) A trace file from a USB-connected NFC transceiver based upon the NXP PN532 chipset, containing packets from a successful attempt at enumerating, and reading the contents of two Sony [FeliCa](https://wiki.wireshark.org/FeliCa) Lite tags.

### IEC 60870-5-104
File: [iec104.pcap](files/pcap/iec104.pcap) IEC 60870-5-104 communication log.

File: [IEC104_SQ.pcapng](files/pcapng/IEC104_SQ.pcapng) IEC 60870-5-104 communication log with SQ bit.

### IEC 61850 9-2
[IEC 61850 9-2 Sampled Values, Wireshark, and the "Cloudy" effect](https://www.linkedin.com/pulse/iec-61850-9-2-sampled-values-wireshark-cloudy-effect-silveira)

[Github: mgadelha/Sampled_Values](https://github.com/mgadelha/Sampled_Values)

### SISO-STD-002
Simulation Interoperability Standards Organization SISO-STD-002 Standard for Link 16 Simulation

File: [siso_std_002_annex_b_example.pcap](files/pcap/siso_std_002_annex_b_example.pcap) .

File: [siso_std_002_transmitter.pcap](files/pcap/siso_std_002_transmitter.pcap).

Standard: [http://www.sisostds.org/ProductsPublications/Standards/SISOStandards.aspx](http://www.sisostds.org/ProductsPublications/Standards/SISOStandards.aspx)

### STANAG-5602 SIMPLE
Standard Interface for Multiple Platform Evaluation

File: [stanag-5602-simple-example.pcap](files/pcap/stanag-5602-simple-example.pcap) .

Standard: [http://assistdoc1.dla.mil/qsDocDetails.aspx?ident_number=213042](http://assistdoc1.dla.mil/qsDocDetails.aspx?ident_number=213042)

### S7COMM - S7 Communication
[s7comm_downloading_block_db1.pcap](files/pcap/s7comm_downloading_block_db1.pcap) s7comm: Connecting and downloading program block DB1 into PLC

[s7comm_program_blocklist_onlineview.pcap](files/pcap/s7comm_program_blocklist_onlineview.pcap) s7comm: Connecting and getting a list of all available blocks in the S7-300 PLC

[s7comm_reading_plc_status.pcap](files/pcap/s7comm_reading_plc_status.pcap) s7comm: Connecting and viewing the S7-300 PLC status

[s7comm_reading_setting_plc_time.pcap](files/pcap/s7comm_reading_setting_plc_time.pcap) s7comm: Connecting, reading and setting the time of the S7-300 PLC

[s7comm_varservice_libnodavedemo.pcap](files/pcap/s7comm_varservice_libnodavedemo.pcap) s7comm: running libnodave demo with a S7-300 PLC, using variable-services reading several different areas and sizes

[s7comm_varservice_libnodavedemo_bench.pcap](files/pcap/s7comm_varservice_libnodavedemo_bench.pcap) s7comm: running libnodave demo benchmark with S7-300 PLC using variable-services to check the communication capabilities

### Harman Pro HiQnet
[hiqnet_netsetter-soundcraft_session.pcapng.gz](files/pcapng.gz/hiqnet_netsetter-soundcraft_session.pcapng.gz) hiqnet: A session between Harman [NetSetter](https://wiki.wireshark.org/NetSetter) desktop application and a Soundcraft Si Compact 16 digital mixing console reading and writing very basic informations.

[hiqnet_visiremote-soundcraft_session.pcapng.gz](files/pcapng.gz/hiqnet_visiremote-soundcraft_session.pcapng.gz) hiqnet: A session between Soundcraft's [ViSiRemote](https://wiki.wireshark.org/ViSiRemote) iPad application and a Soundcraft Si Compact 16 digital mixing console playing around with different values. The VU-meters stream is not part of this capture because it uses another protocol (UDP on port 3333).

### DJI Drones control Protocol
[djiuav.pcap.gz](files/pcap.gz/djiuav.pcap.gz) DJI drone getting managed and sending video stream.

### HCrt (Hotline Command-response Transaction) Protocol
[hcrt.pcap](files/pcap/hcrt.pcap) Some captures of the HCRT protocol. Specifications of the protocol can be found here: [https://github.com/ShepardSiegel/hotline/tree/master/doc](https://github.com/ShepardSiegel/hotline/tree/master/doc).

### DOF (Distributed Object Framework) Protocols
[tunnel.pcap](files/pcap/tunnel.pcap) Contains a DOF session which exercises many aspects of the protocol, best viewed with display filter "dof"

Most of the packets in this capture are encrypted, to view them:

1. Open Edit/Preferences.
2. Expand Protocols, select DOF.
3. Click “Edit…” on DPS Identity Secrets.
4. Click “New”.
5. In Domain, add ‘[{03}:[james.simister@us.panasonic.com](mailto:james.simister@us.panasonic.com)]’ without the quotes.
6. In Identity, add ‘[{03}:[dt@pan9320.pslcl.com](mailto:dt@pan9320.pslcl.com)]’.
7. In Secret, add ‘2BCFE378663EBF2B5C4D8F971175B4767984CC2544EA969FB37799C777CF4C8F’ without the quotes.
8. Click OK on all the dialogs.

[dof-small-device.pcapng](files/pcapng/dof-small-device.pcapng) Example of a small device communicating with a server.

[dof-short-capture.pcapng](files/pcapng/dof-short-capture.pcapng) Larger example of two nodes communicating.

Both of these captures create secure sessions, but the keys are not provided.

Information on the DOF protocols can be found at [https://opendof.org](https://opendof.org/). Full protocol specifications are available on the downloads page.

### CBOR (Concise Binary Object Representation)
[coap-cbor.pcap](files/pcap/coap-cbor.pcap) The CBOR test vectors over CoAP defined here: [https://github.com/cbor/test-vectors/](https://github.com/cbor/test-vectors/)

### RADIUS (RFC 2865)
File: [radius_localhost.pcapng](files/pcapng/radius_localhost.pcapng)

This file contains RADIUS packets sent from localhost to localhost, using [FreeRADIUS Server](http://freeradius.org/) and the radtest utility.

Description of packets: | Frame | Description | shared secret | | on server | on client | | 1-4 | user steve authenticating with EAP-MD5, password bad (Access rejected) | testing123 | | 5-8 | user steve authenticating with EAP-MD5, password testing (Access Accepted) | testing123 | | 9-10 | same user, same password, PAP (Access Accepted) | testing123 | | 11-12 | same user/password, CHAP (Access Accepted) | testing123 | | 13-14 | same user, password bad_passsword, PAP (Access Rejected) | testing123 | | 15-17 | The client has a wrong shared secret, the server does not answer | bad_secret | testing123 | | 18-19 | Authentication successfull with PAP | bad_secret |

### Distributed Interactive Simulation (IEEE 1278)
Distributed Interactive Simulation (DIS) is described [here](https://en.wikipedia.org/wiki/Distributed_Interactive_Simulation).

Capture files:

+ [DIS_EntityState_1.pcapng](files/pcapng/DIS_EntityState_1.pcapng) - Basic [EntityState](https://wiki.wireshark.org/EntityState) PDUs capture
+ [DIS_EntityState_2.pcapng](files/pcapng/DIS_EntityState_2.pcapng) - Another basic [EntityState](https://wiki.wireshark.org/EntityState) PDUs capture
+ [DIS_EnvironmentalProcess.pcapng](files/pcapng/DIS_EnvironmentalProcess.pcapng) - EnvironmentalProcessPDU capture
+ [DIS_Signal.pcapng](files/pcapng/DIS_Signal.pcapng) - Signal PDUs capture
+ [DIS_signal_and_transmitter.pcapng](files/pcapng/DIS_signal_and_transmitter.pcapng) - Signal and Transmitter PDUs capture

### Financial Information eXchange (FIX)
Capture files generated using the "f8test" program from the open-source FIX protocol implementation [Fix8](http://www.fix8.org/) (version 1.3.4).

+ [fix.pcap](files/pcap/fix.pcap)
+ [fix-ssl.pcap](files/pcap/fix-ssl.pcap)

The SSL keylog file for `fix-ssl.pcap` should contain:  
CLIENT_RANDOM 330221F6F09769F5F0E128551DF5C75F18464BEFB88B9CFE77FB83EFEEE4A6B5 3494FD0D729C23E590F8F7F9B150D534E5F225AA60873E91719A289D8BB92A9CDB482185213F11BB105C7C634A32BCEF

### UserLog
userlog is user flow logs of H3C device.

Flow logging records users’ access to the extranet. The device classifies and calculates flows through the 5-tuple information, which includes source IP address, destination IP address, source port, destination port, and protocol number, and generates user flow logs. Flow logging records the 5-tuple information of the packets and number of the bytes received and sent. With flow logs, administrators can track and record accesses to the network, facilitating the availability and security of the network.

[UserLog.pcap](files/pcap/UserLog.pcap)

### OpenFlow
[openflow_v1.3_messages.pcapng.gz](files/pcapng.gz/openflow_v1.3_messages.pcapng.gz): A collection of [OpenFlow](https://wiki.wireshark.org/OpenFlow) v1.3 packets (taken from [bug 9283](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9283)).

### ISO 8583-1
[iso8583_messages.tar.gz](files/gz/iso8583_messages.tar.gz): A collection of ISO8583-1 packets (taken from [bug 12244](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12244)).

### DNP3
[dnp3_read.pcap](files/pcap/dnp3_read.pcap); [dnp3_select_operate.pcap](files/pcap/dnp3_select_operate.pcap); [dnp3_write.pcap](files/pcap/dnp3_write.pcap). Source: pcapr.net by bwilkerson.

### System Calls
[curl-packets+syscalls-2016-05-04.pcapng](files/pcapng/curl-packets-syscalls-2016-05-04.pcapng): Network traffic and system calls generated by running `curl` to download a file. To be opened with Wireshark.

[curl-wsdl-win64.scap](files/scap/curl-wsdl-win64.scap): System calls generated by running `curl` captured with `sysdig`. To be opened with [Stratoshark](https://wiki.wireshark.org/Stratoshark).

### Linux netlink
[netlink.pcap](files/pcap/netlink.pcap): Linux netlink with rtnetlink (route) and Netfilter protocols, captured in a Ubuntu 14.04.4 QEMU VM. Also contains NFQUEUE traffic with some DNS queries.

[netlink-nflog.pcap](files/pcap/netlink-nflog.pcap): Linux netlink embedding rtnetlink and NFLOG (Netfilter) protocols. The NFLOG packets contain HTTP and ICMP packets, using `nf-queue` program as listener.

[netlink-conntrack.pcap](files/pcap/netlink-conntrack.pcap): Linux netlink, an HTTP request and DNS query with Netfilter (NFQUEUE and conntrack) packets. Used the `conntrack -E` command as listener.

[netlink-ipset.pcap](files/pcap/netlink-ipset.pcap): Linux netlink-netfilter traffic while executing various ipset commands.

[nlmon-big.pcap](files/pcap/nlmon-big.pcap): Linux netlink traffic captured on a MIPS (big-endian) device.

Related (NFLOG):

+ [nflog.pcap](files/pcap/nflog.pcap): another HTTP and ICMP trace captured with `tcpdump -i nflog:42` (NFLOG encapsulation, not netlink).
+ [nflog-ebtables.pcapng](files/pcapng/nflog-ebtables.pcapng): NFLOG via ebtables (family `NFPROTO_BRIDGE`). Contains ARP, IPv4, IPv6, ICMP, ICMPv6, TCP.

### Oracle TNS / SQLnet / OCI / OPI
[TNS_Oracle1.pcap](files/pcap/TNS_Oracle1.pcap) A sample of TNS traffic (dated Apr 2014).

[TNS_Oracle2.pcap](files/pcap/TNS_Oracle2.pcap) A bunch of INSERT INTO's on an Oracle server (dated Apr 2009).

[TNS_Oracle3.pcap](files/pcap/TNS_Oracle3.pcap) A bunch of SELECT FROM's on an Oracle server (dated Apr 2009).

[TNS_Oracle4.pcap](files/pcap/TNS_Oracle4.pcap) Oracle server redirecting to an alternate port upon connection (dated Apr 2009).

[TNS_Oracle5.pcap](files/pcap/TNS_Oracle5.pcap) Another sample of TNS traffic (dated Oct 2015).

[7_oracle10_2016.pcapng](files/pcapng/7_oracle10_2016.pcapng) Oracle 10 examples (dated Dec 2016)

[8_oracle11_2016.pcapng](files/pcapng/8_oracle11_2016.pcapng) Oracle 11 examples (dated Dec 2016)

[9_oracle12_2016.pcapng](files/pcapng/9_oracle12_2016.pcapng) Oracle 12 examples (dated Dec 2016)

[10_sqldeveloper10_2016.pcapng](files/pcapng/10_sqldeveloper10_2016.pcapng) Oracle 10 SQL Developer (dated Dec 2016)

[11_sqldeveloper11_2016.pcapng](files/pcapng/11_sqldeveloper11_2016.pcapng) Oracle 11 SQL Developer (dated Dec 2016)

[12_sqldeveloper12_2016.pcapng](files/pcapng/12_sqldeveloper12_2016.pcapng) Oracle 12 SQL Developer (dated Dec 2016)

[oracle12-example.pcapng](files/pcapng/oracle12-example.pcapng) Oracle 12 examples.

Special thanks to pcapr.net project.

### Lawo EmberPlus S101/Glow
[s101glow.pcap](files/pcap/s101glow.pcap)

### HP ERM
[hp-erm-1.cap](files/cap/hp-erm-1.cap) Simple sample of 2 pings, one untagged on VLAN 10, one tagged on VLAN 2010 and the HP ERM results of the port of the device sending the ICMP Echo Request.

[hp-erm-2.cap](files/cap/hp-erm-2.cap) Complex sample of 2 pings, one untagged on VLAN 10, one tagged on VLAN 2010 and the HP ERM results of the port of the device sending the ICMP Echo Request, the port on the second switch connecting to the first (both VLANs tagged) and a double-encapsulated sample.

### Automotive Protocols
[udp-nm_anon.pcap](files/pcap/udp-nm_anon.pcap) Simple UDP-NM packet.

[caneth.pcapng](files/pcapng/caneth.pcapng) Simple CAN-ETH protocol capture.

### Steam In-Home Streaming Protocol
Valve Software's Steam In-Home Streaming Protocol, which is used by the Steam client and Steam Link devices.

Further Information:

+ [https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol](https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol)
+ [https://codingrange.com/blog/steam-in-home-streaming-control-protocol](https://codingrange.com/blog/steam-in-home-streaming-control-protocol)

[steam-ihs-discovery.pcap](files/pcap/steam-ihs-discovery.pcap) Server discovery and connection negotiation/authentication

### Wi-SUN low power RF Protocol
[wisunSimple.pcapng](files/pcapng/wisunSimple.pcapng) Two almost identical frames containing a PAN Advertisement Solicit. The first frame has an error (missing Header Termination 1) and the second has that error corrected. This was used to test a change in Wireshark intended to give a clearer warning message for exactly this error.

### Nano / RaiBlocks Cryptocurrency Protocol
[nano.pcap](files/pcap/nano.pcap) Some traffic from the Nano live network, including all common packet and block types.

[nano_tcp.pcap](files/pcap/nano_tcp.pcap) Example Nano bootstrap traffic (TCP).

### ua/udp, ua3g and noe protocols (Alcatel-Lucent Enterprise)
[uaudp_ipv6.pcap](files/pcap/uaudp_ipv6.pcap) Some traffic over ipv6. Filter on fc0c::8 and decode frame [#17 (closed)](https://wiki.wireshark.org/wireshark/wireshark/-/issues/17) (udp port 32513) as ua/udp protocol. On capture where the source and destination ports are the same, add the call server ip address in the protocol preferences to allow the correct decoding.

[ua3g_freeseating_ipv6.pcap](files/pcap/ua3g_freeseating_ipv6.pcap) Freeseating message: ipv6 addresses (filter ua3g.ip.freeseating.parameter.ipv6)

[ua3g_freeseating_ipv4.pcap](files/pcap/ua3g_freeseating_ipv4.pcap) Freeseating message: ipv4 address (filter ua3g.ip.freeseating.parameter.ip)

### DICOM
[DICOM_C-ECHO-echoscu.pcap](files/pcap/DICOM_C-ECHO-echoscu.pcap) Successful C-ECHO request generated with echoscu fromOFFIS DICOM Toolkit

### ETSI Intelligent Transport Systems (ITS) Protocols
[etsi-its-cam-unsecured.pcapng](files/pcapng/etsi-its-cam-unsecured.pcapng) Cooperative Awareness Basic Service (CAM) sample capture in non secured mode. See ETSI EN 302 637-2 for protocol details.

[etsi-its-denm-unsecured.pcapng](files/pcapng/etsi-its-denm-unsecured.pcapng) Decentralized Environmental Notification Basic Service (DENM) sample capture in non secured mode. See ETSI EN 302 637-3 for protocol details.

[etsi-its-cam-secured.pcapng](files/pcapng/etsi-its-cam-secured.pcapng) Cooperative Awareness Basic Service (CAM) sample capture in secured mode.

[etsi-its-denm-secured.pcapng](files/pcapng/etsi-its-denm-secured.pcapng) Decentralized Environmental Notification Basic Service (DENM) sample capture in secured mode.

[EA_Request.pcapng](files/pcapng/EA_Request.pcapng) Enrollment Authorization request/response from an OBU/RSU to a PKI EA entity. To decrypt the messages exchange in Wireshark, please use the following parameters:

- Private key of the PKI EA certificate: 06EB0D8314ADC4C3564A8E721DF1372FF54B5C725D09E2E353F2D0A46003AB86

- Whole PKI EA certificate hash SHA-256: 843BA5DC059A5DD3A6BF81842991608C4CB980456B9DA26F6CC2023B5115003E

See:

+ IEEE 1609.2a-2017 IEEE Standard for Wireless Access in Vehicular Environments—Security Services for Applications and Management Messages
+ ETSI TS 102 940 ITS Security; ITS communications security architecture and security management
+ ETSI TS 102 941 ITS Security; Trust and Privacy Management
+ ETSI TS 103 097 ITS Security; Security header and certificate formats

### NetBIOS
A sample program (with nearly the same data transferred) has been run under MS-DOS using different NetBIOS implementations/drivers:

+ [microsoft_npc_netbios.pcapng](files/pcapng/microsoft_npc_netbios.pcapng) NetBEUI (aka NPC) using Microsoft Network Client 3
+ [novell_eth2_netbios.pcapng](files/pcapng/novell_eth2_netbios.pcapng) NetBIOS over IPX using Novell Netware client on Ethernet-II
+ [novell_raw_netbios.pcapng](files/pcapng/novell_raw_netbios.pcapng) NetBIOS over IPX using Novell Netware client on Ethernet-I raw
+ [novell_llc_netbios.pcapng](files/pcapng/novell_llc_netbios.pcapng) NetBIOS over IPX using Novell Netware client using Ethernet-I with LLC

And another NetBIOS example: SMB between an MS-DOS client and a Windows 98 server over NetBEUI: [dos_win98_smb_netbeui.pcapng](files/pcapng/dos_win98_smb_netbeui.pcapng)

### Dynamic Link Exchange Protocol (DLEP)
[dlep.pcap](files/pcap/dlep.pcap) Basic data items as defined in RFC8175

### Asphodel Protocol
[Asphodel_WMRTCP5135.pcapng](files/pcapng/Asphodel_WMRTCP5135.pcapng) Streaming data example from a wireless module through a reciever.

### Protobuf
Please refer to [Protobuf dissector description page](https://wiki.wireshark.org/Protobuf) for how to use the sample capture files.

[protobuf_udp_addressbook.pcapng](files/pcapng/protobuf_udp_addressbook.pcapng) Protobuf UDP example.

[protobuf_tcp_addressbook.pcapng](files/pcapng/protobuf_tcp_addressbook.pcapng) Protobuf TCP example.

[protobuf_udp_addressbook_with_image.pcapng](files/pcapng/protobuf_udp_addressbook_with_image.pcapng) Protobuf UDP example with image field.

[protobuf_udp_addressbook_with_image_ts.pcapng](files/pcapng/protobuf_udp_addressbook_with_image_ts.pcapng) Protobuf UDP example about image field and google.protobuf.Timestamp field.

### MessagePack
[msgpack-generated.pcap](files/pcap/msgpack-generated.pcap) Generated (synthetic) file with MessagePack (msgpack) data wrapped in "Exported PDU" packets that label what each one demonstrates.

### gRPC
Please refer to [gRPC dissector description page](https://wiki.wireshark.org/gRPC) for how to use the sample capture files.

[grpc_person_search_protobuf_with_image.pcapng](files/pcapng/grpc_person_search_protobuf_with_image.pcapng) gRPC Person search service example, using Protobuf to serialize structured data.

[grpc_person_search_json_with_image.pcapng](files/pcapng/grpc_person_search_json_with_image.pcapng) gRPC Person search service example, using JSON to serialize structured data.

### AllJoyn
[Gitlab issues](https://gitlab.com/wireshark/wireshark/-/issues) with samples attached.

[9361 - AllJoyn protocol dissector](https://gitlab.com/wireshark/wireshark/-/issues/9361)

[10567 - Improve support for AllJoyn Reliable Datagram Protocol.](https://gitlab.com/wireshark/wireshark/-/issues/10567)

### Thrift
Please refer to [Thrift dissector description page](https://wiki.wireshark.org/Thrift) for how to use the sample capture files with specific dissectors.

[jaeger-compact.pcap](files/pcap/jaeger-compact.pcap) Thrift Compact Protocol UDP example using [Jaeger](https://www.jaegertracing.io/).

[anony-tcp-std.pcap](files/pcap/anony-tcp-std.pcap) Thrift Binary Protocol TCP example with [packet reassembly](https://gitlab.com/wireshark/wireshark/-/issues/16244).

### Huawei's GRE bonding control (RFC8157)
[greb_DSLkeepalive_m.cap](files/cap/greb_DSLkeepalive_m.cap) Keepalive (regular "Hello") for the bonding as seen on a Deutsche Telekom DSL line (that's why it is encapsuluated in PPP and VLAN 7)

[notifyLTE.pcap](files/pcap/notifyLTE.pcap) "Notify" over LTE, just keeping the IPv6 prefix fresh

[greb_notifyDSLfail_overLTE.cap](files/cap/greb_notifyDSLfail_overLTE.cap) Notification of DSL failure

[greb_filterlist.pcap](files/pcap/greb_filterlist.pcap) Notify incl. filter list

### ADWS
ADWS (Active Directory Web Services) relies on [WCF](https://learn.microsoft.com/en-us/dotnet/framework/wcf/) which relies on [[MC-NMF]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/0aab922d-8023-48bb-8ba2-c4d3404cc69d) and [[MS-NNS]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nns/93df08eb-a6c4-4dff-81c3-519cf7236df4)

In this capture file we have, the first TCP connection using SPNEGO with Kerberos and the second using raw NTLM (without SPNEGO). The targeted server for both is the same but one via FQDN (so Kerberos ticket retrieval worked) and the second via IP.

[wcf_nettcpbinding.pcapng](files/pcapng/wcf_nettcpbinding.pcapng)

### NTLMSSP
See [NTLMSSP](https://wiki.wireshark.org/NTLMSSP)

[NTLM.pcap](files/pcap/NTLM-wenchao.pcap) (libpcap) Illustrate [NTLM](https://wiki.wireshark.org/NTLMSSP) authentication process, based on WSS 3.0

Usage of the [[MS-TSCH](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)] MS-RPC protocol, to create two scheduled tasks with the `SchRpcRegisterTask` method, then listing all the tasks using the `SchRpcEnumTasks` methods. Auth uses NTLMSSP and RPC trafic can be decrypted (as described in [NTLMSSP](https://wiki.wireshark.org/NTLMSSP)) using cleartext password "clem":

+ With NTLMv1 ESS (Extended Session Security): [create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_PKT_PRIVACY_NTLMv1_ESS__password_clem.pcapng](files/pcapng/create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_PKT_PRIVACY_NTLMv1_ESS__password_clem.pcapng)
+ With NTLMv2: [create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_PKT_PRIVACY_NTLMv2__password_clem.pcapng](files/pcapng/create_two_tasks_then_enum_RPC_C_AUTHN_LEVEL_PKT_PRIVACY_NTLMv2__password_clem.pcapng)

The two following examples show LDAP and DRSUAPI MS-RPC trafic that can be decrypted by providing the cleartext "admin" password, as described in [NTLMSSP](https://wiki.wireshark.org/NTLMSSP):

+ [ntlm_ldap.pcapng](files/pcapng/ntlm_ldap.pcapng)
+ [ntlm_rpc.pcapng](files/pcapng/ntlm_rpc.pcapng)

### Zabbix Protocol
+ [zabbix70-proxy-and-agent.pcapng](files/pcapng/zabbix70-proxy-and-agent.pcapng): Zabbix 7.0.0alpha2, active proxy is talking to the server, active agent 2 is talking to the proxy
+ [zabbix30-proxy-and-agent.pcapng](files/pcapng/zabbix30-proxy-and-agent.pcapng): Zabbix 3.0.32 (very old version!), active proxy is talking to the server, active agent is talking to the proxy

### DHCPFO Protocol
Dynamic Host Configuration Protocol - Failover

+ [dhcpfo.pcapng](files/pcapng/dhcpfo.pcapng): Two Windows Server 2022 DHCP servers talking to each other with DHCPFO, while a DHCP client retrieves and releases its lease

### COTP (ISO 8073)
Connection Oriented Transfer Protocol

[COTP_Example.pcapng.gz](files/pcapng.gz/COTP_Example.pcapng.gz): Two computers exchanging messages using ISO 8073 packets on top of RFC 1006.

### MDB
Multi-Drop Bus / Internal Communication Protocol

+ [mdb_cashless_1.pcap](files/pcap/mdb_cashless_1.pcap): Cashless payment transaction
+ [mdb_bill_validator.pcap](files/pcap/mdb_bill_validator.pcap): Bill validator

### TPM 2.0
[30629ce1: tpm20: Add TPM2.0 dissector](https://gitlab.com/wireshark/wireshark/-/commit/30629ce16612c91bc8bdc4184c2a2442f4577965)  
[policy-authorizeNV.pcap](files/pcap/policy-authorizeNV.pcap) TPM2.0 policy sample.

## Captures in specific file formats
[i4b.trace](files/trace/i4b.trace) An I4B (ISDN for BSD) capture file.

[D-1-Anonymous-Anonymous-D-OFF-27d01m2009y-00h00m00s-0a0None.trc](files/trc/D-1-Anonymous-Anonymous-D-OFF-27d01m2009y-00h00m00s-0a0None.trc) An EyeSDN capture file containing DPNSS packets.

[erf-ethernet-example.erf](files/erf/erf-ethernet-example.erf) A Endace [ERF](https://wiki.wireshark.org/ERF) capture file.

[pcapng-example.pcapng](files/pcapng/pcapng-example.pcapng) A PCAPNG example file with packets from interfaces with different link-layer types, file- and packet-comments, a name resolution block and a TLS session keys block.

## Captures used in Wireshark testing
Here are some of the captures used during Wireshark testing. Full collection in the [test/captures](https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures) source code directory.

[c1222_std_example8.pcap](files/pcap/c1222_std_example8.pcap) ANSI C12.22 packets, used to cover bug 9196.

[dhcp-nanosecond.pcap](files/pcap/dhcp-nanosecond.pcap) DHCP with nanosecond timing.

[dhcp.pcapng](files/pcapng/dhcp.pcapng) DHCP saved in pcapng format.

[dns_port.pcap](files/pcap/dns_port.pcap) DNS running on a different port than 53.

[dns+icmp.pcapng.gz](files/pcapng.gz/dns-icmp.pcapng.gz) DNS and ICMP saved in gzipped pcapng format.

[dvb-ci_UV1_0000.pcap](files/pcap/dvb-ci_UV1_0000.pcap) DVB Common Interface (DVB-CI) packet.

[rsasnakeoil2.pcap](files/pcap/rsasnakeoil2.pcap) SSL handshake and encrypted payload.

[sample_control4_2012-03-24.pcap](files/pcap/sample_control4_2012-03-24.pcap) [ZigBee](https://wiki.wireshark.org/ZigBee) protocol traffic.

[snakeoil-dtls.pcap](files/pcap/snakeoil-dtls.pcap) DTLS handshake and encrypted payload.

[wpa-Induction.pcap.gz](files/pcap.gz/wpa-Induction.pcap.gz) [WiFi](https://wiki.wireshark.org/WiFi) 802.11 WPA traffic.

[wpa-eap-tls.pcap.gz](files/pcap.gz/wpa-eap-tls.pcap.gz) [WiFi](https://wiki.wireshark.org/WiFi) 802.11 WPA-EAP/Rekey sample.

[segmented_fpm.pcap](files/pcap/segmented_fpm.pcap) FPM and Netlink used for Lua plugin TCP-based dissector testing.
