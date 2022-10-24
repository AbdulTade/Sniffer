#pragma once

/*
* For ICMP packets whose time to live field in the IPV4 header is zero, then it signifies time exceeded message
*/
#include "pch.h"
#include <winsock2.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "pcap.h"

#ifdef SNIFFER_EXPORTS
#define SNIFFER_API __declspec(dllexport)
#else
#define SNIFFER_API __declspec(dllimport)
#endif

#define PCAP_HDR_MAGIC 0xA1B2C3D4 /* Magic number for packet capture file */

#pragma pack(push,1)
/* Packet capture record pkt_hdr*/
typedef struct {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
#pragma pack(pop)

#pragma pack(push,1)
/* Global Header */
typedef struct {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;
#pragma pack(pop)

#pragma pack(push,1)
/* Modified packet capture record */
typedef struct {
	pcaprec_hdr_t hdr; /* the regular header */
	uint32_t ifindex;  /* index, in *capturing* machine's list of interfaces, of the interface on which this packet came in. */
	uint16_t protocol; /* Ethernet packet type */
	uint8_t  pkt_type; /* broadcast/multicast/etc. indication */
	uint8_t  pad;      /* pad to a 4-byte boundary */
} pcaprec_modified_hdr;
#pragma pack(pop)

typedef enum
{
	ICMP_PROTOCOL = 1,
	TCP_PROTOCOL = 6,
	UDP_PROTOCOL = 17,
	IPV6_PROTOCOL = 41,
	VINES_PROTOCOL = 83,
	OSPF_PROTOCOL = 89,
	SCTP_PROTOCOL = 132
} UPPER_LAYER_PROTOCOL;

typedef enum
{
	NETWORK_UNREACHABLE, /* Tells you if a specific network is unreachable */
	HOST_UNREACHABLE,    /* Tells you if a specific host is currently unreachable */
	PROTOCOL_UNREACHABLE,
	PORT_UNREACHABLE,
	FRAGMENTATION_NEEDED,
	SRC_ROUTE_FAILED,
	DEST_NETWORK_UNKNOWN,
	DEST_HOST_UNKNOWN,
	SRC_HOST_ISOLATED,
	DEST_NETWORK_ADMIN_PROHIB,
	NETWORK_UNRCH_TOS,
	HOST_UNRCH_TOS,
	COMM_ADMIN_PROHIB_FILTR,
	HOST_PRECED_VIOLATION,
	PRECED_CUTOFF_IN_EFF
} ICMP_DEST_UNRCH_CODES;

typedef enum
{
	REDIRECT_FOR_NETWORK, /* For whole network redirects */
	REDIRECT_FOR_HOST,    /* Only used for redirects of a specific host */
	REDIRECT_FOR_TOS_NETWORK,      /* Used for redirects of specific service types and a whole network */
	REDIRECT_FOR_TOS_HOST         /*  */
}ICMP_REDIRECT_CODES;

typedef enum
{
	TTL_EQ_ZERO_IN_TRANSIT,
	TTL_EQ_ZERO_DURING_REASSEMBLY
} ICMP_TIME_EXCEEDED_CODES;

typedef enum
{

} ICMP_TIMESTAMP_CODES;

/* ICMP type values */
typedef enum
{
	ICMP_ECHO_REPLY = 0,
	ICMP_ECHO_REQUEST = 8,
	ICMP_DEST_UNRCH = 3,
	ICMP_SRC_QUENCH = 4,
	ICMP_REDIRECT = 5,
	ICMP_TTL_ZERO = 11,
	ICMP_PARAM_PROB = 12, /* ICMP parameter problem */
	ICMP_TIMESTAMP_REQ = 13,
	ICMP_TIMESTAMP_REP = 14,
	ICMP_INFORMATION_REQ = 15,
	ICMP_INFORMATION_REP = 16
} ICMP_TYPES;


typedef enum
{
	LINKTYPE_NULL, /* BSD loopback encapsulation */
	LINKTYPE_ETHERNET, /* Ethernet link layer */
	LINKTYPE_AX25 = 3,
	LINKTYPE_IEEE802_5 = 6,
	LINKTYPE_ARCNET_BSD = 7,
	LINKTYPE_SLIP       = 8,
	LINKTYPE_RAW = 101,
	LINKTYPE_PPP = 9
}LINKTYPE;


#pragma pack(push,1)
/* IPV4 header */
typedef struct
{
	uint8_t  ver_hdrlen;
	uint8_t  service;
	uint16_t total_length;
	uint16_t ident;
	uint16_t FragmentOffset : 13, isLastFragment : 1, Fragmentable : 1, Unused : 1;
	uint8_t  timetolive;
	uint8_t  Protocol;
	uint16_t HeaderChkSum;
	uint32_t SrcIp;
	uint32_t DestIp;
} IpHdr;
#pragma pack(pop)

#pragma pack(push,1)
/* TCP Header */
typedef struct
{
	uint16_t src_port; /* Source Port */
	uint16_t dest_port; /* Destination Port */
	uint32_t SequenceNumber; /* The sequence number of the first data octet in this segment (except when SYN is present). If SYN is present the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.*/
	uint32_t AcknowlegdementNumber; /* If ACK control bit is set field contains value of the next sequence number the sender of the segment expects to recieve*/
	uint32_t Window : 16, /* The number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.*/
		FIN : 1, /* No more data from sender */
		SYN : 1, /* Synchronize sequence numbers */
		RST : 1, /* Reset the connections */
		PSH : 1, /* Push Function */
		ACK : 1, /* Acknowledgement field significant */
		URG : 1, /* Urgent Pointer field significant */
		Reserved : 6, /* Unused must be zero */
		DataOffset : 4;/* This Indicates where data begins in unit of 4 bytes */

	uint16_t CheckSum; /* One's Complement sum of all 16 bit words in header and text */
	uint16_t UrgentPointer; /* */
	uint32_t Options : 24, Padding : 8;
}TcpHdr;
#pragma pack(pop)

#pragma pack(push,1)
/* UDP Header */
typedef struct
{
	uint16_t uSrcPort;
	uint16_t uDestPort;
	uint16_t uPktLength;
	uint16_t uChkSum;
} UdpHdr;
#pragma pack(pop)

#pragma pack(push,1)
/* Mac Addresses (Dest -- Src) */
typedef struct {
	uint8_t dest[6];
	uint8_t src[6];
} MacAddr;
#pragma pack(pop)

#pragma pack(push,1)
/* 14-byte Ethernet Frame */
typedef struct
{
	MacAddr macaddr;
	uint16_t PacketType;
} EtherFrame;
#pragma pack(pop)

#pragma pack(push,1)
/* ARP Packet Header */
typedef struct
{
	uint16_t HardwareType;
	uint16_t ProtocolType;
	uint8_t  HadwareAddrLength;
	uint8_t  ProtocolAddrLength;
	uint16_t Opcode;
	uint8_t  SrcMac[6];
	uint32_t SrcIp;
	uint8_t  DestMac[6];
	uint32_t DestIp;
}ARP_PACKET;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct
{
	uint8_t ICMP_Type;
	uint8_t Code;
	uint16_t CheckSum;
	union
	{
		struct
		{
			uint16_t Identifier;    /* Set in request packet and sent back in reply packet */
			uint16_t SequenceNumber; /* sequence number for each host */
		}ICMP_ECHO;

		/* Sent to a network device about the state of unreachability of the src or recipient of a packet */
		struct
		{
			uint32_t Unused;
			IpHdr iphdr;
			uint64_t OrigData;
		}ICMP_DEST_UNRCH;

		/* Sent to tell originating packet src to slow down when continuing to send data */
		struct
		{
			uint32_t Unused;
			IpHdr iphdr;
			uint64_t OrigData;
		}ICMP_SRC_QUENCH;

		struct
		{
			uint32_t GateWayIP; /* IP address of gateway */
			IpHdr iphdr;
			uint64_t OrigData;
		} ICMP_REDIRECT;

		/* Sent when a pkt src source when the TTL field of an IPV4 packet carrying an ICMP message is zero */
		struct
		{
			uint32_t Unused;
			IpHdr iphdr;
			uint64_t OrigData;
		}ICMP_TTL_ZERO;
		/*  Parameter problem messages are used to tell the sending host that the gateway or receiving host had problems understanding parts of the IP headers such as errors, or that some required options where missing */
		struct
		{
			uint32_t Pointer : 8, Unused : 24;
			IpHdr iphdr;
			uint64_t OrigData;
		} ICMP_PARAM_PROB;

		/* ICMP time information */
		struct
		{
			uint16_t Identifier;
			uint16_t SequenceNumber;
			uint32_t OriginateTimeStamp; /* Last time a sender touched a packet */
			uint32_t RecieveTimeStamp;   /* Last time echoing host touched packet */
			uint32_t TransmitTimeStamp;  /* Last time set just previous to sending the packet */
		} ICMP_TIMESTAMP;

		struct
		{
			uint16_t Identifier;
			uint16_t SequenceNumber;
		} ICMP_INFORMATION;
	}ICMP_HDR_EXTRA;
}ICMP;

/* QUIC low order byte flags */
typedef enum
{
	SIX_BYTES_PKT_NUM_PRESENT = 0x30,
	FOUR_BYTES_PKT_NUM_PRESENT = 0x20,
	TWO_BYTES_PKT_NUM_PRESENT = 0x10,
	ONE_BYTE_PKT_NUM_PRESENT = 0x00
} QUIC_LO_BYTES_FLAGS;

#pragma pack(push,1)
typedef struct
{
	struct
	{
		uint8_t PublicFlagVersion : 1,
			PublicFlagReset : 1,
			DiversificationNoncePresent : 1,
			ConnectionIDPresent : 1,
			LowOrderBytesPresent : 2,
			Unused : 2;
	}Flags;
}QUIC;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct
{
	uint16_t Id; /* Indetifier to match replies */
	uint16_t RCODE : 4,  /* Response Code 0 not error,1 format error 2 server failure, 3 Name Error,4 Not Implemented 5 Refused */
		Opcode : 4,
		Z : 3,   /* Reserved for future use */
		RA : 1,  /* Recursion Available - set or cleared in a response, denotes whether recursive query support is available in the nameserver */
		RD : 1,  /* Specifies the kind of query in message */
		TC : 1,  /* Truncation - specifies that this message was truncated*/      /* Recursion Desired - directs nameserver to pursue the query recursively */
		AA : 1,  /* Authoritative Answer - specifies that responding nameserver is an authority for the domain in question section*/
		QR : 1;  /* /* Specifies whether message is query or response 0 for requests 1 for response */


	uint16_t QdCount;/* Number of entries in question */
	uint16_t ANCOUNT;/* Number of resource records in the answer section */
	uint16_t NSCOUNT;/* an unsigned 16 bit integer specifying the number of name server resource records in the authority records section*/
	uint16_t ARCOUNT;/* an unsigned 16 bit integer specifying the number of resource records in the additional records section */
} DnsHdr;
#pragma pack(pop)


#define ARP_SIGNATURE 0x0608
#define IPV4_SIGNATURE 0x0008

std::map<int, const char*> ArpHardwareType =
{
	{1,"Ethernet"},
	{6,"IEEE 802 networks or ARCNET"},
	{15,"Frame Relay"},
	{16,"Asynchronous Transfer Mode(ATM)"},
	{17,"HDLC"},
	{18,"Fibre Channel"},
	{19,"Asynchronous Transfer Mode (ATM)"},
	{20,"Serial Line"}
};

const char* OpcodeNames[] =
{
	"\0",
	"ARP Request",
	"ARP Reply",
	"RARP Request",
	"RARP Reply",
	"DRARP Request",
	"DRARP Reply",
	"DRARP Error",
	"InARP Request",
	"InARP Reply"
};

#define ERROR_COLOR   "\033[91m"
#define SUCCESS_COLOR "\033[92m"
#define WARNING_COLOR "\033[93m"
#define RESET_COLOR   "\033[0m"

extern "C" SNIFFER_API void WriteError(const char* _Msg);
extern "C" SNIFFER_API void DieWithError(const char* _Msg, int iExitCode);
extern "C" SNIFFER_API void WriteOutput(const char* _Msg);
extern "C" SNIFFER_API void WriteOutputFormatted(const char* lpColor, const char* fmt, ...);
extern "C" SNIFFER_API void WriteLine(const char* _Msg);


extern "C++" SNIFFER_API class Sniffer
{
private:
	DWORD err;
	static DWORD WSAInit()
	{
		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			printf("WSAStartup failed with error: %d\n", iResult);
			WSACleanup();
			return 0;
		}
		puts("[+] Winsock initialized successfully");
		return 1;
	}


public:
	Sniffer()
	{
		err = WSAInit();
	}
	BOOL Sniff(std::string filename, ULONGLONG Duration);
	BOOL FromFile(std::string filename);
};

extern "C" SNIFFER_API BOOL GetInterfaces(pcap_if_t * *alldevs);
extern "C" SNIFFER_API const char* HexString(int num);
extern "C" SNIFFER_API BOOL GetInterfaceType(pcap_if_t * *alldevs, const char* Type, char* buff, size_t len);
extern "C" SNIFFER_API BOOL DumpToFile(char* dev, char* filename, ULONGLONG Duration);
extern "C" SNIFFER_API void PrintPacketDetails(u_char** pkt_data);
extern "C" SNIFFER_API void ParseDNS(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API void ParseIPV4(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API void ParseTCP(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API void ParseARP(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API void ParseICMP(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API void ParseUDP(uint8_t* udp_pkt_payload);
extern "C" SNIFFER_API BOOL Sniff_Packets(char* filename, ULONGLONG Duration);
extern "C" SNIFFER_API BOOL PathsToFile();

extern "C++" SNIFFER_API std::vector<std::string> FindDiskVolumes();
extern "C++" SNIFFER_API std::vector<std::string> GetDiskPaths(std::vector<std::string> GUIDs);