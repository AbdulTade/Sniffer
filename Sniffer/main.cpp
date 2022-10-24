#include "pch.h"
#include <Winsock2.h>
#include <iostream>
#include <string.h>
#include <string>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "Shlwapi.h"
#include "pcap.h"
#include "PktHeaders.h"

#pragma comment(lib,"ws2_32")
#pragma comment(lib,"Shlwapi")

void WriteError(const char* _Msg)
{
    fprintf(stderr, "%s%s %s\n", ERROR_COLOR, _Msg, RESET_COLOR);
}

void DieWithError(const char* _Msg, int iExitCode)
{
    WriteError(_Msg);
    ExitProcess(iExitCode);
}

void WriteOutput(const char* _Msg)
{
    fprintf(stdout, "%s%s%s", SUCCESS_COLOR, _Msg, RESET_COLOR);
}

void WriteLine(const char* _Msg)
{
    fprintf(stdout, "%s%s%s\n", SUCCESS_COLOR, _Msg, RESET_COLOR);
}

void WriteOutputFormatted(const char* lpColor, const char* fmt, ...)
{
    if (lpColor == NULL)
        lpColor = SUCCESS_COLOR;
    printf("%s", lpColor); // Set terminal color. Only valid for powershell
    va_list args;
    va_start(args, fmt);
    vprintf_s(fmt, args);
    va_end(args);
    printf("%s", RESET_COLOR);
}


const char* HexString(int num)
{
    srand((unsigned int)time(NULL));
    static std::string buff;
    char* tmp = new char[10];

    for (int i = 0; i < num; i++)
    {
        memset(tmp, 0, 10);
        snprintf(tmp, 10, "%x", rand() % 255);
        buff.append(tmp);
    }
    buff.append(".pcap");
    return buff.c_str();
}

BOOL GetInterfaces(pcap_if_t** alldevs)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    RtlSecureZeroMemory(errbuf, PCAP_ERRBUF_SIZE);
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, alldevs, errbuf) == -1)
    {
        WriteOutputFormatted("%s", errbuf);
        return FALSE;
    }
    return TRUE;
}

BOOL GetInterfaceType(pcap_if_t** alldevs, const char* Type, char* buff, size_t len)
{
    char* lower;
    for (d = *alldevs; d != NULL; d = d->next)
    {
        lower = AnsiLower(d->description);
        if (strstr(lower, Type) != NULL)
        {
            memcpy(buff, d->name, len);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL DumpToFile(char* dev, char* filename, ULONGLONG Duration)
{
    pcap_t* capture;
    pcap_dumper_t* dumpfile;
    pcap_pkthdr* header;
    u_char* pkt_data;
    int res = -1;
    ULONGLONG tick = GetTickCount64();
    capture = pcap_open_live(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 2500, NULL);
    if (capture == NULL)
    {
        return FALSE;
    }

    dumpfile = pcap_dump_open(capture, filename);
    if (dumpfile == NULL)
    {
        return FALSE;
    }

    while ((res = pcap_next_ex(capture, &header, (const u_char**)&pkt_data)) >= 0)
    {
        if (GetTickCount64() - tick <= (Duration * 2500))
        {
            if (res == 0)
                continue;
            PrintPacketDetails(&pkt_data);
            pcap_dump((unsigned char*)dumpfile, header, pkt_data);
        }
        else {
            pcap_dump_close(dumpfile);
            break;
        }
    }
    return TRUE;
}

void* ChangeByteEndian(void* ptr_to_data, int size_to_reverse)
{
    char* data_ptr = (char*)ptr_to_data;
    char* host_bytes = new char[size_to_reverse];
    if (!host_bytes)
        return NULL;
    for (int i = 0; i < size_to_reverse; i++)
        host_bytes[i] = data_ptr[(size_to_reverse - 1) - i];
    return host_bytes;
}

void PrintPacketDetails(u_char** pkt_data)
{
    size_t eframe_size = sizeof(EtherFrame);
    IpHdr* iphdr;       /* IP header*/
    EtherFrame* eframe;	/* Source and Destination mac address */
    uint8_t ipver;		/* IP version 4 for IPV4 */
    uint8_t hdrlen;		/* header field in units of 4 bytes */

    eframe = (EtherFrame*)(*pkt_data);

    if (eframe->PacketType == ARP_SIGNATURE)
    {
        ParseARP(*(pkt_data));
    }

    else if (eframe->PacketType == IPV4_SIGNATURE)
    {
        iphdr = (IpHdr*)(*(pkt_data)+eframe_size);
        uint16_t payload_size = iphdr->total_length - ((iphdr->ver_hdrlen & 0x0F) * 4);
        char* pkt_payload = (char*)(*pkt_data + eframe_size + sizeof(IpHdr));

        ParseIPV4(*pkt_data);

        if (iphdr->Protocol == ICMP_PROTOCOL)
        {
            ParseICMP((uint8_t*)pkt_payload);
        }

        else if (iphdr->Protocol == TCP_PROTOCOL)
        {

            ParseTCP((uint8_t*)pkt_payload);
        }

        else if (iphdr->Protocol == UDP_PROTOCOL)
        {

            UdpHdr* udphdr = (UdpHdr*)(pkt_payload);
            ParseUDP((uint8_t*)pkt_payload);

            if (ntohs(udphdr->uSrcPort) == 53 || ntohs(udphdr->uDestPort) == 53)
            {
                uint8_t* udp_payload = (uint8_t*)udphdr + sizeof(UdpHdr);
                ParseDNS(udp_payload);
            }
        }

        puts("");
        //Hide limits to pointer data inside pointer;
        // Since 64 bit windows uses 48 bit physical addressing
        return;
    }

}

void GetMac(u_char* addr, const char* type)
{
    char mac[25];
    uint8_t mac_bytes_network[6] = { 0 };
    for (int i = 0; i < 6; i++)
    {
        mac_bytes_network[i] = *(addr + i);
    }

    snprintf
    (
        mac, 24,
        "%x:%x:%x:%x:%x:%x",
        mac_bytes_network[0], mac_bytes_network[1],
        mac_bytes_network[2], mac_bytes_network[3],
        mac_bytes_network[4], mac_bytes_network[5]
    );

    printf("[*] %s Mac: %s\n", type, mac);
}

void GetIP(uint8_t* addr, const char* type)
{
    char ip[26];
    uint8_t ip_div[4] = { 0 };
    for (int j = 0; j < 4; j++)
    {
        ip_div[j] = *(addr + j);
    }
    //char* ip_div_host = (char*)ChangeByteEndian(ip_div, 0x4);

    snprintf
    (
        ip, 25,
        "%d.%d.%d.%d",
        ip_div[0], ip_div[1],
        ip_div[2], ip_div[3]
    );

    printf("[*] %s IP: %s\n", type, ip);
}

void sig_cleanup(int signum)
{
    WriteOutput("[*] Cleaning Up ...");
    WSACleanup();
    exit(0);
}

void ParseDNS(uint8_t* udp_pkt_payload)
{
    DnsHdr* dnshdr = (DnsHdr*)(udp_pkt_payload);
    uint8_t* dns_payload = (uint8_t*)(udp_pkt_payload + sizeof(DnsHdr));
    WriteOutput("[*] ====================================================================  DNS        ========================================================================================\n");
    printf("[*] Identifier          :\t%10d\n", ntohs(dnshdr->Id));
    printf("[*] QR                  :\t%10d\n", dnshdr->QR);
    printf("[*] Opcode              :\t%10d\n", dnshdr->Opcode);
    printf("[*] Authoritative Answer:\t%10d\n", dnshdr->AA);
    printf("[*] Truncation          :\t%10d\n", dnshdr->TC);
    printf("[*] Recursion Desired   :\t%10d\n", dnshdr->RD);
    printf("[*] Recursion Available :\t%10d\n", dnshdr->RA);
    printf("[*] Unused              :\t%10d\n", dnshdr->Z);
    printf("[*] Response Code       :\t%10d\n", dnshdr->RCODE);
    printf("[*] Num Questions       :\t%10d\n", ntohs(dnshdr->QdCount));
    printf("[*] Num RR in Answers   :\t%10d\n", ntohs(dnshdr->ANCOUNT));
    printf("[*] NameServer RRs      :\t%10d\n", ntohs(dnshdr->NSCOUNT));
    printf("[*] No Add. Records     :\t%10d\n", ntohs(dnshdr->ARCOUNT));
    WriteOutput("[*] ====================================================================  DNS END    ========================================================================================\n");
}

void ParseTCP(uint8_t* pkt_payload)
{
    TcpHdr* tcphdr = (TcpHdr*)pkt_payload;
    WriteOutput("[*] ====================================================================  TCP HEADER ========================================================================================\n");
    printf("[*] Source Port:\t%10d\n", ntohs(tcphdr->src_port));
    printf("[*] Destination Port:\t%10d\n", ntohs(tcphdr->dest_port));
    printf("[*] Sequence Number:\t%10lu\n", ntohl(tcphdr->SequenceNumber));
    printf("[*] AcknowledgementNumber:\t%10lu\n", ntohl(tcphdr->AcknowlegdementNumber));
    printf("[*] DataOffset:\t%10lu\n", tcphdr->DataOffset);
    printf("[*]	Flags:\n\tURG\t%10d\n\tACK\t%10d\n\tPSH\t%10d\n\tRST\t%10d\n\tSYN\t%10d\n\tFIN\t%10d\n", tcphdr->URG, tcphdr->ACK, tcphdr->PSH, tcphdr->RST, tcphdr->SYN, tcphdr->FIN);
    printf("[*] Window:\t%10lu\n", ntohl(tcphdr->Window));
    printf("[*] Checksum:\t%10d\n", ntohs(tcphdr->CheckSum));
    printf("[*] UrgentPointer:\t%10d\n", ntohs(tcphdr->UrgentPointer));
    printf("[*] Options:\t%10lu\n", ntohl(tcphdr->Options));
    printf("[*] Padding:\t%10lu\n", ntohl(tcphdr->Padding));
    WriteOutput("[*] ====================================================================  TCP END    ========================================================================================\n");

    uint16_t src_port = ntohs(tcphdr->src_port);
    uint16_t dest_port = ntohs(tcphdr->dest_port);

    if (src_port == 80 || dest_port == 80)
    {
        WriteOutput("[*] HTTP packet");
    }
}

void ParseUDP(uint8_t* pkt_payload)
{
    UdpHdr* udphdr = (UdpHdr*)(pkt_payload);
    WriteOutput("[*] ====================================================================  UDP HEADER ========================================================================================\n");
    printf("[*] Source Port:\t%10d\n", ntohs(udphdr->uSrcPort));
    printf("[*] Destination Port:\t%10d\n", ntohs(udphdr->uDestPort));
    printf("[*] Packet Length:\t%10d\n", ntohs(udphdr->uPktLength));
    printf("[*] Checksum:\t%10d\n", ntohs(udphdr->uChkSum));
    WriteOutput("[*] ====================================================================  UDP END    ========================================================================================\n");
}

void ParseICMP(uint8_t* pkt_payload)
{
    WriteOutput("[*] ====================================================================  ICMP HEADER =======================================================================================\n");
    ICMP* icmp_pkt = (ICMP*)(pkt_payload);
    printf("[*] ICMP Type:\t%d\n", icmp_pkt->ICMP_Type);
    printf("[*] ICMP Code:\t%d\n", icmp_pkt->Code);
    printf("[*] ICMP Checksum:\t0x%x\n", ntohs(icmp_pkt->CheckSum));
    switch (icmp_pkt->ICMP_Type)
    {

    case ICMP_ECHO_REQUEST:
        printf("[*] Identifier:\t%d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.Identifier));
        printf("[*] SequenceNumber:\t%d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.SequenceNumber));
        break;
    case ICMP_ECHO_REPLY:
        printf("[*] Identifier:\t%d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.Identifier));
        printf("[*] SequenceNumber:\t%lu\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.SequenceNumber));
        break;
    case ICMP_DEST_UNRCH:
        WriteOutput("[*] ICMP Destination Unreachable\n");
        break;
    case ICMP_REDIRECT:
        GetIP((uint8_t*)&icmp_pkt->ICMP_HDR_EXTRA.ICMP_REDIRECT.GateWayIP, "GetWay IP");
        break;
    case ICMP_SRC_QUENCH:
        WriteOutput("[*] ICMP Source Quench\n");
        break;
    case ICMP_TTL_ZERO:
        WriteOutput("[*] ICMP Time Exceeded\n");
        break;
    case ICMP_PARAM_PROB:
        printf("[*] ICMP Pointer:\t%10lu\n", ntohl(icmp_pkt->ICMP_HDR_EXTRA.ICMP_PARAM_PROB.Pointer));
        break;
    case ICMP_TIMESTAMP_REP:
        WriteOutput("[*] ICMP Timestamp reply\n");
        break;
    case ICMP_TIMESTAMP_REQ:
        WriteOutput("[*] ICMP Timestamp request\n");
        break;
    case ICMP_INFORMATION_REP:
        WriteOutput("[*] ICMP information reply\n");
        printf("[*] Identifier:\t%d10\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.Identifier));
        printf("[*] SequenceNumber:\t%10d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.SequenceNumber));
        break;
    case ICMP_INFORMATION_REQ:
        WriteOutput("[*] ICMP information request\n");
        printf("[*] Identifier:\t%10d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.Identifier));
        printf("[*] SequenceNumber:\t%10d\n", ntohs(icmp_pkt->ICMP_HDR_EXTRA.ICMP_ECHO.SequenceNumber));
        break;
    }

    WriteOutput("[*] ====================================================================  ICMP END   ========================================================================================\n");
}

void ParseIPV4(uint8_t* pkt_data)
{
    size_t eframe_size = sizeof(EtherFrame);
    IpHdr* iphdr;       /* IP header*/
    EtherFrame* eframe;	/* Source and Destination mac address */
    uint8_t ipver;		/* IP version 4 for IPV4 */
    uint8_t hdrlen;		/* header field in units of 4 bytes */

    eframe = (EtherFrame*)(pkt_data);
    iphdr = (IpHdr*)(pkt_data + eframe_size);

    uint16_t payload_size = iphdr->total_length - ((iphdr->ver_hdrlen & 0x0F) * 4);
    char* pkt_payload = (char*)(pkt_data + eframe_size + sizeof(IpHdr));

    ipver = (iphdr->ver_hdrlen & 0xF0) >> 4;
    hdrlen = (iphdr->ver_hdrlen & 0x0F) * 4;

    WriteOutput("[*] ====================================================================  IPV4 HEADER =======================================================================================\n");
    GetMac(eframe->macaddr.src, "Src");
    GetMac(eframe->macaddr.dest, "Dest");
    printf("[*] IP version:\t%10d\n[*] hdrlen:\t%10u bytes\n", ipver, hdrlen);
    printf("[*] Packet Identification %10lu\n", ntohs(iphdr->ident));
    int isLastFragment = !(iphdr->isLastFragment);
    int isFragmentable = !(iphdr->Fragmentable);
    int FragmentOffset = iphdr->FragmentOffset;

    printf("[*] Service:\t0x%10x\n", iphdr->service);
    printf("[*] Total Length:\t%10d\n", ntohs(iphdr->total_length));
    printf("[*] Flags:\n\tFragmentable %10d\n\tisLastFragment %10d\n\tTFragmentOffset: %10d\n", isFragmentable, isLastFragment, FragmentOffset);
    printf("[*] Time to Live (TTL):\t%10d hops\n", iphdr->timetolive);
    printf("[*] Protocol:\t%10d\n", iphdr->Protocol);
    printf("[*] CheckSum:\t0x%10x\n", ntohs(iphdr->HeaderChkSum));

    GetIP((uint8_t*)&iphdr->SrcIp, "Src");
    GetIP((uint8_t*)&iphdr->DestIp, "Dest");

    WriteOutput("[*] ====================================================================  IPV4 END   ========================================================================================\n");
}

void ParseARP(uint8_t* pkt_data)
{
    size_t eframe_size = sizeof(EtherFrame);
    EtherFrame* eframe = (EtherFrame*)pkt_data;

    eframe = (EtherFrame*)(pkt_data);
    ARP_PACKET* arp_pkt = (ARP_PACKET*)(pkt_data + eframe_size);
    WriteOutput("[*] ====================================================================  ARP PACKET ========================================================================================\n");
    GetMac(eframe->macaddr.src, "Src");
    GetMac(eframe->macaddr.dest, "Dest");
    printf("[*] HardwareType:\t%10d\n", ntohs(arp_pkt->HardwareType));
    printf("[*] MessageLayerProtocol:\t%10d\n", ntohs(arp_pkt->ProtocolType));
    printf("[*] HardwareAddrLength:\t%10d\n", arp_pkt->HadwareAddrLength);
    printf("[*] ProtocolAddrLength:\t%10d\n", arp_pkt->ProtocolAddrLength);

    if (!((arp_pkt->Opcode < 1) && (arp_pkt->Opcode > 9)))
        printf("[*] Opcode:\t%s\n", OpcodeNames[ntohs(arp_pkt->Opcode)]);
    else
        WriteError("[*] Opcode:\tUnknown\n");

    GetMac((u_char*)&arp_pkt->SrcMac, "Src");
    GetMac((u_char*)&arp_pkt->DestMac, "Dest");
    GetIP((u_char*)&arp_pkt->SrcIp, "Src");
    GetIP((u_char*)&arp_pkt->DestIp, "Dest");
    WriteOutput("[*] ====================================================================  ARP END    ========================================================================================\n");

    puts("\n");
    return;
}

BOOL Sniff_Packets(char* filename, ULONGLONG Duration)
{
    BOOL bFileExists = TRUE;
    char iface_name[MAX_PATH] = { 0 };
    const char* filename_str = filename;

    if (!filename)
        filename_str = HexString(64);
    pcap_t* capture = NULL;
    pcap_dumper_t* dumpfile = NULL;
    pcap_pkthdr* header = NULL;
    u_char* pkt_data = NULL;
    int res = -1;

    if (!Duration)
        Duration = ULLONG_MAX;

    if (!filename)
        bFileExists = FALSE;

    pcap_if_t* alldevs;

    if (!GetInterfaces(&alldevs))
    {
        WriteError("[*] GetInterfaces() failed\n");
        return FALSE;
    }

    if (!GetInterfaceType(&alldevs, "wi-fi", iface_name, MAX_PATH))
    {
        WriteError("[*] GetInteraceType() failed\n");
        return FALSE;
    }
    ULONGLONG tick = GetTickCount64();
    capture = pcap_open_live(iface_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 2500, NULL);
    if (capture == NULL)
    {
        return FALSE;
    }

    if (bFileExists)
    {
        dumpfile = pcap_dump_open(capture, filename_str);
        if (dumpfile == NULL)
            return FALSE;
    }

    while ((res = pcap_next_ex(capture, &header, (const u_char**)&pkt_data)) >= 0)
    {
        if (GetTickCount64() - tick <= (Duration * 1000))
        {
            if (res == 0)
                continue;

            (bFileExists) ? pcap_dump((unsigned char*)dumpfile, header, pkt_data) : PrintPacketDetails(&pkt_data);
        }
        else {
            if (bFileExists)
                pcap_dump_close(dumpfile);
            break;
        }
    }

    if (bFileExists)
        pcap_dump_close(dumpfile);

    WSACleanup();
    return TRUE;
}

BOOL Sniffer::Sniff(std::string filename, ULONGLONG Duration)
{
    BOOL bFileExists = TRUE;
    char iface_name[MAX_PATH] = { 0 };
    const char* filename_str = filename.c_str();
    pcap_t* capture = NULL;
    pcap_dumper_t* dumpfile = NULL;
    pcap_pkthdr* header = NULL;
    u_char* pkt_data = NULL;
    int res = -1;
    if (!err)
        return FALSE;

    if (!Duration)
        Duration = ULLONG_MAX;

    if (!filename.size())
        bFileExists = FALSE;

    pcap_if_t* alldevs;

    if (!GetInterfaces(&alldevs))
    {
        WriteError("[*] GetInterfaces() failed\n");
        return FALSE;
    }

    if (!GetInterfaceType(&alldevs, "wi-fi", iface_name, MAX_PATH))
    {
        WriteError("[*] GetInteraceType() failed\n");
        return FALSE;
    }
    ULONGLONG tick = GetTickCount64();
    capture = pcap_open_live(iface_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 2500, NULL);
    if (capture == NULL)
    {
        return FALSE;
    }

    if (bFileExists)
    {
        dumpfile = pcap_dump_open(capture, filename_str);
        if (dumpfile == NULL)
            return FALSE;
    }

    while ((res = pcap_next_ex(capture, &header, (const u_char**)&pkt_data)) >= 0)
    {
        if (GetTickCount64() - tick <= (Duration * 1000))
        {
            if (res == 0)
                continue;

            (bFileExists) ? pcap_dump((unsigned char*)dumpfile, header, pkt_data) : PrintPacketDetails(&pkt_data);
        }
        else {
            if (bFileExists)
                pcap_dump_close(dumpfile);
            break;
        }
    }

    if (bFileExists)
        pcap_dump_close(dumpfile);

    WSACleanup();
    return TRUE;
}

BOOL Sniffer::FromFile(std::string filename)
{
    if (!PathFileExistsA(filename.c_str()))
    {
        WriteError("[*] File does not exist");
        return FALSE;
    }


    std::ifstream file;
    file.open(filename, std::ios::binary);
    file.seekg(SEEK_END);
    size_t size = file.tellg();
    file.seekg(SEEK_SET);

    char* buff = new char[size];
    if (!buff)
        return FALSE;

    RtlZeroMemory(buff, size);
    file.read(buff, size);
    file.close();

    printf("[*] 0x%08x\n", *((u_long*)buff));

    pcap_hdr_t* g_hdr = (pcap_hdr_t*)(buff);
    char* pkt_hdr_data_arr = (char*)(buff + sizeof(pcap_hdr_t));
    size_t snaplen = ntohs(g_hdr->snaplen);
    
    if (g_hdr->magic_number != PCAP_HDR_MAGIC)
    {
        WriteError("[*] Invalid capture file format ");
        return FALSE;
    }

    WriteOutputFormatted(NULL, "[*] Packet capture version: %d.%d\n",ntohs(g_hdr->version_major),ntohs(g_hdr->version_minor));
    if (ntohl(g_hdr->network) != LINKTYPE_ETHERNET)
    {
        WriteError("[*] Unrecognized linktype terminating ...\n");
        return FALSE;
    }

    WriteOutput("[*] Linktype Ethernet\n");
    size_t size_pkt_hdr_arr = size - sizeof(pcap_hdr_t);
    while (size_pkt_hdr_arr <= 0)
    {
        pcaprec_hdr_t* pkt_hdr = (pcaprec_hdr_t*)(pkt_hdr_data_arr);
        time_t ts_sec = pkt_hdr->ts_sec;
        time_t ts_usec = pkt_hdr->ts_usec;

        uint8_t* payload = (uint8_t*)((char*)pkt_hdr_data_arr + sizeof(pcap_hdr_t));
        WriteOutputFormatted(NULL,"[*] Timestamp: %ll.%ll\n",ts_sec,ts_usec);

        PrintPacketDetails(&payload);
        size_pkt_hdr_arr -= sizeof(pcaprec_hdr_t) + g_hdr->snaplen;
        pkt_hdr = (pcaprec_hdr_t*)(payload + g_hdr->snaplen + sizeof(pcap_hdr_t));
    }
}


/*LPCSTR WipeDisk(char* volume_path)
{
    size_t size = strlen(volume_path);
    char* volume_wildcard = new char[MAX_PATH];
    memset(volume_wildcard, 0x0, MAX_PATH);
    snprintf(volume_wildcard, MAX_PATH, "%s*", volume_path);

    if (!PathFileExistsA(volume_path))
        return "File does not exist";

    if (!strcmp(AnsiUpper(volume_path), "C:\\"))
        return "Cannot delete root directory";

    DWORD attr = GetFileAttributesA(volume_path);
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY))
        return "File not a directory";

    SHFILEOPSTRUCTA ShFile;
    ShFile.fFlags = FOF_NO_UI;
    ShFile.wFunc = FO_DELETE;
    ShFile.hwnd = NULL;
    ShFile.pFrom = volume_wildcard;
    ShFile.pTo = NULL;

    if (!SHFileOperationA(&ShFile))
        return NULL;

    return "SHFileOperationA() failed";
}*/

std::vector<std::string> FindDiskVolumes()
{
    HANDLE hVolume = NULL;
    std::vector<std::string> volume_names;
    char* GUID = new char[MAX_PATH];

    hVolume = FindFirstVolumeA(GUID, MAX_PATH);
    if (hVolume == INVALID_HANDLE_VALUE)
    {
        volume_names[0] = "\0";
        return volume_names;
    }

    std::string volume = GUID;
    volume_names.push_back(volume);
    BOOL err = TRUE;

    for (; err == TRUE;)
    {
        err = FindNextVolumeA(hVolume, GUID, MAX_PATH);
        std::string name = GUID;
        volume_names.push_back(name);
    }

    FindVolumeClose(hVolume);
    return volume_names;
}


std::vector<std::string> GetDiskPaths(std::vector<std::string> GUIDs)
{
    std::vector<std::string> Paths;
    BOOL bSuccess = FALSE;
    DWORD dwCount = 5;

    for (int i = 0; i < GUIDs.size(); i++)
    {
        DWORD returnLength = MAX_PATH + 1;
        char* name = new char[MAX_PATH];
    again:
        bSuccess = GetVolumePathNamesForVolumeNameA(GUIDs[i].c_str(), name, MAX_PATH, &returnLength);
        if (bSuccess)
        {
            std::string path = name;
            Paths.push_back(path);
            continue;
        }
        else
            while (dwCount--)
                goto again;

        printf(GUIDs[i].c_str());
    }

    return Paths;
}

BOOL PathsToFile()
{
    std::vector<std::string> GUIDs = FindDiskVolumes();
    if (GUIDs[0] == "\0")
        return FALSE;
    std::vector<std::string> paths = GetDiskPaths(GUIDs);
    if (paths[0] == "\0")
        return FALSE;
    std::string drive_paths;

    for (int i = 0; i < paths.size(); i++)
    {
        if (paths[i] == "")
            continue;
        drive_paths += paths[i] + '\n';
    }

    std::ofstream ostream;
    ostream.open("disk.txt", std::ios::binary);
    ostream.write(drive_paths.c_str(),drive_paths.size());
    ostream.close();

    return TRUE;
}