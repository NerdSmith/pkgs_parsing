#include <iostream>
#include <sstream>
#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"

std::string mult(char c, int n)
{
    std::string s = "";
    for (int i = 0; i < n; i++) {
        s += c;
    }
    return s;
}


std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    case pcpp::HTTPRequest:
        return "HTTP";
    default:
        return std::to_string(protocolType);
    }
}

std::string parseEthernet(pcpp::Layer* layer, std::string indent)
{
    pcpp::EthLayer* ethernetLayer = static_cast<pcpp::EthLayer*>(layer);
    std::stringstream res;

    res
        << indent << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
        << indent << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
        << indent << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;
    return res.str();
}

std::string parseIPv4(pcpp::Layer* layer, std::string indent)
{
    pcpp::IPv4Layer* ipLayer = static_cast<pcpp::IPv4Layer*>(layer);
    std::stringstream res;

    res
        << indent << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
        << indent << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
        << indent << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
        << indent << "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;
    return res.str();
}

std::string parseIPv6(pcpp::Layer* layer, std::string indent)
{
    pcpp::IPv6Layer* ipLayer = static_cast<pcpp::IPv6Layer*>(layer);
    std::stringstream res;

    res
        << indent << "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
        << indent << "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl;
    return res.str();
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}

std::string parseTCP(pcpp::Layer* layer, std::string indent)
{
    pcpp::TcpLayer* tcpLayer = static_cast<pcpp::TcpLayer*>(layer);
    std::stringstream res;

    res 
        << indent << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
        << indent << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
        << indent << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl
        << indent << "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;

    return res.str();
}

std::string parseUDP(pcpp::Layer* layer, std::string indent)
{
    pcpp::UdpLayer* udpLayer = static_cast<pcpp::UdpLayer*>(layer);
    std::stringstream res;

    res
        << indent << "Source TCP port: " << udpLayer->getSrcPort() << std::endl
        << indent << "Destination TCP port: " << udpLayer->getDstPort() << std::endl
        << indent << "Window size: " << pcpp::netToHost16(udpLayer->getUdpHeader()->headerChecksum) << std::endl;

    return res.str();
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
    case pcpp::HttpRequestLayer::HttpGET:
        return "GET";
    case pcpp::HttpRequestLayer::HttpPOST:
        return "POST";
    default:
        return "Other";
    }
}

std::string parseHTTP(pcpp::Layer* layer, std::string indent)
{
    pcpp::HttpRequestLayer* httpRequestLayer = static_cast<pcpp::HttpRequestLayer*>(layer);
    std::stringstream res;

    res
        << indent << "HTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
        << indent << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl
        << indent << "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
        << indent << "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << std::endl
        << indent << "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << std::endl
        << indent << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;

    return res.str();
}

std::string parseLayerByProto(pcpp::Layer* layer, std::string indent) {
    pcpp::ProtocolType protoType = layer->getProtocol();

    switch (protoType)
    {
    case pcpp::Ethernet:
        return parseEthernet(layer, indent);
    case pcpp::IPv4:
        return parseIPv4(layer, indent);
    case pcpp::IPv6:
        return parseIPv6(layer, indent);
    case pcpp::TCP:
        return parseTCP(layer, indent);
    case pcpp::UDP:
        return parseUDP(layer, indent);
    case pcpp::HTTPRequest:
        return parseHTTP(layer, indent);
    default:
        return "";
    }
}

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    pcpp::Packet parsedPacket(packet);
    parsedPacket.computeCalculateFields();

    int counter;
    pcpp::Layer* curLayer;
    std::string indent;
    
    std::cout << "---------------------\n";
    for (curLayer = parsedPacket.getFirstLayer(), counter = 0; curLayer != NULL; curLayer = curLayer->getNextLayer(), counter++)
    {
        indent = mult('\t', counter);
        std::cout
            << indent
            << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; "
            << "Total data: " << curLayer->getDataLen() << " [bytes]; "
            << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; "
            << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]"
            << std::endl
            << parseLayerByProto(curLayer, indent);
        
    }
    std::cout << "---------------------\n";
}

void help() 
{
    std::cout << "Using:";
    std::cout << "\t./<program name> <ip to listen>\n";
    std::cout << "\te.g. ./catch_pkgs 192.168.28.108\n";
    return;
}

void printInfo(pcpp::PcapLiveDevice* dev) 
{
    std::cout
        << "Interface info:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl
        << "   Interface description: " << dev->getDesc() << std::endl
        << "   MAC address:           " << dev->getMacAddress() << std::endl
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl
        << "   Interface MTU:         " << dev->getMtu() << std::endl;

    if (dev->getDnsServers().size() > 0)
        std::cout << "   DNS server:            " << dev->getDnsServers().at(0) << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Not enough args\n";
        help();
        return 1;
    }

    std::string interfaceIPAddr = argv[1];

    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
    if (dev == NULL)
    {
        std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
        return 1;
    }

    printInfo(dev);

    if (!dev->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    std::cout << std::endl << "Starting async capture..." << std::endl;

    dev->startCapture(onPacketArrives, NULL);

    pcpp::multiPlatformSleep(200);

    dev->stopCapture();

    return 0;
}
