#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#pragma pack(push, 1)

struct dns_header_t {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct name_label {
    const char* ptr;
    uint8_t len;
};

struct question_t {
    std::vector<name_label> labels;
    uint16_t qtype;
    uint16_t qclass;
};

struct resource_t {
    std::vector<name_label> labels;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata;
};

#pragma pack(pop)

enum class RecordType { UNKNOWN, AN, NS, AR };
enum class RDataType { UNKNOWN, A, AAAA, NS, CNAME, TXT, PTR, SOA, MX };

template <typename T> struct ParseResult {
    bool success;
    std::string error;
    T data;
};

#define MDNS_PORT 5353
#define MDNS_IP "224.0.0.251"
#define MAX_NAME_LEN 256
#define NAME_END 0x00
#define NAME_POINTER 0xC0

volatile sig_atomic_t running = 1;
int sock;

void handle_sigint(int sig) {
    running = 0;
}
int setup();

ParseResult<dns_header_t> parse_dns_header(const char* const& buffer, const size_t len);
ParseResult<question_t> parse_question(const dns_header_t* header, const char* const& buffer, const size_t len,
                                       const char*& ptr);
ParseResult<resource_t> parse_resource(const dns_header_t* header, const char* const& buffer, const size_t len,
                                       const char*& ptr);
ParseResult<std::vector<name_label>> parse_name(const char* const& buffer, const size_t len, const char*& ptr);

void print_buffer(const char* const& buffer, const size_t len);
void print_dns_header(const dns_header_t& header, size_t len);
void print_question(const question_t& question, const uint16_t num);
void print_resource(const resource_t& resource, const uint16_t num, RecordType type);

int main() {
    if (setup() != 0) {
        std::cout << "startup failed" << std::endl;
        return 1;
    }

    // receive data loop
    char buffer[1500] = {0};
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval timeout = {0, 200000};

        int ready = select(sock + 1, &readfds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (running)
                perror("select failed");
            break;
        }
        if (ready == 0)
            continue; // Timeout, loop to check running

        if (FD_ISSET(sock, &readfds)) {
            ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &addrlen);
            if (len < 0) {
                if (running)
                    perror("recvfrom failed");
                break;
            }

            auto header_result = parse_dns_header(buffer, len);
            if (!header_result.success) {
                std::cout << "\033[31m" << header_result.error << "\033[0m" << std::endl;
                print_buffer(buffer, len);
                continue;
            }
            dns_header_t header = header_result.data;
            print_dns_header(header, len);

            const char* ptr = buffer + sizeof(dns_header_t);
            bool parse_failed = false;
            std::string error_msg;

            // Parse questions
            for (uint16_t i = 1; i <= header.qdcount && !parse_failed; i++) {
                auto question_result = parse_question(&header, buffer, len, ptr);
                if (!question_result.success) {
                    parse_failed = true;
                    error_msg = question_result.error;
                    break;
                }
                print_question(question_result.data, i);
            }

            // Parse answers
            for (uint16_t i = 1; i <= header.ancount && !parse_failed; i++) {
                auto resource_result = parse_resource(&header, buffer, len, ptr);
                if (!resource_result.success) {
                    parse_failed = true;
                    error_msg = resource_result.error;
                    break;
                }
                print_resource(resource_result.data, i, RecordType::AN);
            }

            // Parse authority
            for (uint16_t i = 1; i <= header.nscount && !parse_failed; i++) {
                auto resource_result = parse_resource(&header, buffer, len, ptr);
                if (!resource_result.success) {
                    parse_failed = true;
                    error_msg = resource_result.error;
                    break;
                }
                print_resource(resource_result.data, i, RecordType::NS);
            }

            // Parse additional
            for (uint16_t i = 1; i <= header.arcount && !parse_failed; i++) {
                auto resource_result = parse_resource(&header, buffer, len, ptr);
                if (!resource_result.success) {
                    parse_failed = true;
                    error_msg = resource_result.error;
                    break;
                }
                print_resource(resource_result.data, i, RecordType::AR);
            }

            if (parse_failed) {
                std::cout << "\033[31m" << error_msg << "\033[0m" << std::endl;
                print_buffer(buffer, len);
                continue;
            }
        }
    }

    std::cout << std::endl << "shutting down" << std::endl;
    close(sock);
    return 0;
}

int setup() {
    // setup signals
    signal(SIGINT, handle_sigint);

    // create socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return 1;
    }

    // allow reuse of local addresses
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(sock);
        return 1;
    }

    // bind to DNS port
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MDNS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("bind failed");
        close(sock);
        return 1;
    }

    // join group
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_IP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
        perror("setsockopt IP_ADD_MEMBERSHIP failed");
        close(sock);
        return 1;
    }

    std::cout << "startup complete" << std::endl;
    return 0;
}

ParseResult<dns_header_t> parse_dns_header(const char* const& buffer, const size_t len) {
    if (len < sizeof(dns_header_t)) {
        return {false, "Buffer too small for DNS header", {}};
    }
    dns_header_t header = *(dns_header_t*)buffer;
    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qdcount = ntohs(header.qdcount);
    header.ancount = ntohs(header.ancount);
    header.nscount = ntohs(header.nscount);
    header.arcount = ntohs(header.arcount);
    return {true, "", header};
}

ParseResult<question_t> parse_question(const dns_header_t* header, const char* const& buffer, const size_t len,
                                       const char*& ptr) {
    question_t question;
    auto name_result = parse_name(buffer, len, ptr);
    if (!name_result.success) {
        return {false, name_result.error, {}};
    }
    question.labels = name_result.data;
    if (ptr + 4 > buffer + len) {
        return {false, "Buffer too small for qtype and qclass", {}};
    }
    question.qtype = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    question.qclass = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    return {true, "", question};
}

ParseResult<resource_t> parse_resource(const dns_header_t* header, const char* const& buffer, const size_t len,
                                       const char*& ptr) {
    resource_t resource;
    auto name_result = parse_name(buffer, len, ptr);
    if (!name_result.success) {
        return {false, name_result.error, {}};
    }
    resource.labels = name_result.data;
    if (ptr + 10 > buffer + len) {
        return {false, "Buffer too small for resource fields", {}};
    }
    resource.rtype = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    resource.rclass = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    resource.ttl = ntohl(*(uint32_t*)ptr);
    ptr += 4;
    resource.rdlength = ntohs(*(uint16_t*)ptr);
    ptr += 2;
    if (ptr + resource.rdlength > buffer + len) {
        return {false, "Invalid rdata length", {}};
    }
    // TODO: Implement rdata parsing.
    resource.rdata.assign(ptr, ptr + resource.rdlength);
    ptr += resource.rdlength;
    return {true, "", resource};
}

ParseResult<std::vector<name_label>> parse_name(const char* const& buffer, const size_t len, const char*& ptr) {
    std::vector<name_label> labels;
    const char* compressedNamePtr = nullptr;
    while (true) {
        if (ptr >= buffer + len) {
            return {false, "Pointer out of bounds", {}};
        }
        uint8_t label_len = *ptr;
        if (label_len == NAME_END) {
            if (compressedNamePtr != nullptr) {
                ptr = compressedNamePtr;
            }
            ptr++;
            break;
        } else if (label_len >= NAME_POINTER) {
            if (ptr + 1 >= buffer + len) {
                return {false, "Invalid pointer", {}};
            }
            uint16_t raw_offset = *((uint16_t*)ptr);
            uint16_t offset = ntohs(raw_offset) & 0x3FFF;
            if (offset >= len) {
                return {false, "Invalid offset", {}};
            }
            if (compressedNamePtr == nullptr) {
                compressedNamePtr = ptr + 1;
            }
            ptr = buffer + offset;
        } else {
            if (ptr + label_len + 1 > buffer + len) {
                return {false, "Invalid label len " + std::to_string(label_len), {}};
            }
            ptr++;
            labels.push_back({ptr, label_len});
            ptr += label_len;
        }
    }
    return {true, "", labels};
}

void print_buffer(const char* const& buffer, const size_t len) {
    std::cout << "\tHex=";
    for (ssize_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

void print_dns_header(const dns_header_t& header, size_t len) {
    std::cout << "received: bytes=" << std::left << std::setw(4) << std::setfill(' ') << len << ", id=" << header.id
              << ", flags=" << std::left << std::setw(5) << std::setfill(' ') << header.flags
              << ", qdcount=" << std::left << std::setw(2) << std::setfill(' ') << header.qdcount
              << ", ancount=" << std::left << std::setw(2) << std::setfill(' ') << header.ancount
              << ", nscount=" << std::left << std::setw(2) << std::setfill(' ') << header.nscount
              << ", arcount=" << std::left << std::setw(2) << std::setfill(' ') << header.arcount << std::endl
              << std::resetiosflags(std::ios::left) << std::setfill(' ');
}

void print_question(const question_t& question, const uint16_t num) {
    std::string qname = "";
    for (size_t i = 0; i < question.labels.size(); ++i) {
        qname += std::string(question.labels[i].ptr, question.labels[i].len);
        if (i < question.labels.size() - 1)
            qname += ".";
    }

    std::cout << "\t"
              << "\033[34m"
              << "qd" << (int)num << ", qtype=" << (int)question.qtype << ", qclass=" << (int)question.qclass
              << ", qname=" << qname << "\033[0m" << std::endl;
}

void print_resource(const resource_t& resource, const uint16_t num, RecordType type) {
    std::string rname = "";
    for (size_t i = 0; i < resource.labels.size(); ++i) {
        rname += std::string(resource.labels[i].ptr, resource.labels[i].len);
        if (i < resource.labels.size() - 1)
            rname += ".";
    }
    std::string rdata_str;
    for (uint8_t byte : resource.rdata) {
        rdata_str += (byte >= 32 && byte <= 127) ? (char)byte : '?';
    }

    std::string type_str;
    std::string color;
    switch (type) {
    case RecordType::AN:
        type_str = "an";
        color = "\033[33m";
        break;
    case RecordType::NS:
        type_str = "ns";
        color = "\033[38;5;161m";
        break;
    case RecordType::AR:
        type_str = "ar";
        color = "\033[38;5;73m";
        break;
    default:
        type_str = "unknown";
        color = "\033[0m";
        break;
    }

    std::cout << "\t" << color << type_str << (int)num << ", rtype=" << (int)resource.rtype
              << ", rclass=" << (int)resource.rclass << ", ttl=" << (int)resource.ttl
              << ", rdlength=" << (int)resource.rdlength << ", rname=" << rname << ", rdata=" << rdata_str << "\033[0m"
              << std::endl;
}
