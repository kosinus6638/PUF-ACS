#pragma once

#include <arpa/inet.h>  // htons

#include "math.h"
#include "global_defines.h"

namespace puf {


const uint16_t ETH_TYPE = htons(ETHER_TYPE_PUF_ACS);
const uint16_t ETH_Q = htons(ETHER_TYPE_Q);
const uint16_t ETH_AD = htons(ETHER_TYPE_AD);
const uint16_t ETH_EX = htons(ETHER_TYPE_EXPERIMENTAL);


enum __attribute__((__packed__)) packet_type_e {
    PUF_CON_E = 0x01,
    PUF_SYN_E = 0x02,
    PUF_SYN_ACK_E = 0x03,
    PUF_PERFORMANCE_E = 0x04,
    PUF_UNKNOWN_E = 0x05
};


packet_type_e deduce_type(const uint8_t *buf, size_t bufLen);


typedef union VLAN_Payload {
    struct __attribute__((__packed__)) {
        uint16_t load1;
        uint16_t load2;
    };
    uint32_t payload;
} VLAN_Payload;


typedef struct MAC {
    uint8_t bytes[6];
    void hash(int iterations = 1);
    void print() const;

    uint8_t& operator[](int index);
    bool operator!();
    bool operator==(const MAC &rhs) const;
#ifdef __linux
    MAC& operator^=(const uint64_t*);
#elif ESP_PLATFORM
    MAC& operator^=(const uint32_t*);
#endif
    uint64_t to_u64() const;
} MAC;


class PUF_CON {
    typedef union {
        struct __attribute__((__packed__))  {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint8_t ether_type[2];
            uint8_t type;
            uint8_t T[65];
        } U;
        uint8_t data[sizeof(U)];
    } Header_t;

    Header_t header;

public:
    MAC src_mac, dst_mac;
    ECP_Point T;

    void calc();
    void from_binary(uint8_t*, size_t);
    uint8_t* binary();
    constexpr size_t header_len() {return sizeof(Header_t);}
};


class PUF_SYN {
    typedef union {
        struct __attribute__((__packed__)) {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint8_t ether_type[2];
            uint8_t type;
            uint8_t d[4];
            uint8_t pc[6];
            uint8_t C[65];
        } U;
        uint8_t data[sizeof(U)];
    } Header_t;

    Header_t header;
public:
    MPI d;
    ECP_Point C;
    MAC src_mac, dst_mac, pc;

    void calc();
    void from_binary(uint8_t*, size_t);
    uint8_t* binary();
    constexpr size_t header_len() {return sizeof(Header_t);}
};


class PUF_SYN_ACK {
    typedef union {
        struct __attribute__((__packed__))  {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint8_t ether_type[2];
            uint8_t type;
            uint8_t S[65];
        } U;
        uint8_t data[sizeof(U)];
    } Header_t;

    Header_t header;

public:
    MAC src_mac, dst_mac;
    ECP_Point S;

    void calc();
    void from_binary(uint8_t*, size_t);
    uint8_t* binary();
    constexpr size_t header_len() {return sizeof(Header_t);}
};


class PUF_Performance {
    typedef union {
        struct __attribute__((__packed__))  {
            uint8_t dst_mac[6];
            uint8_t src_mac[6];
            uint8_t ad_header[2];
            uint8_t vlan_buf_1[2];
            uint8_t q_header[2];
            uint8_t vlan_buf_2[2];
            uint8_t ether_type[2];
        } U;
        uint8_t data[ETHER_FRAME_LEN];
    } Header_t;

    Header_t header;

public:
    MAC src_mac, dst_mac;

    void calc();
    void from_binary(uint8_t*, size_t);
    uint8_t* binary();
    constexpr size_t header_len() {return sizeof(Header_t);}

    void set_payload(const VLAN_Payload load);
    VLAN_Payload get_payload() const;
};


using REGISTER = PUF_CON;


};  // Namespace puf