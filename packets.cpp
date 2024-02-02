#include "packets.h"
#include "errors.h"

#include <mbedtls/sha256.h>


namespace puf {


packet_type_e deduce_type(const uint8_t *buf, size_t bufLen) {

    if( *reinterpret_cast<const uint16_t*>( buf + sizeof(MAC)*2 ) == ETH_AD ) {
        return PUF_PERFORMANCE_E;
    } else {
        switch( *reinterpret_cast<const packet_type_e*>( buf + sizeof(MAC)*2+2 ) ) {
            case PUF_CON_E:
                return PUF_CON_E;
            case PUF_SYN_E:
                return PUF_SYN_E;
            case PUF_SYN_ACK_E:
                return PUF_SYN_ACK_E;
            default:
                return PUF_UNKNOWN_E;
        }
    }
}


void MAC::hash(int iterations) {
    static unsigned char output[32];
    for(int i=0; i<iterations; ++i) {
#if MBEDTLS_VERSION_MAJOR >= 3
        if( mbedtls_sha256(bytes, 6, output, 0) ) {
#else
        if( mbedtls_sha256_ret(bytes, 6, output, 0) ) {
#endif
            throw PacketException("Error SHA256");
        }
        memcpy(bytes, output, 6);
    }
}


void MAC::print() const {
    for(int i=0; i<sizeof(bytes); ++i) {
        printf("%02x", bytes[i]);
        putc( i==5 ? '\n' : ':', stdout );
    }
}


uint8_t& MAC::operator[](int index) {
    return bytes[index];
}


bool MAC::operator!() {
    for(int i=0; i<sizeof(bytes); ++i) {
        if(bytes[i]) return false;
    }
    return true;
}


bool MAC::operator==(const MAC &rhs) const {
    return memcmp(bytes, rhs.bytes, 6) == 0;
}


uint64_t MAC::to_u64() const {
    uint64_t retval = 0;
    uint8_t *ptr = reinterpret_cast<uint8_t*>(&retval);
    for(size_t i=0; i<sizeof(bytes); ++i) {
        *ptr++ = bytes[i];
    }
    return retval;
}


#ifdef __linux
MAC& MAC::operator^=(const uint64_t* buf) {
#elif ESP_PLATFORM
MAC& MAC::operator^=(const uint32_t* buf) {
#endif
    if(!buf) throw PacketException("Buffer must not be Null");
    for(int i=0; i<6; ++i) {
        // bytes[i] ^= *(((uint8_t*)(buf))+i);
        bytes[i] ^= *(reinterpret_cast<const uint8_t*>(buf));
    }
    return *this;
}


void PUF_CON::calc() {
    memset(&header, 0, sizeof(header));
    memcpy(header.U.src_mac, src_mac.bytes, 6);
    memcpy(header.U.dst_mac, dst_mac.bytes, 6);
    memcpy( header.U.ether_type, &ETH_TYPE, sizeof(header.U.ether_type) );
    header.U.type = PUF_CON_E;
    memcpy(header.U.T, T.binary(), 65);
}


uint8_t* PUF_CON::binary() {
    return header.data;
}


void PUF_CON::from_binary(uint8_t *buffer, size_t buflen) {
    if(!buffer) {
        throw PacketException("Buffer must not be NULL");
    }
    if(buflen != header_len()) {
        throw PacketException("PUF_CON: Wrong buffer size");
    }
    
    memcpy(header.data, buffer, buflen);

    T.from_binary(header.U.T, sizeof(header.U.T));
    memcpy(src_mac.bytes, header.U.src_mac, sizeof(src_mac.bytes));
    memcpy(dst_mac.bytes, header.U.dst_mac, sizeof(dst_mac.bytes));
}


void PUF_SYN::calc() {
    memset(&header, 0, sizeof(header));

    uint32_t d_sint = d.binary32();

    memcpy(header.U.src_mac, src_mac.bytes, 6);
    memcpy(header.U.dst_mac, dst_mac.bytes, 6);
    memcpy( header.U.ether_type, &ETH_TYPE, sizeof(header.U.ether_type) );
    header.U.type = PUF_SYN_E;
    memcpy(header.U.d, &d_sint, sizeof(header.U.d));
    memcpy(header.U.pc, pc.bytes, sizeof(header.U.pc));
    memcpy(header.U.C, C.binary(), 65);
}


uint8_t* PUF_SYN::binary() {
    return header.data;
}


void PUF_SYN::from_binary(uint8_t *buffer, size_t buflen) {
    if(!buffer) {
        throw PacketException("Buffer must not be NULL");
    }

    if(buflen != header_len()) {
        throw PacketException("PUF_SYN: Wrong buffer size");
    }

    memcpy(header.data, buffer, buflen);

    C.from_binary(header.U.C, sizeof(header.U.C));
    d.from_binary(header.U.d, sizeof(header.U.d));
    memcpy(src_mac.bytes, header.U.src_mac, sizeof(src_mac.bytes));
    memcpy(dst_mac.bytes, header.U.src_mac, sizeof(dst_mac.bytes));
    memcpy(pc.bytes, header.U.pc, sizeof(pc.bytes));
}


void PUF_SYN_ACK::calc() {
    memset(&header, 0, sizeof(header));
    memcpy(header.U.src_mac, src_mac.bytes, 6);
    memcpy(header.U.dst_mac, dst_mac.bytes, 6);
    memcpy( header.U.ether_type, &ETH_TYPE, sizeof(header.U.ether_type) );
    header.U.type = PUF_SYN_ACK_E;
    memcpy(header.U.S, S.binary(), 65);
}


uint8_t* PUF_SYN_ACK::binary() {
    return header.data;
}


void PUF_SYN_ACK::from_binary(uint8_t *buffer, size_t buflen) {
    if(!buffer) {
        throw PacketException("Buffer must not be NULL");
    }
    if(buflen != header_len()) {
        throw PacketException("PUF_SYN_ACK: Wrong buffer size");
    }

    memcpy(header.data, buffer, buflen);

    S.from_binary(header.U.S, sizeof(header.U.S));
    memcpy(src_mac.bytes, header.U.src_mac, sizeof(src_mac.bytes));
    memcpy(dst_mac.bytes, header.U.dst_mac, sizeof(dst_mac.bytes));
}


void PUF_Performance::calc() {
    memset(&header, 0, sizeof(header));
    memcpy(header.U.src_mac, src_mac.bytes, 6);
    memcpy(header.U.dst_mac, dst_mac.bytes, 6);
    memcpy(header.U.q_header, &ETH_Q, sizeof(header.U.q_header) );
    memcpy(header.U.ad_header, &ETH_AD, sizeof(header.U.ad_header) );
    memcpy(header.U.ether_type, &ETH_EX, sizeof(header.U.ether_type) );
}


uint8_t* PUF_Performance::binary() {
    return header.data;
}


void PUF_Performance::set_payload(Payload load) {
    *(reinterpret_cast<uint16_t*>(header.U.vlan_buf_1)) = load.load1;
    *(reinterpret_cast<uint16_t*>(header.U.vlan_buf_2)) = load.load2;
}


Payload PUF_Performance::get_payload() const {
    Payload retval;
    retval.load1 = *(reinterpret_cast<const uint16_t*>(header.U.vlan_buf_1));
    retval.load2 = *(reinterpret_cast<const uint16_t*>(header.U.vlan_buf_2));
    return retval;
}


void PUF_Performance::from_binary(uint8_t *buffer, size_t buflen) {
    // Buffer checks
    if(!buffer) {
        throw PacketException("Buffer must not be NULL");
    }
    if(buflen < 64 || buflen > ETHER_FRAME_LEN) {
        throw PacketException("PUF_Performance: Wrong buffer size");
    }

    // Integrity check
    memcpy(header.data, buffer, buflen);
    if( memcmp( header.U.q_header, &ETH_Q, sizeof(header.U.q_header)) != 0 ||
        memcmp( header.U.ad_header, &ETH_AD, sizeof(header.U.ad_header) != 0)) 
    {
        memset(header.data, 0, sizeof(header.data));
        throw PacketException("Faulty header types");
    }

    memcpy(src_mac.bytes, header.U.src_mac, sizeof(src_mac.bytes));
    memcpy(dst_mac.bytes, header.U.dst_mac, sizeof(dst_mac.bytes));
}

};  // namespace puf