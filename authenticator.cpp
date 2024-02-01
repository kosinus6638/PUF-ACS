#include "authenticator.h"
#include "statics.h"
#include "errors.h"

#include <stdio.h>
#include <stdlib.h>


namespace puf {


Authenticator::Authenticator(Network &net, AuthenticationServer &as) : 
    net(net), 
    as(as), 
    G(PUFStatics::instance().ecp_group().G),
    connected_(false)
{ }

Authenticator::~Authenticator() {
    as.sync();
}

void Authenticator::init() {
    net.init();
    as.fetch();
    switch_mac = SWITCH_MAC;
}


int Authenticator::sign_up() {
    REGISTER reg;

    uint8_t buffer[128];
    size_t n = net.receive(buffer, sizeof(buffer));

    try {
        reg.from_binary(buffer, n);
    } catch(const PacketException &e) {
        return 1;
    }

    A = reg.T;
    base_mac = reg.src_mac;                 // Store Base MAC
    remote_mac = reg.src_mac;               // Current remote MAC (differs from base MAC when hashed)
    switch_mac = reg.dst_mac;               // Current MAC of this very device
    printf("Remote MAC:\t"); remote_mac.print();
    remote_mac.hash(1);                     // Hash
    printf("Public Key A: "); A.print64();

    as.store(base_mac, A, remote_mac, DEFAULT_COUNTER);

    return 0;
}


int Authenticator::PUF_CON_phase() {
    // Query for hashed mac
    auto q = as.query(puf_con.src_mac);
    if(!q) {
        return 1;
    }
    base_mac = q.mac;
    A = q.ecp;
    remote_mac = puf_con.src_mac;
    return 0;
}


int Authenticator::PUF_SYN_phase() {
    puf_syn.pc = base_mac;              // Set PUF Challenge
    puf_syn.dst_mac = remote_mac;       // Set remote MAC
    puf_syn.src_mac = switch_mac;       // Set source MAC
    mbedtls_mpi_sint d_sint = rand();   // Get random number
    puf_syn.d = d_sint;                 // Set random value for d
    c = rand();                         // Set random value for c

    try {
        puf_syn.C = G*c;                    // Calc C
        K = puf_con.T*c;                    // Calc K (required for k = K.x)
#if MBEDTLS_VERSION_MAJOR >= 3
        k = K.private_X;                    // Calc k
        puf_syn.pc ^= k.private_p;          // Calc pc
#else 
        k = K.X;                            // Calc k
        puf_syn.pc ^= k.p;                  // Calc pc
#endif
    } catch(const MathException &e) {
        puts(e.what());
        return 1;
    }

    puf_syn.calc();                     // Build package
    net.send(puf_syn.binary(), puf_syn.header_len());

    return 0;
}


bool Authenticator::PUF_ACK_phase() {
    S = A*puf_syn.d + puf_con.T;                    // Calculate S
    return puf_syn_ack.S == S;
}


int Authenticator::accept(uint8_t *buffer, size_t n) {    
    uint8_t buffer_[128];
    uint8_t n_;

    // Error check
    if( deduce_type(buffer, n) != PUF_CON_E ) {
        puts("Packet is not of type PUF_CON");
        return 1;
    }

    // Query supplicant
    puf_con.from_binary( buffer, n );
    if( PUF_CON_phase() != 0) {
        puts("Query did not yield result");
        return 1;
    }
    connected_ = false;

    // Calculate and send PUF_SYN
    PUF_SYN_phase();

    // Receive PUF_SYN_ACK
    n_ = net.receive(buffer_, sizeof(buffer_));
    if( deduce_type(buffer_, n_) != PUF_SYN_ACK_E ) {
        puts("Packet is not of type PUF_SYN_ACK");
        return 1;
    }

    // Check if access is granted
    puf_syn_ack.from_binary(buffer_, n_);
    connected_ = PUF_ACK_phase();
    return connected_ ? 0 : 1;
}


}   // Namespace puf