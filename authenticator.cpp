#include "authenticator.h"
#include "statics.h"
#include "errors.h"

#include <stdio.h>
#include <stdlib.h>


namespace puf {


Authenticator::Authenticator(Network &net, AuthenticationServer &as) : 
    net(net), 
    as(as), 
    G(PUFStatics::instance().ecp_group().G)
{
}


void Authenticator::init() {
    net.init();
    state = IDLE;
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

    return 0;
}


int Authenticator::PUF_CON_phase() {
    uint8_t buffer[128];
    size_t n = net.receive(buffer, sizeof(buffer));

    try {
        puf_con.from_binary(buffer, n);
    } catch(const PacketException &e) {
        puts(e.what());
        return 1;
    }

    printf("T64:\t"); puf_con.T.print64();
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


int Authenticator::PUF_ACK_phase() {
    uint8_t buffer[128];
    size_t n = net.receive(buffer, sizeof(buffer));

    try {
        puf_syn_ack.from_binary( (uint8_t*)buffer, n);  // Build packet from binary
        S = A*puf_syn.d + puf_con.T;                    // Calculate S
    } catch(const PacketException &e) {
        puts(e.what());
        return 1;
    }

    printf("S == S_:\t%s\n", (puf_syn_ack.S == S) ? "true" : "false" );
    return 0;
}


void Authenticator::accept() {    
    size_t bufSize = 128;
    uint8_t buffer[128];

    sign_up();
    PUF_CON_phase();
    PUF_SYN_phase();
    PUF_ACK_phase();
}


}   // Namespace puf