#include "supplicant.h"
#include "statics.h"
#include "errors.h"
#include <time.h>

namespace puf {

const static MAC switch_mac = SWITCH_MAC;


Supplicant::Supplicant(Network &net_, PUF &puf_) : 
    state(UNINITIALISED),
    ctr(0),
    net(net_), 
    sram_puf(puf_),
    G(PUFStatics::instance().ecp_group().G) {
}


// Init hardwarespecific modules
void Supplicant::init() {
    net.init();
    mac = sram_puf.puf_to_mac();
    state = INITIALISED;

    // ToDo: Use Non-Volatile Storage to know how many times the mach must be hashed
    mac.hash(1);
}


int Supplicant::wait_for_AU_ok() {
    return 10;
    // uint8_t buffer[128];
    // int n = net.receive(buffer, sizeof(buffer));
    // PUF_Performance pp;
    // pp.from_binary(buffer, n);
    // auto counter = pp.get_payload().payload;
    // ctr = static_cast<int>(counter);
    // return 0; 
}


void Supplicant::sign_up() {
    REGISTER reg;
    MPI a;

    MAC base_mac = sram_puf.puf_to_mac();
    MAC response = sram_puf.get_puf_response(base_mac);

    a.from_binary(response.bytes, 6);
    reg.T = G*a;

    reg.src_mac = base_mac;
    reg.dst_mac = switch_mac;
    reg.calc();

    // Data exchange with AU
    net.send(reg.binary(), reg.header_len());
    ctr = wait_for_AU_ok();
}


int Supplicant::PUF_CON_phase() {
    PUF_CON puf_con;
    t = rand();
    puf_con.T = G*t;
    puf_con.src_mac = mac;
    puf_con.dst_mac = switch_mac;
    puf_con.calc();
    net.send(puf_con.binary(), puf_con.header_len());
    return 0;
}


int Supplicant::PUF_SYN_phase() {

    uint8_t buffer[512];
    int n = net.receive(buffer, sizeof(buffer));

    // Timeout/Access Denied
    if( n < 0 ) {
        puts("Timeout");
        return 1;
    } 
    buffer[n] = 0;

    try {
        puf_syn.from_binary(buffer, n);
    } catch(const PacketException &e) {     // Faulty package
        puts(e.what());
        return 1;
    }

    return 0;
}


int Supplicant::PUF_ACK_phase() {

    PUF_SYN_ACK puf_syn_ack;
    ECP_Point S;

    try {
#if MBEDTLS_VERSION_MAJOR >= 3
        k = (puf_syn.C*t).private_X;
        puf_syn.pc ^= k.private_p;
#else
        k = (puf_syn.C*t).X;
        puf_syn.pc ^= k.p;
    #endif

        MAC response = sram_puf.get_puf_response(puf_syn.pc);
        MPI a(response.bytes, 6);

        S = G*(t + (a*puf_syn.d));

        puf_syn_ack.dst_mac = switch_mac;
        puf_syn_ack.src_mac = mac;
        puf_syn_ack.S = S;
        puf_syn_ack.calc();
        net.send(puf_syn_ack.binary(), puf_syn_ack.header_len());

    } catch(const PacketException &e) {
        puts(e.what());
        return 1;
    } catch(const NetworkException &e) {
        puts(e.what());
        return 1;
    }
    return 0;
}


bool Supplicant::connected() {
    return state == CONNECTED;
}


void Supplicant::connect(int attempts) {

    while(state != CONNECTED && attempts > 0) {
        printf("Trying to connect. Attempts left: %d\n", attempts);
        switch(state) {

            case UNINITIALISED:
                throw puf::Exception("Supplicant has not been initialised yet");
                break;

            case INITIALISED:
                PUF_CON_phase();
                state = HANGING;
                [[fallthrough]];

            case HANGING:
                if( PUF_SYN_phase() != 0) {
                    state = INITIALISED;
                    attempts--;
                    break;
                }
                state = VALIDATING;
                [[fallthrough]];

            case VALIDATING:
                if(PUF_ACK_phase() != 0) {
                    state = INITIALISED;
                    attempts--;
                    break;
                }
                state = CONNECTED;
                break;

            default:
                ;
        }
    }
}


};  // namespace puf