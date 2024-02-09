#pragma once

#include "packets.h"
#include "platform.h"
#include "math.h"

namespace puf {


class Authenticator {
public:

    Network &net;
    AuthenticationServer &as;

    MPI k;
    MPI c;
    ECP_Point G;
    ECP_Point A;
    ECP_Point K;
    ECP_Point S;

    MAC base_mac; 
    MAC remote_mac;
    MAC switch_mac;

    PUF_CON puf_con;
    PUF_SYN puf_syn;
    PUF_SYN_ACK puf_syn_ack;

    int PUF_CON_phase();
    int PUF_SYN_phase();
    bool PUF_ACK_phase();

public:
    Authenticator(Network&, AuthenticationServer&);
    Authenticator() = delete;
    Authenticator(Authenticator&) = delete;
    Authenticator(Authenticator&&) = delete;
    ~Authenticator();

    void init();
    int sign_up();
    int accept(uint8_t *buffer, size_t n);
    bool connected() {return connected_;}
    bool validate(const PUF_Performance &pp, bool initial_frame=false);

private:
    bool connected_;
};


};