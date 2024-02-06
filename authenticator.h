#pragma once

#include "packets.h"
#include "platform.h"
#include "math.h"

namespace puf {


typedef struct QueryResult {
    ECP_Point ecp;
    MAC mac;
    bool valid;
    operator bool() const {return valid;}
} QueryResult;


class AuthenticationServer {
public:

    /**
     * Loads entries
    */
    virtual void fetch() = 0;

    /**
     * Saves current entries
    */
    virtual void sync() = 0;

    /**
     * Registers a new supplicant with its base mac, its public point A and the hashed
     * mac. Creates a new entry.
     * 
     * @param base_mac The base mac
     * @param A Public key A
     * @param hashed_mac Hashed version of base mac
     * @param ctr Counter value. Defaults to DEFAULT_COUNTER
    */
    virtual void store(const MAC& base_mac, const ECP_Point& A, MAC& hashed_mac, int ctr) = 0;
    
    /**
     * Checks if the MAC is known and permitted to operate. Hashes MAC and decrements
     * counter if access is granted.
     * 
     * @param hashed_mac The MAC to query, must be a hash of #nth iteration from base mac
     * @return Pair of A and base mac. Empty optional if access is denied
    */
    virtual QueryResult query(const MAC& hashed_mac, bool decrease_counter = true) = 0;
};


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

private:
    bool connected_;
};


};