#pragma once

#include "packets.h"
#include "platform.h"
#include "math.h"

namespace puf {


#define DEFAULT_RESOURCE    "Supplicant.csv"
#define DEFAULT_COUNTER     100


typedef struct QueryResult {
    ECP_Point ecp;
    MAC mac;
    bool valid;
    operator bool() const {return valid;}
} QueryResult;


class AuthenticationServer {
public:

    /**
     * Loads entries from a resource at URL.
     * 
     * @param url The URL from which the entries are loaded. Defaults to DEFAULT_FILE
    */
    void fetch(const char* url=DEFAULT_RESOURCE);

    /**
     * Saves current entries into resource at URL.
     * 
     * @param filename The filename the entries are written into. Defaults to DEFAULT_FILE
    */
    void sync(const char* url=DEFAULT_RESOURCE);

    /**
     * Registers a new supplicant with its base mac, its public point A and the hashed
     * mac. Creates a new entry.
     * 
     * @param base_mac The base mac
     * @param A Public key A
     * @param hashed_mac Hashed version of base mac
     * @param ctr Counter value. Defaults to DEFAULT_COUNTER
    */
    void store(const MAC& base_mac, const ECP_Point& A, MAC& hashed_mac, int ctr=DEFAULT_COUNTER);
    
    /**
     * Checks if the MAC is known and permitted to operate. Hashes MAC and decrements
     * counter if access is granted.
     * 
     * @param hashed_mac The MAC to query, must be a hash of #nth iteration from base mac
     * @return Pair of A and base mac. Empty optional if access is denied
    */
    QueryResult query(const MAC& hashed_mac);
};

extern char* intern_k;
extern char* intern_c;

class Authenticator {
public:

    enum AuthenticatorState {
        UINITIALISED = 0,
        IDLE,       // Awaiting PUF_CON or PUF_Performance
        AWAITING_PUF_SYN_ACK
    };
    AuthenticatorState state;

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

    int sign_up();
    int PUF_CON_phase();
    int PUF_SYN_phase();
    int PUF_ACK_phase();

public:
    Authenticator(Network&, AuthenticationServer&);


    Network &net;
    AuthenticationServer &as;

    void init();
    void accept();

    Authenticator() = delete;
    Authenticator(Authenticator&) = delete;
    Authenticator(Authenticator&&) = delete;

private:
};


};