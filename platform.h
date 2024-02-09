#pragma once

#include "packets.h"

namespace puf {

class Network {
public:

    /**
     * Initializes the Network. 
    */
    virtual void init() = 0;

    /**
     * Attempts to send bufSize bytes of buf via network
     * @param buf The buffer to be sent
     * @param bufSize The number of bytes to be sent
    */
    virtual void send(uint8_t *buf, size_t bufSize) = 0;

    /**
     * Attempts to receive a message via the network
     * @param buf The buffer which the message is written into
     * @param bufSize The maximum amount of bytes to be written
     * @return The number of bytes written
    */
    virtual int receive(uint8_t *buf, size_t bufSize) = 0;
};


class PUF {
public:

    /**
     * Extracts MAC using the PUF
     * @return The resulting MAC address
    */
    virtual MAC puf_to_mac() const = 0;

    /**
     * Challenges the PUF and returns the PUF response
     * @param puf_challenge The bytes the PUF is challenged with
     * @return The PUF response
    */
    virtual MAC get_puf_response(const puf::MAC& puf_challenge) const = 0;
};


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

};