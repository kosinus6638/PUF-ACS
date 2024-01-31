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


};