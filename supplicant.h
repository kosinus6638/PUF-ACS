#pragma once

#include "math.h"
#include "platform.h"


namespace puf {

class Supplicant {
private:

    enum SupplicantState {
        UNINITIALISED = 0,
        INITIALISED,
        HANGING,
        VALIDATING,
        CONNECTED
    };

    SupplicantState state;

    int ctr;
    Network &net;
    PUF &sram_puf;
    ECP_Point G;

    int wait_for_AU_ok();


    // Three phases
    int PUF_CON_phase();
    int PUF_SYN_phase();
    int PUF_ACK_phase();


public:
    Supplicant() = delete;
    Supplicant(Supplicant&) = delete;
    Supplicant(Supplicant&&) = delete;

    /**
     * Constructor
     * @param Network Realization of Network Interface @see Network
     * @param PUF Realization of PUF Interface @see PUF
    */
    Supplicant(Network&, PUF&);

    PUF_SYN puf_syn;
    MAC mac;
    MPI t, k;

    /**
     * Initialises the supplicant by extracting the PUF and initialising the network.
     * Recalculates MAC address each time when called.
    */
    void init();

    /**
     * Connect to the Authenticator by performing the three way handshake
     * @param attempts The number of attempts used to connect. Defaults to 1.
    */
    void connect(int attempts = 1);

    /**
     * Returns true if connected, false otherwise
    */
    bool connected();

    /**
     * Registers itself to the Authenticator by sending the base MAC and the public key A.
     * Should be done before using this class, this is a bodge.
    */
    void sign_up();     // Thanks C++ for making register a keyword
};


};  // Namespace puf