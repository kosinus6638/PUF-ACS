#pragma once

/* MAC address of the switch */
#define SWITCH_MAC                  {0x04, 0x92, 0x26, 0x87, 0x84, 0x11}

/* Ethernet types */
#define ETHER_TYPE_PUF_ACS          0xbeef
#define ETHER_TYPE_EXPERIMENTAL     0x88b5
#define ETHER_TYPE_Q                0x9100
#define ETHER_TYPE_AD               0x98a8

/* Length of ethernet payload frame */
#define ETHER_FRAME_LEN             1522

/* Elliptic rcCurve */
#define ELLIPTIC_CURVE              MBEDTLS_ECP_DP_SECP256R1

/* Timeout for network operations in ms */
#define NETWORK_TIMEOUT_MS          3000

/* To be defined during build by cmake */
#define DEFAULT_RESOURCE    "Supplicant.csv"
#define DEFAULT_COUNTER     100