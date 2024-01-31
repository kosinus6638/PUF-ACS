#pragma once

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>

#include "math.h"

namespace puf {

class PUFStatics {
private:
    bool initialised;
    mbedtls_ecp_group group;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    PUFStatics();
    PUFStatics(const PUFStatics&) = delete;
    PUFStatics& operator=(const PUFStatics&) = delete;
    ~PUFStatics();

public:

    static PUFStatics& instance();

    mbedtls_ecp_group& ecp_group();
    mbedtls_ctr_drbg_context& ctr_drbg_context();
};

};  // namespace puf