#include "statics.h"
#include "global_defines.h"


namespace puf {

const unsigned char PS[] = "puf-acs-esp";


PUFStatics::PUFStatics() {
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, ELLIPTIC_CURVE);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, PS, sizeof(PS));
    initialised = true;
}


PUFStatics::~PUFStatics() {
    mbedtls_ecp_group_free(&group);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}


PUFStatics& PUFStatics::instance() {
    static PUFStatics inst;
    return inst;
}


mbedtls_ecp_group& PUFStatics::ecp_group() {
    return group;
}


mbedtls_ctr_drbg_context& PUFStatics::ctr_drbg_context() {
    return ctr_drbg;
}

};  // namespace puf