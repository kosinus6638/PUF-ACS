#include "math.h"

#include <mbedtls/platform.h>   // mbedtls_snprintf
#include <mbedtls/base64.h>

#include "errors.h"
#include "statics.h"

namespace puf {

void MPI::init() {
    mbedtls_mpi_init(this);
}

MPI::MPI() {
    init();
}

MPI::MPI(const uint8_t* buf, size_t len) {
    init();
    from_binary(buf, len);
}

MPI::MPI(const MPI& rhs) {
    int err;
    init();

    if( (err = mbedtls_mpi_copy(this, &rhs)) != 0) {
        throw MathException(err);
    }
}

MPI::MPI(MPI &&rhs) {
    init();
    mbedtls_mpi_swap(this, &rhs);
}

MPI::MPI(const mbedtls_mpi &rhs) {
    init();
    mbedtls_mpi_copy(this, &rhs);
}

MPI::MPI(mbedtls_mpi_sint rhs) {
    int err;
    init();

    if( (err = mbedtls_mpi_lset(this, rhs)) != 0) {
        throw MathException(err);
    }
}

MPI& MPI::operator=(const MPI &rhs) {
    int err;

    if( (err = mbedtls_mpi_copy(this, &rhs)) != 0) {
        throw MathException(err);
    }

    return *this;
}

MPI& MPI::operator=(MPI &&rhs) {
    mbedtls_mpi_swap(this, &rhs);
    return *this;
}

MPI MPI::operator+(const MPI &rhs) const {
    MPI result = *this;
    result += rhs;
    return result;
}

MPI& MPI::operator+=(const MPI &rhs) {
    int err;

    if( (err = mbedtls_mpi_add_mpi(this, &rhs, this)) != 0) {
        throw MathException(err);
    }

    return *this;
}

MPI MPI::operator*(const MPI &rhs) const {
    MPI result = *this;
    result *= rhs;
    return result;
}

MPI& MPI::operator*=(const MPI &rhs) {
    int err;

    if( (err = mbedtls_mpi_mul_mpi(this, &rhs, this)) != 0) {
        throw MathException(err);
    }

    return *this;
}

MPI::~MPI() {
    mbedtls_mpi_free(this);
#if MBEDTLS_VERSION_MAJOR >= 3
#endif
}

void MPI::from_binary(const uint8_t* buf, size_t len) {
    int err;

    if( (err = mbedtls_mpi_read_binary_le(this, buf, len)) != 0) {
        throw MathException(err);
    }
}

void MPI::print_limbs() const {
    print_mpi(this);
}

uint32_t MPI::binary32() const {
    uint8_t buf[4];
    mbedtls_mpi_write_binary_le(this, buf, sizeof(buf));
    return *reinterpret_cast<uint32_t*>(&buf);
}


void print_mpi(const mbedtls_mpi* p) {
    char str[512];
    size_t bitlen;
    size_t idx = 0;
    
    bitlen = mbedtls_mpi_bitlen(p);
    
    if( bitlen == 0 )
    {
        str[0] = ' '; str[1] = '0'; str[2] = '0';
        idx = 3;
    }
    else
    {
        int n;
        for( n = (int) ( ( bitlen - 1 ) / 8 ); n >= 0; n-- )
        {
            size_t limb_offset = n / sizeof( mbedtls_mpi_uint );
            size_t offset_in_limb = n % sizeof( mbedtls_mpi_uint );
            unsigned char octet =
#if MBEDTLS_VERSION_MAJOR >= 3
            ( p->private_p[limb_offset] >> ( offset_in_limb * 8 ) ) & 0xff;
#else
            ( p->p[limb_offset] >> ( offset_in_limb * 8 ) ) & 0xff;
#endif
            mbedtls_snprintf( str + idx, sizeof( str ) - idx, "%02x", octet );
            idx += 2;
            /* Wrap lines after 16 octets that each take 3 columns */
            if( idx >= 2 * 16 )
            {
                // mbedtls_snprintf( str + idx, sizeof( str ) - idx, "\n" );
                idx = 0;
            }
        }
    }
    
    if( idx != 0 ) {
        mbedtls_snprintf( str + idx, sizeof( str ) - idx, "\n" );
    }

    printf("%s",str);
}


void ECP_Point::init() {
    memset(buf, '\0', 65);
    memset(b64_buf, '\0', BASE64_LEN(65));
    olen = 0;
    b64_olen = 0;
    mbedtls_ecp_point_init(this);
}


ECP_Point::ECP_Point() : group(PUFStatics::instance().ecp_group()) {
    init();
}


ECP_Point::ECP_Point(const ECP_Point &rhs) : group(PUFStatics::instance().ecp_group()) {
    init();
    *this = rhs;
}


ECP_Point::ECP_Point(const mbedtls_ecp_point& p) : group(PUFStatics::instance().ecp_group()) {
    int err;
    init();
#if MBEDTLS_VERSION_MAJOR >= 3
    if( (err = mbedtls_mpi_copy(&this->private_X, &p.private_X)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->private_Y, &p.private_Y)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->private_Z, &p.private_Z)) != 0) {
        throw MathException(err);
    }
#else
    if( (err = mbedtls_mpi_copy(&this->X, &p.X)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->Y, &p.Y)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->Z, &p.Z)) != 0) {
        throw MathException(err);
    }
#endif
    update();
}


ECP_Point::~ECP_Point() {
    mbedtls_ecp_point_free(this);
}

ECP_Point& ECP_Point::operator=(const ECP_Point &rhs) {
    int err;

#if MBEDTLS_VERSION_MAJOR >= 3
    if( (err = mbedtls_mpi_copy(&this->private_X, &rhs.private_X)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->private_Y, &rhs.private_Y)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->private_Z, &rhs.private_Z)) != 0) {
        throw MathException(err);
    }
#else
    if( (err = mbedtls_mpi_copy(&this->X, &rhs.X)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->Y, &rhs.Y)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_mpi_copy(&this->Z, &rhs.Z)) != 0) {
        throw MathException(err);
    }
#endif

    memcpy(buf, rhs.buf, rhs.olen);
    memcpy(b64_buf, rhs.b64_buf, rhs.b64_olen);
    olen = rhs.olen;
    b64_olen = rhs.b64_olen;
    return *this;
}

ECP_Point ECP_Point::operator*(const MPI &rhs) const {
    ECP_Point result = *this;
    result *= rhs;
    return result;
}

ECP_Point& ECP_Point::operator*=(const MPI &rhs) {
    int err;
    if( (err = mbedtls_ecp_mul(&group, this, &rhs, this, mbedtls_ctr_drbg_random, 
        &PUFStatics::instance().ctr_drbg_context())) != 0) {
        throw MathException(err);
    }

    update();
    return *this;
}

ECP_Point ECP_Point::operator+(const ECP_Point &rhs) const {
    ECP_Point result = *this;
    result += rhs;
    return result;
}

ECP_Point& ECP_Point::operator+=(const ECP_Point &rhs) {
    int err;
    const MPI one(1);

    if( (err = mbedtls_ecp_muladd(&group, this, &one, this, &one, &rhs)) != 0) {
        throw MathException(err);
    }

    update();
    return *this;
}

bool ECP_Point::operator==(const ECP_Point &rhs) {
    return (mbedtls_ecp_point_cmp(this, &rhs) == 0);
}

size_t ECP_Point::len() const {
    return olen;
}

size_t ECP_Point::len64() const {
    return b64_olen;
}

int ECP_Point::from_base64(const uint8_t* b64_buf_) {
    int err;

    b64_olen = strlen( (char*)(b64_buf_) );
    memcpy(b64_buf, b64_buf_, b64_olen);

    if( (err = mbedtls_base64_decode(buf, 65, &olen, b64_buf, b64_olen)) != 0) {
        buf[0] = 0;
        b64_buf[0] = 0;
        throw MathException(err);
    }

    if( (err = mbedtls_ecp_point_read_binary(&group, this, buf, olen)) != 0) {
        buf[0] = 0;
        b64_buf[0] = 0;
        throw MathException(err);
    }
    return 0;
}

int ECP_Point::from_binary(const uint8_t* buf_, size_t buflen) {
    int err;
    if( (err = mbedtls_ecp_point_read_binary(&group, this, buf_, buflen)) != 0) {
        buf[0] = 0;
        b64_buf[0] = 0;
        throw MathException(err);
    }
    update();
    return 0;
}

const uint8_t* ECP_Point::base64() const {
    return b64_buf;
}

const uint8_t* ECP_Point::binary() const {
    return buf;
}

void ECP_Point::print() const {
#if MBEDTLS_VERSION_MAJOR >= 3
    printf("X: ");
    print_mpi(&this->private_X);
    printf("\tY: ");
    print_mpi(&this->private_Y);
    printf("\tZ: ");
    print_mpi(&this->private_Z);
#else
    printf("X: ");
    print_mpi(&this->X);
    printf("\tY: ");
    print_mpi(&this->Y);
    printf("\tZ: ");
    print_mpi(&this->Z);
#endif
}

void ECP_Point::print64() const {
    for(size_t i=0; i<b64_olen; ++i) {
        printf("%c", static_cast<char>(b64_buf[i]) );
    }
    printf("\n");
}

void ECP_Point::update() {
    int err;
    if( (err = mbedtls_ecp_point_write_binary(&group, this, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, 65)) != 0) {
        throw MathException(err);
    }

    if( (err = mbedtls_base64_encode(b64_buf, BASE64_LEN(64), &b64_olen, buf, olen)) != 0) {
        throw MathException(err);
    }
}

};  // namespace puf