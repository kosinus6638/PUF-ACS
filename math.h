#pragma once

#include <mbedtls/ecp.h>

#define BASE64_LEN(n) (((((n) + 2) / 3) << 2)+1)

namespace puf {

class MPI : public mbedtls_mpi {
private:
    void init();
public:
    MPI();
    MPI(const MPI& rhs);
    MPI(MPI&& rhs);
    MPI(const mbedtls_mpi &rhs);
    MPI(mbedtls_mpi_sint rhs);
    MPI(const uint8_t* buf, size_t len);
    ~MPI();

    void print_limbs() const;
    void from_binary(const uint8_t* buf, size_t len);
    uint32_t binary32() const;

    MPI& operator=(const MPI &rhs);
    MPI& operator=(MPI &&rhs);
    MPI operator+(const MPI &rhs) const;
    MPI& operator+=(const MPI &rhs);
    MPI operator*(const MPI &rhs) const;
    MPI& operator*=(const MPI &rhs);
};


void print_mpi(const mbedtls_mpi*);


class ECP_Point : public mbedtls_ecp_point {
private:
    void init();
    void update();

    uint8_t buf[65];
    uint8_t b64_buf[ BASE64_LEN(65) ];
    size_t olen;
    size_t b64_olen;
    mbedtls_ecp_group& group;

public:
    ECP_Point();
    ECP_Point(const mbedtls_ecp_point&);
    ECP_Point(const ECP_Point &rhs);
    ~ECP_Point();

    size_t len64() const;
    size_t len() const;
    int from_base64(const uint8_t* b64_buf_);
    int from_binary(const uint8_t*, size_t);
    const uint8_t* base64() const;
    const uint8_t* binary() const;

    void print() const;
    void print64() const;

    ECP_Point& operator=(const ECP_Point &rhs);
    ECP_Point operator*(const MPI &rhs) const;
    ECP_Point& operator*=(const MPI &rhs);
    ECP_Point operator+(const ECP_Point &rhs) const;
    ECP_Point& operator+=(const ECP_Point &rhs);
    bool operator==(const ECP_Point &rhs);
};

};  // Namespace puf