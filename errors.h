#pragma once

#include <string.h>             // strncpy
#include <mbedtls/error.h>      // mbedtls_strerror

namespace puf {

class Exception {
protected:
    char err_msg_buffer[128];
public:
    Exception() {
        err_msg_buffer[0] = 0;
    }

    Exception(const char* err_msg) {
        strncpy(err_msg_buffer, err_msg, sizeof(err_msg_buffer));
    }

    Exception(int err_code) {
        mbedtls_strerror(err_code, err_msg_buffer, sizeof(err_msg_buffer)-1);
    }

    const char* what() const {
        return err_msg_buffer;
    }
};


class MathException : public Exception {
    using Exception::Exception;
};


class PacketException : public Exception {
    using Exception::Exception;
};


class NetworkException : public Exception {
    using Exception::Exception;
};


class PUFException : public Exception {
    using Exception::Exception;
};

};  // namespace puf