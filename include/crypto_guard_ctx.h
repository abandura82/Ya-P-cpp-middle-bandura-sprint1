#pragma once

#include <experimental/propagate_const>
#include <memory>
#include <openssl/evp.h>
#include <print>
// #include <string>

namespace CryptoGuard {

struct CryptoContextDeleter;

class CryptoGuardCtx {
public:
    CryptoGuardCtx();   // {} -al
    ~CryptoGuardCtx();  // {} -al

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);  //{} // -al
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);  //{} // -al
    [[nodiscard]] std::string CalculateChecksum(std::iostream &inStream);
    bool IsValid() const;

private:
    struct Impl;
    // Impl *pImpl_;
    // std::experimental::propagate_const<std::unique_ptr<Impl/*, CryptoContextDeleter*/>> impl_;
    std::unique_ptr<Impl> impl_;
};

}  // namespace CryptoGuard
