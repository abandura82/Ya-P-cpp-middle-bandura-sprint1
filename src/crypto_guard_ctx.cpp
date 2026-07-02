#include "crypto_guard_ctx.h"
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <string>
#include <vector>

namespace CryptoGuard {

#include <openssl/err.h>
#include <stdio.h>

void print_openssl_errors(const char *context_message) {
    unsigned long err_code;
    char err_buf[256];

    fprintf(stderr, "[ERROR] Context: %s\n", context_message);

    // Цикл работает, пока в очереди есть ошибки
    while ((err_code = ERR_get_error()) != 0) {
        // Получаем текстовое описание ошибки
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));

        // Извлекаем компоненты ошибки для детального анализа
        int lib = ERR_GET_LIB(err_code);
        int reason = ERR_GET_REASON(err_code);

        fprintf(stderr, "  - Code: %lu\n", err_code);
        fprintf(stderr, "    String: %s\n", err_buf);
        fprintf(stderr, "    Library ID: %d\n", lib);
        fprintf(stderr, "    Reason ID: %d\n", reason);
    }
}

struct CryptoContextDeleter {
    void operator()(EVP_CIPHER_CTX *ctx) const {
        if (ctx) {
            // Очищаем конфиденциальные данные из контекста
            EVP_CIPHER_CTX_reset(ctx);
            // Освобождаем память
            EVP_CIPHER_CTX_free(ctx);
            std::println("[Deleter] Контекст успешно очищен и удален.");
        }
    }
};

struct HashContextDeleter {
    void operator()(EVP_MD_CTX *ctx) const {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }
};

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

struct CryptoGuardCtx::Impl {
public:
    // Умный указатель именно на OpenSSL контекст с кастомным делейтером!
    std::unique_ptr<EVP_CIPHER_CTX, CryptoContextDeleter> ssl_ctx_;

    Impl() : ssl_ctx_(EVP_CIPHER_CTX_new(), CryptoContextDeleter()) {
        if (!ssl_ctx_) {
            print_openssl_errors("Не удалось создать EVP_CIPHER_CTX");  // +al 20260619
        }
    }
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        // if (!inStream.good() || !outStream.good()) {
        if (!inStream.good()) {
            std::println("Ошибка входного потока");
            return;
        }
        if (!outStream.good()) {
            std::println("Ошибка выходного потока");
            return;
        }

        try {
            // 2. Генерируем ключ и IV из пароля
            AesCipherParams params = CreateCipherParamsFromPassword(password);
            params.encrypt = 1;
            // 3. Инициализируем наш контекст OpenSSL (ssl_ctx_) свежими параметрами
            // Передаем ssl_ctx_.get(), так как это std::unique_ptr (не нужно ли тут испольовать out_ptr??)
            if (EVP_CipherInit_ex(ssl_ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                                  params.encrypt) != 1) {
                print_openssl_errors("Не удалось инициализировать контекст шифрования OpenSSL");  // +al 20260619
            }
            // 4. Готовим буферы для потокового шифрования
            // Размер буфера чтения кратен размеру блока AES (16 байт)
            constexpr size_t BUFFER_SIZE = 4096;
            std::vector<char> inBuf(BUFFER_SIZE);
            // Буфер записи должен быть чуть больше из-за возможного расширения данных шифром
            std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
            // 5. Основной цикл чтения и шифрования
            while (inStream.read(inBuf.data(), inBuf.size()) || inStream.gcount() > 0) {
                std::streamsize bytesRead = inStream.gcount();
                int outLen = 0;

                // Шифруем прочитанный блок
                if (EVP_CipherUpdate(ssl_ctx_.get(), outBuf.data(), &outLen,
                                     reinterpret_cast<const unsigned char *>(inBuf.data()),
                                     static_cast<int>(bytesRead)) != 1) {
                    print_openssl_errors("Ошибка в процессе шифрования данных (EVP_CipherUpdate)");  // +al 20260619
                }

                // Записываем зашифрованные байты в выходной поток
                if (outLen > 0) {
                    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
                }
                // 6. Финализация шифрования (дозапись остаточных блоков / padding)
                int finalLen = 0;
                if (EVP_CipherFinal_ex(ssl_ctx_.get(), outBuf.data(), &finalLen) != 1) {

                    print_openssl_errors(
                        "Ошибка финализации шифрования (EVP_CipherFinal_ex). Возможно, данные повреждены.");
                }

                if (finalLen > 0) {
                    outStream.write(reinterpret_cast<const char *>(outBuf.data()), finalLen);
                }

                std::println("Шифрование файла успешно завершено.");
            }
        } catch (const std::exception &e) {
            std::println(std::cerr, "Критическая ошибка при шифровании: {}", e.what());
            // Дополнительно сбрасываем контекст при ошибке, чтобы не оставлять мусор
            EVP_CIPHER_CTX_reset(ssl_ctx_.get());
        }
    }  // +al
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            std::println("Ошибка входного потока");
            return;
        }
        if (!outStream.good()) {
            std::println("Ошибка выходного потока");
            return;
        }

        try {
            // 2. Генерируем ключ и IV из пароля
            AesCipherParams params = CreateCipherParamsFromPassword(password);
            params.encrypt = 0;
            // 3. Инициализируем наш контекст OpenSSL (ssl_ctx_) свежими параметрами
            // Передаем ssl_ctx_.get(), так как это std::unique_ptr (не нужно ли тут испольовать out_ptr??)
            if (EVP_CipherInit_ex(ssl_ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                                  params.encrypt) != 1) {
                // throw std::runtime_error("Не удалось инициализировать контекст дешифрования OpenSSL"); // -al
                // 20260619
                print_openssl_errors("Не удалось инициализировать контекст дешифрования OpenSSL");  // +al 20260619
            }
            // 4. Подготавливаем буферы для потокового дешифрования
            // Размер буфера чтения кратен размеру блока AES (16 байт)
            constexpr size_t BUFFER_SIZE = 4096;
            std::vector<char> inBuf(BUFFER_SIZE);
            // Буфер записи должен быть чуть больше из-за возможного расширения данных шифром
            std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
            // 5. Потоковое чтение зашифрованного файла и его дешифрование
            while (inStream.read(inBuf.data(), inBuf.size()) || inStream.gcount() > 0) {
                std::streamsize bytesRead = inStream.gcount();
                int outLen = 0;

                if (EVP_CipherUpdate(ssl_ctx_.get(), outBuf.data(), &outLen,
                                     reinterpret_cast<const unsigned char *>(inBuf.data()),
                                     static_cast<int>(bytesRead)) != 1) {
                    print_openssl_errors("Ошибка в процессе дешифрования данных (EVP_CipherUpdate)");
                }

                if (outLen > 0) {
                    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
                }
            }
            // 6. Финализация дешифрования (проверка PKCS#7 padding)
            int finalLen = 0;
            // Если пароль неверный или файл побился, эта функция вернет 0 (ошибка)
            if (EVP_CipherFinal_ex(ssl_ctx_.get(), outBuf.data(), &finalLen) != 1) {
                print_openssl_errors(
                    "Ошибка финализации дешифрования. Неверный пароль или данные повреждены!");  // +al 20260619
            }

            if (finalLen > 0) {
                outStream.write(reinterpret_cast<const char *>(outBuf.data()), finalLen);
            }
            std::println("Дешифрование файла успешно завершено.");
        } catch (const std::exception &e) {
            std::println(std::cerr, "Критическая ошибка при дешифровании: {}", e.what());
            // Дополнительно сбрасываем контекст при ошибке, чтобы не оставлять мусор
            EVP_CIPHER_CTX_reset(ssl_ctx_.get());
        }
    }  // +al

    std::string CalculateChecksum(std::iostream &inStream) const {
        if (!inStream.good()) {
            std::println(std::cerr, "Ошибка: Входной поток для подсчета хэша невалиден.");
            return "";
        }

        // Умный указатель гарантирует вызов EVP_MD_CTX_free при любом исходе
        std::unique_ptr<EVP_MD_CTX, HashContextDeleter> mdCtx(EVP_MD_CTX_new(), HashContextDeleter());
        if (!mdCtx) {
            print_openssl_errors("Не удалось создать EVP_MD_CTX для SHA-256");  // +al 20260619
        }

        // Инициализируем контекст алгоритмом SHA-256
        if (EVP_DigestInit_ex(mdCtx.get(), EVP_sha256(), nullptr) != 1) {
            print_openssl_errors("Не удалось инициализировать хэш SHA-256");  // +al 20260619
        }

        constexpr size_t BUFFER_SIZE = 4096;
        std::vector<char> buffer(BUFFER_SIZE);

        // Потоковое чтение и обновление хэша
        while (inStream.read(buffer.data(), buffer.size()) || inStream.gcount() > 0) {
            std::streamsize bytesRead = inStream.gcount();

            if (EVP_DigestUpdate(mdCtx.get(), buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                print_openssl_errors("Ошибка при обновлении хэша SHA-256");
            }
        }

        // Финализация и получение бинарного хэша (32 байта для SHA-256)
        std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue;
        unsigned int mdLen = 0;

        if (EVP_DigestFinal_ex(mdCtx.get(), mdValue.data(), &mdLen) != 1) {
            print_openssl_errors("Ошибка финализации хэша SHA-256");  // +al 20260619
        }

        // Преобразуем бинарный хэш в шестнадцатеричную строку (Hex-строку)
        std::string hexResult;
        hexResult.reserve(mdLen * 2);
        for (unsigned int i = 0; i < mdLen; ++i) {
            // Добавляем каждый байт в виде двух символов hex (например, 0a, ff)
            std::string byteHex = std::format("{:02x}", mdValue[i]);
            hexResult += byteHex;
        }

        return hexResult;
    }

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            print_openssl_errors("Не удалось создать ключ из пароля");
        }

        return params;
    }
};

// CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {
CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {
    // как в задании, цитирую: в конструктор и деструктор класса поместите функции инициализации EVP из main.
    std::string input = "01234567890123456789";
    std::string output;
    OpenSSL_add_all_algorithms();

    auto params = impl_->CreateCipherParamsFromPassword("12341234");
    params.encrypt = 1;
    auto *ctx = EVP_CIPHER_CTX_new();

    // Передаем параметры в контекст, хранящийся в impl_

    // Инициализируем cipher
    EVP_CipherInit_ex(impl_->ssl_ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                      params.encrypt);

    std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(16);
    int outLen;
}

// Компилятор генерирует перемещение здесь, так как он уже прочитал всё про Impl сверху
CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

CryptoGuardCtx::~CryptoGuardCtx() = default;  // -al 20260514 убираем дефолтный

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    impl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return impl_->CalculateChecksum(inStream); }

bool CryptoGuardCtx::IsValid() const { return impl_ && impl_->ssl_ctx_; }

}  // namespace CryptoGuard
