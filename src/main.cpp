#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include "openssl/crypto.h"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <istream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        // options.Parse(argc, argv); // -al 20270717
        //  +al 20260717
        if (!options.Parse(argc, argv)) {
            std::println("Неверно заданы исходные данные");
            return 2;
        };

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::ifstream inFileStream(options.GetInputFile());
        if (inFileStream.is_open()) {
            std::iostream inStream(inFileStream.rdbuf());

            switch (options.GetCommand()) {
            case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT: {
                // шифруем файл
                std::ofstream outFileStream(options.GetOutputFile());
                if (outFileStream.is_open()) {
                    std::iostream outStream(outFileStream.rdbuf());
                    cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
                    outFileStream.close();
                }
                break;
            }
            case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT: {
                // дешифруем файл
                std::ofstream outFileStream(options.GetOutputFile());
                if (outFileStream.is_open()) {
                    std::iostream outStream(outFileStream.rdbuf());
                    cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
                    outFileStream.close();
                }
                break;
            }
            case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM: {
                std::string s = cryptoCtx.CalculateChecksum(inStream);
                std::println("Контрольная сумма: {}", s);
                break;
            }
            default:
                std::println("Неизвестная команда!");
                break;
            }
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}