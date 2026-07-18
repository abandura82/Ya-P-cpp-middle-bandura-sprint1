#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <boost/type_traits/integral_constant.hpp>
#include <filesystem>
#include <fstream>  // Библиотека для работы с файлами
#include <ios>
#include <iostream>
#include <print>
#include <ranges>

namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help", "показать это сообщение")("command", po::value<std::string>(),
                                                          "задать команду: ENCRYPT|DECRYPT|CHECKSUM")(
        "input", po::value<std::string>(), "исходный файл")("output", po::value<std::string>(), "результирующий файл")(
        "password", po::value<std::string>(), "пароль для шифрования");  //+al
}

ProgramOptions::~ProgramOptions() = default;

// void ProgramOptions::Parse(int argc, char *argv[]) {      // -al 20260511 0006
bool ProgramOptions::Parse(int argc, char *argv[]) {  // +al 20260511 0006
    //+al
    std::stringstream ss;  // +al для отладки

    try {
        // отладка
        auto args = std::views::counted(argv, argc);
        std::string s;
        for (auto arg : args) {
            s += std::string(arg) + " ";
        }
        std::println("argc: {}, argv: [{}]", argc, s);

        try {
            po::store(po::parse_command_line(argc, argv, desc_), vm);
        } catch (const po::error &e) {
            std::println("Boost PO Error: {}", e.what());
        }

        po::notify(vm);

        if (vm.count("help") || vm.count("h")) {
            ss << desc_;
            println("{}", ss.str());
            helpRequested_ = true;
            return true;
        }
        //+al 20260510
        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
        }
        std::println("inputFile: {}", inputFile_);  // потом убрать
        if (!isInputFileValid()) {
            std::println("Ошибка: исходный файл: {} не существует или не может быть открыт", inputFile_);
            return false;  // если не смогли открыть существующий или создать файл новый файл
        } else {
            inputFileOk_ = true;
        }

        //+al 20260510
        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
            if (!isOutputFileValid()) {
                std::println("Ошибка: результирующий файл: {} не может быть записан", outputFile_);
                return false;
            }
            outputFileOk_ = true;
        }
        std::println("outputFile: {}", outputFile_);

        // +al 20260717
        if (vm.count("output")) {
            namespace fs = std::filesystem;
            if (fs::equivalent(inputFile_, outputFile_)) {
                std::println("Ошибка: исходный файл: {} совпадает с результирующим: {}", inputFile_, outputFile_);
                return false;
            } else if (inputFile_ == outputFile_) {
                std::println("Пути совпадают");
                return false;
            }
        }

        //+al 20260510
        if (vm.count("password")) {
            password_ = vm["password"].as<std::string>();
        }
        std::println("password: {}", password_);

        if (vm.count("command")) {
            std::string cmd = vm["command"].as<std::string>();
            std::println("cmd: {}", cmd);
            if (cmd == "ENCRYPT") {
                command_ = COMMAND_TYPE::ENCRYPT;

            } else if (cmd == "DECRYPT") {
                command_ = COMMAND_TYPE::DECRYPT;

            } else if (cmd == "CHECKSUM") {
                command_ = COMMAND_TYPE::CHECKSUM;

            } else {
                command_ = COMMAND_TYPE::UNKNOWN;
            }
        }

        // Валидация: проверим, что файл указан, если это не help
        if (!vm.count("input") && !helpRequested_) {
            throw std::runtime_error("Ошибка: Входной файл обязателен к указанию (--input).");
            return false;
        }
        return true;
    } catch (const std::exception &e) {
        // std::cerr << e.what() << std::endl;
        ss << e.what();
        println("{}", ss.str());
        // std::cout << desc << std::endl;
        // ss << desc_;
        // println("{}", ss.str());
        // exit(1);
        return false;
    }
}

void ProgramOptions::ShowOptions() {
    std::stringstream ss;
    ss << desc_;
    println(ss);
}

bool ProgramOptions::isInputFileValid() {
    // Создание файла
    bool res = false;
    std::ifstream MyFile(inputFile_);
    if (MyFile.good()) {
        return true;
    } else {
        std::ofstream MyFileToCreate(inputFile_);
        if (!MyFileToCreate) {  // Проверка: удалось ли открыть/создать файл
            std::println("Системная ошибка: {} (код {})", std::strerror(errno), errno);
            std::println("Абсолютный путь: {}", std::filesystem::absolute(inputFile_).string());
            return false;
        }
        MyFileToCreate << "1234567890";
        return true;
    }
}

bool ProgramOptions::isOutputFileValid() {
    std::ofstream MyFileToCreate(outputFile_, std::ios::trunc);
    if (!MyFileToCreate) {  // Проверка: удалось ли открыть/создать файл
        std::println("Системная ошибка: {} (код {})", std::strerror(errno), errno);
        std::println("Абсолютный путь: {}", std::filesystem::absolute(outputFile_).string());
        return false;
    }
    return true;
}

}  // namespace CryptoGuard
