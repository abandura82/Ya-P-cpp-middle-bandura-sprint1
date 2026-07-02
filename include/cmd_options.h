#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM, UNKNOWN };

    bool Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }
    bool IsHelpRequested() const { return helpRequested_; }  // +al

    void ShowOptions();
    bool isInputFileOk() { return inputFileOk_; }
    bool isOutputFileOk() { return outputFileOk_; }

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::string inputFile_{"./in/inputFileDefault.txt"};     // +al добавил дефолт
    std::string outputFile_{"./out/outputFileDefault.txt"};  // +al добавил дефолт
    std::string password_{"12345678"};
    bool helpRequested_{false};  // +al
    bool inputFileOk_{false};    // +al
    bool isInputFileValid();     // +al
    bool outputFileOk_{false};   // +al
    bool isOutputFileValid();    // +al

    boost::program_options::options_description desc_;
    boost::program_options::variables_map vm;  // +al
};

}  // namespace CryptoGuard
