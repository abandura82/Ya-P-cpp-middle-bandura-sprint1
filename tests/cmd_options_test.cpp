#include "../include/cmd_options.h"
#include "../include/crypto_guard_ctx.h"
#include <fstream>
#include <gtest/gtest.h>
#include <istream>
// #include <ostream>
#include <vector>

TEST(ProgramOptionsTest, TestParseBig) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./build/CryptoGuard",
                          "--input",
                          "./in/inputTestFile.txt",
                          "--o",
                          "./out/outputTestFile.txt",
                          "--p",
                          "ppp",
                          "--c",
                          "ENCRYPT"};
    int argc = 9;
    bool res = po.Parse(argc, const_cast<char **>(argv));
    EXPECT_TRUE(res);
    EXPECT_TRUE(po.isInputFileOk());
    EXPECT_TRUE(po.isOutputFileOk());
}

TEST(ProgramOptionsTest, TestParseHelp) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./build/CryptoGuard", "--help"};
    int argc = 2;
    bool res = po.Parse(argc, const_cast<char **>(argv));
    EXPECT_TRUE(res);
    EXPECT_EQ(po.IsHelpRequested(), true);
}
TEST(ProgramOptionsTest, TestParseInput) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./build/CryptoGuard", "--input", "./in/inputTestFile.txt"};
    int argc = 3;
    po.Parse(argc, const_cast<char **>(argv));
    EXPECT_TRUE(po.isInputFileOk());
}
TEST(ProgramOptionsTest, TestParseOutput) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./build/CryptoGuard", "--output", "./out/outputTestFile.txt"};
    int argc = 3;
    po.Parse(argc, const_cast<char **>(argv));
    EXPECT_TRUE(po.isOutputFileOk());
}

TEST(ProgramOptionsTest, TestBadCommand) {
    CryptoGuard::ProgramOptions po;
    const char *argv[] = {"./build/CryptoGuard", "--command", "NoSuchCommand"};
    int argc = 3;
    po.Parse(argc, const_cast<char **>(argv));
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::UNKNOWN);
}

TEST(CryptoGuardTest, TestChecksum) {
    CryptoGuard::CryptoGuardCtx cgc;
    const char *argv[] = {"./build/CryptoGuard", "--input", "./in/inputTestFile.txt"};
    int argc = 3;

    std::ifstream inFileStream("./in/inputTestFile.txt");
    // Создаем объект std::iostream и передаем ему буфер открытого файла
    std::iostream inStream(inFileStream.rdbuf());
    std::string s = cgc.CalculateChecksum(inStream);
    EXPECT_EQ(s, "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646");
}

TEST(CryptoGuardTest, TestEmptyFileChecksum) {
    CryptoGuard::CryptoGuardCtx cgc;
    const char *argv[] = {"./build/CryptoGuard", "--input", "./in/emptyInputTestFile.txt"};
    int argc = 3;

    std::ifstream inFileStream("./in/emptyInputTestFile.txt");
    // Создаем объект std::iostream и передаем ему буфер открытого файла
    std::iostream inStream(inFileStream.rdbuf());
    std::string s = cgc.CalculateChecksum(inStream);
    EXPECT_EQ(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardTest, TestEncryptDecrypt) {
    CryptoGuard::ProgramOptions po;
    // шифруем
    const char *argvBefore[] = {"./build/CryptoGuard",
                                "--input",
                                "./in/inputTestFile.txt",
                                "--o",
                                "./out/outputTestFile.txt",
                                "--p",
                                "ppp",
                                "--c",
                                "ENCRYPT"};
    int argc = 9;
    po.Parse(argc, const_cast<char **>(argvBefore));

    std::ifstream inFileStream(po.GetInputFile());
    std::string sBefore;  //, sAfterEncrypt, sBeforeDecrypt;
    if (inFileStream.is_open()) {
        CryptoGuard::CryptoGuardCtx cgcCheckSum;

        std::iostream inStreamCheckSum(inFileStream.rdbuf());
        sBefore = cgcCheckSum.CalculateChecksum(inStreamCheckSum);  // контрольная сумма до
        inFileStream.close();
        inFileStream.open(po.GetInputFile());
        // читаем заново
        std::iostream inStream(inFileStream.rdbuf());
        std::ofstream outFileStream(po.GetOutputFile());
        if (outFileStream.is_open()) {
            // CryptoGuard::CryptoGuardCtx cgc;
            std::iostream outStream(outFileStream.rdbuf());
            // cgc.EncryptFile(inStream, outStream, po.GetPassword());
            cgcCheckSum.EncryptFile(inStream, outStream, po.GetPassword());
            outFileStream.close();
        }
    }
    // дешифруем
    CryptoGuard::ProgramOptions poAfter;
    const char *argvAfter[] = {"./build/CryptoGuard",
                               "--i",
                               "./out/outputTestFile.txt",
                               "--o",
                               "./out/outputTestFile_decr.txt",
                               "--p",
                               "ppp",
                               "--c",
                               "DECRYPT"};
    poAfter.Parse(argc, const_cast<char **>(argvAfter));
    CryptoGuard::CryptoGuardCtx cgcAfter;
    std::ifstream inFileStreamAfter(poAfter.GetInputFile());
    std::string sAfter;
    if (inFileStreamAfter.is_open()) {
        std::iostream inStreamAfter(inFileStreamAfter.rdbuf());
        std::ofstream outFileStreamAfter(poAfter.GetOutputFile());
        if (outFileStreamAfter.is_open()) {
            std::iostream outStreamAfter(outFileStreamAfter.rdbuf());
            cgcAfter.DecryptFile(inStreamAfter, outStreamAfter, poAfter.GetPassword());
            inFileStreamAfter.close();
            outFileStreamAfter.close();
            // дешифровали. теперь считаем контрольную сумму того, что получилось
            inFileStreamAfter.open(poAfter.GetOutputFile());
            std::iostream inStreamAfterCheckSum(inFileStreamAfter.rdbuf());
            sAfter = cgcAfter.CalculateChecksum(inStreamAfterCheckSum);
        }
    }
    EXPECT_EQ(sBefore, sAfter);
}

// Написать Тест для провeрки корректной обработки случая, когда input=output
TEST(ProgramOptionsTest, TestIntputEqOutput) {
    const char *argv[] = {"./build/CryptoGuard",
                          "--input",
                          "./in/inputTestFile.txt",
                          "--o",
                          "./in/inputTestFile.txt",
                          "--p",
                          "ppp",
                          "--c",
                          "ENCRYPT"};
    int argc = 9;
    CryptoGuard::ProgramOptions po;
    EXPECT_EQ(po.Parse(argc, const_cast<char **>(argv)), false);
}

TEST(CryptoGuardTest, TestEncryptSameResult) {
    CryptoGuard::ProgramOptions po;
    // шифруем
    const char *argvBefore[] = {"./build/CryptoGuard",
                                "--input",
                                "./in/inputTestFile.txt",
                                "--o",
                                "./out/outputTestFile.txt",
                                "--p",
                                "ppp",
                                "--c",
                                "ENCRYPT"};
    int argc = 9;
    po.Parse(argc, const_cast<char **>(argvBefore));
    std::vector<std::string> results;
    for (int i = 0; i < 10; ++i) {
        std::ifstream inFileStream(po.GetInputFile());
        if (inFileStream.is_open()) {
            CryptoGuard::CryptoGuardCtx cgc;
            std::iostream inStreamCheckSum(inFileStream.rdbuf());
            // читаем заново
            std::iostream inStream(inFileStream.rdbuf());
            std::ofstream outFileStream(po.GetOutputFile());
            if (outFileStream.is_open()) {
                // CryptoGuard::CryptoGuardCtx cgc;
                std::iostream outStream(outFileStream.rdbuf());
                cgc.EncryptFile(inStream, outStream, po.GetPassword());
                inFileStream.close();
                outFileStream.close();
            }
            // дешифровали. теперь считаем контрольную сумму того, что получилось
            inFileStream.open(po.GetOutputFile());
            std::iostream inStreamAfterCheckSum(inFileStream.rdbuf());
            results.push_back(cgc.CalculateChecksum(inStreamAfterCheckSum));
            std::println("Checksum: {} on iteration {} ", results[i], i);
            inFileStream.close();
        }
    }
    // Переменная, в которую запишется результат
    bool isEqual = true;

    if (!results.empty()) {
        const std::string &first = results.front();

        // Результат проверки записывается напрямую в переменную
        isEqual =
            std::all_of(results.begin() + 1, results.end(), [&first](const std::string &str) { return str == first; });
    } else {
        isEqual = true;
    };
    EXPECT_EQ(isEqual, true);
}
