#include "../include/cmd_options.h"
#include "../include/crypto_guard_ctx.h"
#include <fstream>
#include <gtest/gtest.h>

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

TEST(ProgramOptionsTest, TestChecksum) {
    CryptoGuard::CryptoGuardCtx cgc;
    const char *argv[] = {"./build/CryptoGuard", "--input", "./in/inputTestFile.txt"};
    int argc = 3;

    std::ifstream inFileStream("./in/inputTestFile.txt");
    // Создаем объект std::iostream и передаем ему буфер открытого файла
    std::iostream inStream(inFileStream.rdbuf());
    std::string s = cgc.CalculateChecksum(inStream);
    EXPECT_EQ(s, "c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646");
}

TEST(ProgramOptionsTest, TestEmptyFileChecksum) {
    CryptoGuard::CryptoGuardCtx cgc;
    const char *argv[] = {"./build/CryptoGuard", "--input", "./in/emptyInputTestFile.txt"};
    int argc = 3;

    std::ifstream inFileStream("./in/emptyInputTestFile.txt");
    // Создаем объект std::iostream и передаем ему буфер открытого файла
    std::iostream inStream(inFileStream.rdbuf());
    std::string s = cgc.CalculateChecksum(inStream);
    EXPECT_EQ(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
