
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace fs = std::filesystem;

constexpr unsigned short PORT = 5000;
constexpr size_t BUFFER_SIZE = 64 * 1024;
constexpr uint32_t MAX_PACKET_SIZE = 1024 * 1024;
constexpr ULONG PBKDF2_ITERATIONS = 200000;

constexpr size_t KEY_SIZE = 32;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t SALT_SIZE = 16;

constexpr char PACKET_AUTH = 0;
constexpr char PACKET_AUTH_OK = 1;
constexpr char PACKET_FILE = 2;
constexpr char PACKET_DATA = 3;
constexpr char PACKET_QUIT = 4;
constexpr char PACKET_FOLDER_START = 5;
constexpr char PACKET_DIRECTORY = 6;
constexpr char PACKET_FOLDER_FILE = 7;
constexpr char PACKET_FOLDER_END = 8;

SOCKET connection = INVALID_SOCKET;
std::atomic<bool> running{ true };
std::mutex sendMutex;

struct CryptoContext
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    std::vector<unsigned char> keyObject;

    bool initialize(const std::string& password,
                    const unsigned char* salt)
    {
        if (BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0) != 0)
        {
            return false;
        }

        if (BCryptSetProperty(
            algorithm,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(
                const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0) != 0)
        {
            return false;
        }

        BCRYPT_ALG_HANDLE hashAlgorithm = nullptr;

        if (BCryptOpenAlgorithmProvider(
            &hashAlgorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        {
            return false;
        }

        std::vector<unsigned char> derivedKey(KEY_SIZE);

        NTSTATUS status = BCryptDeriveKeyPBKDF2(
            hashAlgorithm,
            reinterpret_cast<PUCHAR>(
                const_cast<char*>(password.data())),
            static_cast<ULONG>(password.size()),
            const_cast<PUCHAR>(salt),
            SALT_SIZE,
            PBKDF2_ITERATIONS,
            derivedKey.data(),
            KEY_SIZE,
            0);

        BCryptCloseAlgorithmProvider(hashAlgorithm, 0);

        if (status != 0)
            return false;

        DWORD objectSize = 0;
        DWORD resultSize = 0;

        if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize),
            &resultSize,
            0) != 0)
        {
            return false;
        }

        keyObject.resize(objectSize);

        status = BCryptGenerateSymmetricKey(
            algorithm,
            &key,
            keyObject.data(),
            objectSize,
            derivedKey.data(),
            KEY_SIZE,
            0);

        SecureZeroMemory(derivedKey.data(), derivedKey.size());

        return status == 0;
    }

    bool encrypt(
        const std::vector<unsigned char>& input,
        std::vector<unsigned char>& output,
        unsigned char* nonce,
        unsigned char* tag)
    {
        if (!key)
            return false;

        if (BCryptGenRandom(
            nullptr,
            nonce,
            NONCE_SIZE,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            return false;
        }

        output.resize(input.size());

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);

        auth.pbNonce = nonce;
        auth.cbNonce = NONCE_SIZE;
        auth.pbTag = tag;
        auth.cbTag = TAG_SIZE;

        ULONG result = 0;

        NTSTATUS status = BCryptEncrypt(
            key,
            const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()),
            &auth,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &result,
            0);

        output.resize(result);

        return status == 0;
    }

    bool decrypt(
        const std::vector<unsigned char>& input,
        std::vector<unsigned char>& output,
        unsigned char* nonce,
        unsigned char* tag)
    {
        if (!key)
            return false;

        output.resize(input.size());

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);

        auth.pbNonce = nonce;
        auth.cbNonce = NONCE_SIZE;
        auth.pbTag = tag;
        auth.cbTag = TAG_SIZE;

        ULONG result = 0;

        NTSTATUS status = BCryptDecrypt(
            key,
            const_cast<PUCHAR>(input.data()),
            static_cast<ULONG>(input.size()),
            &auth,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &result,
            0);

        if (status != 0)
        {
            output.clear();
            return false;
        }

        output.resize(result);
        return true;
    }

    void cleanup()
    {
        if (key)
        {
            BCryptDestroyKey(key);
            key = nullptr;
        }

        if (algorithm)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            algorithm = nullptr;
        }

        if (!keyObject.empty())
            SecureZeroMemory(keyObject.data(), keyObject.size());

        keyObject.clear();
    }

    ~CryptoContext()
    {
        cleanup();
    }
};

CryptoContext crypto;

bool sendAll(SOCKET socket, const char* data, size_t size)
{
    while (size > 0)
    {
        int amount = static_cast<int>(
            std::min(size, static_cast<size_t>(INT_MAX)));

        int sent = send(socket, data, amount, 0);

        if (sent <= 0)
            return false;

        data += sent;
        size -= static_cast<size_t>(sent);
    }

    return true;
}

bool recvAll(SOCKET socket, char* data, size_t size)
{
    while (size > 0)
    {
        int amount = static_cast<int>(
            std::min(size, static_cast<size_t>(INT_MAX)));

        int received = recv(socket, data, amount, 0);

        if (received <= 0)
            return false;

        data += received;
        size -= static_cast<size_t>(received);
    }

    return true;
}

void appendU32(std::vector<unsigned char>& data, uint32_t value)
{
    for (int i = 3; i >= 0; --i)
        data.push_back(static_cast<unsigned char>(value >> (i * 8)));
}

void appendU64(std::vector<unsigned char>& data, uint64_t value)
{
    for (int i = 7; i >= 0; --i)
        data.push_back(static_cast<unsigned char>(value >> (i * 8)));
}

bool readU32(const std::vector<unsigned char>& data,
             size_t& offset,
             uint32_t& value)
{
    if (offset + 4 > data.size())
        return false;

    value = 0;

    for (int i = 0; i < 4; ++i)
        value = (value << 8) | data[offset++];

    return true;
}

bool readU64(const std::vector<unsigned char>& data,
             size_t& offset,
             uint64_t& value)
{
    if (offset + 8 > data.size())
        return false;

    value = 0;

    for (int i = 0; i < 8; ++i)
        value = (value << 8) | data[offset++];

    return true;
}

void appendString(
    std::vector<unsigned char>& data,
    const std::string& value)
{
    appendU32(data, static_cast<uint32_t>(value.size()));
    data.insert(data.end(), value.begin(), value.end());
}

bool readString(
    const std::vector<unsigned char>& data,
    size_t& offset,
    std::string& value)
{
    uint32_t length = 0;

    if (!readU32(data, offset, length) ||
        length == 0 ||
        length > 32768 ||
        offset + length > data.size())
    {
        return false;
    }

    value.assign(
        data.begin() + offset,
        data.begin() + offset + length);

    offset += length;
    return true;
}

bool sendPacketUnlocked(
    char type,
    const std::vector<unsigned char>& payload = {})
{
    std::vector<unsigned char> plain;
    plain.reserve(payload.size() + 1);

    plain.push_back(static_cast<unsigned char>(type));
    plain.insert(plain.end(), payload.begin(), payload.end());

    std::vector<unsigned char> encrypted;

    unsigned char nonce[NONCE_SIZE]{};
    unsigned char tag[TAG_SIZE]{};

    if (!crypto.encrypt(plain, encrypted, nonce, tag))
        return false;

    if (encrypted.size() > MAX_PACKET_SIZE)
        return false;

    uint32_t length = static_cast<uint32_t>(encrypted.size());

    std::vector<unsigned char> header;

    header.insert(header.end(), nonce, nonce + NONCE_SIZE);
    header.insert(header.end(), tag, tag + TAG_SIZE);
    appendU32(header, length);

    return sendAll(
        connection,
        reinterpret_cast<const char*>(header.data()),
        header.size()) &&
        sendAll(
            connection,
            reinterpret_cast<const char*>(encrypted.data()),
            encrypted.size());
}

bool sendPacket(
    char type,
    const std::vector<unsigned char>& payload = {})
{
    std::lock_guard<std::mutex> lock(sendMutex);
    return sendPacketUnlocked(type, payload);
}

bool receivePacket(
    char& type,
    std::vector<unsigned char>& payload)
{
    unsigned char header[NONCE_SIZE + TAG_SIZE + 4];

    if (!recvAll(
        connection,
        reinterpret_cast<char*>(header),
        sizeof(header)))
    {
        return false;
    }

    unsigned char* nonce = header;
    unsigned char* tag = header + NONCE_SIZE;

    std::vector<unsigned char> headerData(
        header + NONCE_SIZE + TAG_SIZE,
        header + sizeof(header));

    size_t offset = 0;
    uint32_t length = 0;

    if (!readU32(headerData, offset, length) ||
        length == 0 ||
        length > MAX_PACKET_SIZE)
    {
        return false;
    }

    std::vector<unsigned char> encrypted(length);

    if (!recvAll(
        connection,
        reinterpret_cast<char*>(encrypted.data()),
        encrypted.size()))
    {
        return false;
    }

    std::vector<unsigned char> plain;

    if (!crypto.decrypt(encrypted, plain, nonce, tag) ||
        plain.empty())
    {
        std::cout << "\n[ERROR] Authentication failed. Invalid password or corrupted data.\n";
        return false;
    }

    type = static_cast<char>(plain[0]);
    payload.assign(plain.begin() + 1, plain.end());

    return true;
}

bool sendHandshake(bool server, const std::string& password)
{
    unsigned char salt[SALT_SIZE]{};

    if (server)
    {
        if (BCryptGenRandom(
            nullptr,
            salt,
            SALT_SIZE,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            return false;
        }

        const char magic[] = "P2P1";

        if (!sendAll(connection, magic, 4) ||
            !sendAll(
                connection,
                reinterpret_cast<const char*>(salt),
                SALT_SIZE))
        {
            return false;
        }
    }
    else
    {
        char magic[4];

        if (!recvAll(connection, magic, 4) ||
            std::string(magic, 4) != "P2P1" ||
            !recvAll(
                connection,
                reinterpret_cast<char*>(salt),
                SALT_SIZE))
        {
            return false;
        }
    }

    if (!crypto.initialize(password, salt))
        return false;

    if (server)
    {
        char type;
        std::vector<unsigned char> payload;

        if (!receivePacket(type, payload) ||
            type != PACKET_AUTH)
        {
            return false;
        }

        return sendPacket(PACKET_AUTH_OK);
    }

    if (!sendPacket(PACKET_AUTH))
        return false;

    char type;
    std::vector<unsigned char> payload;

    return receivePacket(type, payload) &&
        type == PACKET_AUTH_OK;
}

std::string cleanPath(std::string path)
{
    if (path.size() >= 2 &&
        path.front() == '"' &&
        path.back() == '"')
    {
        path = path.substr(1, path.size() - 2);
    }

    return path;
}

void showProgress(
    uint64_t transferred,
    uint64_t total,
    std::chrono::steady_clock::time_point start,
    std::chrono::steady_clock::time_point& lastUpdate,
    uint64_t& lastBytes)
{
    auto now = std::chrono::steady_clock::now();

    double elapsed =
        std::chrono::duration<double>(now - start).count();

    double interval =
        std::chrono::duration<double>(now - lastUpdate).count();

    double speed = 0.0;

    if (interval > 0.0)
        speed = (transferred - lastBytes) / interval;

    double average = elapsed > 0.0
        ? transferred / elapsed
        : 0.0;

    int percent = total > 0
        ? static_cast<int>((transferred * 100) / total)
        : 100;

    std::cout
        << "\r" << percent << "% | "
        << transferred / (1024.0 * 1024.0)
        << " / "
        << total / (1024.0 * 1024.0)
        << " MB | "
        << speed / (1024.0 * 1024.0)
        << " MB/s | Average: "
        << average / (1024.0 * 1024.0)
        << " MB/s"
        << std::flush;

    lastUpdate = now;
    lastBytes = transferred;
}

bool sendFilePacket(
    const fs::path& path,
    const std::string& remoteName,
    char packetType)
{
    if (!fs::exists(path) || !fs::is_regular_file(path))
    {
        std::cout << "[ERROR] File not found.\n";
        return false;
    }

    std::ifstream file(path, std::ios::binary);

    if (!file)
    {
        std::cout << "[ERROR] Could not open file.\n";
        return false;
    }

    uint64_t fileSize = fs::file_size(path);

    std::vector<unsigned char> metadata;
    appendString(metadata, remoteName);
    appendU64(metadata, fileSize);

    if (!sendPacket(packetType, metadata))
        return false;

    std::vector<char> buffer(BUFFER_SIZE);

    uint64_t transferred = 0;

    auto start = std::chrono::steady_clock::now();
    auto lastUpdate = start;
    uint64_t lastBytes = 0;

    std::cout << "\n[SENDING] " << remoteName << "\n";

    while (transferred < fileSize)
    {
        size_t amount = static_cast<size_t>(
            std::min<uint64_t>(
                BUFFER_SIZE,
                fileSize - transferred));

        file.read(buffer.data(), amount);

        if (file.gcount() != static_cast<std::streamsize>(amount))
            return false;

        std::vector<unsigned char> chunk(
            buffer.begin(),
            buffer.begin() + amount);

        if (!sendPacket(PACKET_DATA, chunk))
            return false;

        transferred += amount;

        showProgress(
            transferred,
            fileSize,
            start,
            lastUpdate,
            lastBytes);
    }

    std::cout << "\n[COMPLETE] File sent.\n";
    return true;
}

bool sendFile(const std::string& input)
{
    fs::path path(cleanPath(input));

    if (!fs::exists(path) || !fs::is_regular_file(path))
    {
        std::cout << "[ERROR] Invalid file path.\n";
        return false;
    }

    return sendFilePacket(
        path,
        path.filename().generic_string(),
        PACKET_FILE);
}

bool sendFolder(const std::string& input)
{
    fs::path folder(cleanPath(input));

    if (!fs::exists(folder) || !fs::is_directory(folder))
    {
        std::cout << "[ERROR] Folder not found.\n";
        return false;
    }

    folder = folder.lexically_normal();

    std::string folderName = folder.filename().generic_string();

    if (folderName.empty() ||
        folderName == "." ||
        folderName == "..")
    {
        std::cout << "[ERROR] Invalid folder name.\n";
        return false;
    }

    std::vector<unsigned char> startData;
    appendString(startData, folderName);

    if (!sendPacket(PACKET_FOLDER_START, startData))
        return false;

    std::error_code ec;

    fs::recursive_directory_iterator iterator(
        folder,
        fs::directory_options::skip_permission_denied,
        ec);

    fs::recursive_directory_iterator end;

    size_t fileCount = 0;

    std::cout << "\n[SENDING FOLDER] " << folderName << "\n";

    while (iterator != end)
    {
        const fs::directory_entry entry = *iterator;

        std::error_code entryError;

        if (entry.is_symlink(entryError))
        {
            iterator.disable_recursion_pending();
            iterator.increment(ec);
            ec.clear();
            continue;
        }

        fs::path relative =
            fs::relative(entry.path(), folder, entryError);

        if (!entryError)
        {
            std::string remotePath = relative.generic_string();

            if (entry.is_directory(entryError))
            {
                std::vector<unsigned char> data;
                appendString(data, remotePath);

                if (!sendPacket(PACKET_DIRECTORY, data))
                    return false;
            }
            else if (entry.is_regular_file(entryError))
            {
                if (!sendFilePacket(
                    entry.path(),
                    remotePath,
                    PACKET_FOLDER_FILE))
                {
                    return false;
                }

                ++fileCount;
            }
        }

        iterator.increment(ec);
        ec.clear();
    }

    if (!sendPacket(PACKET_FOLDER_END))
        return false;

    std::cout << "\n[COMPLETE] Folder sent.\n";
    std::cout << "Files transferred: " << fileCount << "\n";

    return true;
}

std::string getSafeFileName(const std::string& input)
{
    fs::path path(input);

    if (path.has_root_name() ||
        path.has_root_directory() ||
        path.is_absolute() ||
        path.has_parent_path())
    {
        return {};
    }

    std::string name = path.filename().string();

    if (name.empty() ||
        name == "." ||
        name == ".." ||
        name.find_first_of("<>:\"/\\|?*") != std::string::npos)
    {
        return {};
    }

    return name;
}

bool getSafeRelativePath(
    const std::string& input,
    fs::path& output)
{
    fs::path path(input);

    if (path.empty() ||
        path.is_absolute() ||
        path.has_root_name() ||
        path.has_root_directory())
    {
        return false;
    }

    for (const auto& part : path)
    {
        std::string name = part.string();

        if (name.empty() ||
            name == "." ||
            name == ".." ||
            name.find_first_of("<>:\"|?*") != std::string::npos)
        {
            return false;
        }
    }

    output = path;
    return true;
}

fs::path makeUniquePath(
    const fs::path& directory,
    const std::string& name)
{
    fs::path original = directory / name;

    if (!fs::exists(original))
        return original;

    for (unsigned int i = 1; i < 100000; ++i)
    {
        fs::path candidate =
            directory / (name + "_" + std::to_string(i));

        if (!fs::exists(candidate))
            return candidate;
    }

    return {};
}

bool receiveFileData(
    const fs::path& outputPath,
    uint64_t fileSize)
{
    std::error_code ec;

    fs::create_directories(outputPath.parent_path(), ec);

    if (ec)
        return false;

    std::ofstream output(outputPath, std::ios::binary);

    if (!output)
        return false;

    uint64_t transferred = 0;

    auto start = std::chrono::steady_clock::now();
    auto lastUpdate = start;
    uint64_t lastBytes = 0;

    while (transferred < fileSize)
    {
        char type;
        std::vector<unsigned char> chunk;

        if (!receivePacket(type, chunk) ||
            type != PACKET_DATA ||
            chunk.empty() ||
            chunk.size() > fileSize - transferred)
        {
            output.close();
            fs::remove(outputPath, ec);
            return false;
        }

        output.write(
            reinterpret_cast<const char*>(chunk.data()),
            static_cast<std::streamsize>(chunk.size()));

        if (!output)
        {
            output.close();
            fs::remove(outputPath, ec);
            return false;
        }

        transferred += chunk.size();

        showProgress(
            transferred,
            fileSize,
            start,
            lastUpdate,
            lastBytes);
    }

    output.close();
    return true;
}

void receiveLoop()
{
    std::error_code ec;
    fs::create_directories("received", ec);

    fs::path activeFolder;
    bool folderActive = false;

    while (running)
    {
        char type;
        std::vector<unsigned char> payload;

        if (!receivePacket(type, payload))
            break;

        size_t offset = 0;

        if (type == PACKET_QUIT)
        {
            std::cout << "\n[REMOTE PEER] Disconnected.\n";
            break;
        }

        if (type == PACKET_FILE)
        {
            std::string name;
            uint64_t fileSize = 0;

            if (!readString(payload, offset, name) ||
                !readU64(payload, offset, fileSize) ||
                offset != payload.size())
            {
                break;
            }

            name = getSafeFileName(name);

            if (name.empty())
                break;

            fs::path output = makeUniquePath("received", name);

            if (output.empty())
                break;

            std::cout << "\n[RECEIVING] " << name << "\n";

            if (!receiveFileData(output, fileSize))
                break;

            std::cout << "\n[SAVED] " << output.string() << "\n";
            continue;
        }

        if (type == PACKET_FOLDER_START)
        {
            std::string name;

            if (!readString(payload, offset, name) ||
                offset != payload.size())
            {
                break;
            }

            name = getSafeFileName(name);

            if (name.empty())
                break;

            activeFolder = makeUniquePath("received", name);

            if (activeFolder.empty())
                break;

            fs::create_directories(activeFolder, ec);

            if (ec)
                break;

            folderActive = true;

            std::cout << "\n[RECEIVING FOLDER] "
                      << name << "\n";
            continue;
        }

        if (type == PACKET_DIRECTORY)
        {
            if (!folderActive)
                break;

            std::string name;
            fs::path relative;

            if (!readString(payload, offset, name) ||
                offset != payload.size() ||
                !getSafeRelativePath(name, relative))
            {
                break;
            }

            fs::create_directories(activeFolder / relative, ec);

            if (ec)
                break;

            continue;
        }

        if (type == PACKET_FOLDER_FILE)
        {
            if (!folderActive)
                break;

            std::string name;
            uint64_t fileSize = 0;
            fs::path relative;

            if (!readString(payload, offset, name) ||
                !readU64(payload, offset, fileSize) ||
                offset != payload.size() ||
                !getSafeRelativePath(name, relative))
            {
                break;
            }

            fs::path output = activeFolder / relative;

            std::cout << "\n[RECEIVING] "
                      << relative.generic_string() << "\n";

            if (!receiveFileData(output, fileSize))
                break;

            std::cout << "\n[SAVED] "
                      << relative.generic_string() << "\n";
            continue;
        }

        if (type == PACKET_FOLDER_END)
        {
            if (!folderActive || !payload.empty())
                break;

            std::cout << "\n[COMPLETE] Folder received.\n";
            std::cout << "[SAVED TO] "
                      << activeFolder.string() << "\n";

            folderActive = false;
            activeFolder.clear();
            continue;
        }

        break;
    }

    running = false;
}

SOCKET createServer()
{
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (server == INVALID_SOCKET)
        return INVALID_SOCKET;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
        server,
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address)) == SOCKET_ERROR ||
        listen(server, 1) == SOCKET_ERROR)
    {
        closesocket(server);
        return INVALID_SOCKET;
    }

    std::cout << "[SERVER] Waiting on port " << PORT << "...\n";

    SOCKET client = accept(server, nullptr, nullptr);

    closesocket(server);
    return client;
}

SOCKET createClient(const std::string& ip)
{
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (client == INVALID_SOCKET)
        return INVALID_SOCKET;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1)
    {
        closesocket(client);
        return INVALID_SOCKET;
    }

    std::cout << "[CLIENT] Connecting to " << ip << "...\n";

    if (connect(
        client,
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address)) == SOCKET_ERROR)
    {
        closesocket(client);
        return INVALID_SOCKET;
    }

    return client;
}

int main()
{
    WSADATA wsaData{};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cout << "[ERROR] Winsock initialization failed.\n";
        return 1;
    }

    std::cout << "====================================\n";
    std::cout << "          P2P FILE TRANSFER\n";
    std::cout << "====================================\n\n";

    std::cout << "[1] Server\n";
    std::cout << "[2] Client\n\n";
    std::cout << "Select an option: ";

    std::string choice;
    std::getline(std::cin, choice);

    std::string password;

    std::cout << "Transfer password: ";
    std::getline(std::cin, password);

    if (password.empty() || password.size() > 1024)
    {
        std::cout << "[ERROR] Invalid password length.\n";
        WSACleanup();
        return 1;
    }

    if (choice == "1")
    {
        connection = createServer();

        if (connection != INVALID_SOCKET &&
            !sendHandshake(true, password))
        {
            closesocket(connection);
            connection = INVALID_SOCKET;
        }
    }
    else if (choice == "2")
    {
        std::string ip;

        std::cout << "Server IP address: ";
        std::getline(std::cin, ip);

        connection = createClient(ip);

        if (connection != INVALID_SOCKET &&
            !sendHandshake(false, password))
        {
            closesocket(connection);
            connection = INVALID_SOCKET;
        }
    }
    else
    {
        std::cout << "[ERROR] Invalid selection.\n";
        WSACleanup();
        return 1;
    }

    SecureZeroMemory(password.data(), password.size());

    if (connection == INVALID_SOCKET)
    {
        std::cout << "\n[ERROR] Connection or authentication failed.\n";
        WSACleanup();
        return 1;
    }

    std::cout << "\n[CONNECTED] Secure connection established.\n";
    std::cout << "====================================\n";
    std::cout << "TRANSFER COMMANDS\n";
    std::cout << "====================================\n";
    std::cout << "/send \"file_path\"       - Send a file\n";
    std::cout << "/sendfolder \"folder_path\" - Send a folder\n";
    std::cout << "/quit                    - Disconnect\n\n";

    std::thread receiver(receiveLoop);

    std::string command;

    while (running)
    {
        std::cout << "> ";

        if (!std::getline(std::cin, command))
            break;

        if (command.rfind("/sendfolder ", 0) == 0)
        {
            std::string path = command.substr(12);

            if (!path.empty())
                sendFolder(path);
            else
                std::cout << "No folder path provided.\n";
        }
        else if (command.rfind("/send ", 0) == 0)
        {
            std::string path = command.substr(6);

            if (!path.empty())
                sendFile(path);
            else
                std::cout << "No file path provided.\n";
        }
        else if (command == "/quit")
        {
            sendPacket(PACKET_QUIT);
            break;
        }
        else
        {
            std::cout << "Unknown command.\n";
            std::cout << "Available: /send, /sendfolder, /quit\n";
        }
    }

    running = false;

    shutdown(connection, SD_BOTH);

    if (receiver.joinable())
        receiver.join();

    closesocket(connection);
    connection = INVALID_SOCKET;

    WSACleanup();

    std::cout << "\nConnection closed.\n";
    return 0;
}
