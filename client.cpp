#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <fstream>
#include <openssl/err.h>

void handleSystemCallError(std::string errorMsg);
int createClientSocket(const std::string &serverIP, int serverPort);
void receiveMessages(int bytesRead, int clientSocket, char buffer[1024], int bufferSize, std::string password);
void sendMessage(int clientSocket, char outMessage[1024], int bufferSize, const std::string &username, std::string password);
std::string readEncryptionKeyFromFile(const std::string &filename, std::string password);
std::string decryptData(const std::string &data, const std::string &key);
std::string encryptData(const std::string &data, const std::string &key);
const int bufferSize = 10240;

int main()
{
    char buffer[bufferSize];
    char outMessage[bufferSize];

    std::cout << "Enter server IP: ";
    std::string serverIP;
    std::cin >> serverIP;

    std::cout << "Enter server port: ";
    int serverPort;
    std::cin >> serverPort;

    std::cout << "Enter your username: ";
    std::string username;
    std::cin >> username;

    std::cout << "Enter encryption password: ";
    std::string encrPSWD;
    std::cin >> encrPSWD;

    int clientSocket = createClientSocket(serverIP, serverPort);

    const char *messageToSend = "Hello From Client!\n";
    send(clientSocket, messageToSend, strlen(messageToSend), 0);

    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        std::cout << buffer << "\n";
    }
    else
    {
        std::cerr << "Error receiving message\n";
    }

    std::thread first(receiveMessages, bytesRead, clientSocket, buffer, bufferSize, encrPSWD);
    std::thread second(sendMessage, clientSocket, outMessage, bufferSize, username, encrPSWD);

    first.join();
    second.join();

    close(clientSocket);
}

// error handler
void handleSystemCallError(std::string errorMsg)
{
    std::cout << errorMsg << ", errno: " << errno << "\n";
    exit(EXIT_FAILURE);
}

// creates a client socket
int createClientSocket(const std::string &serverIP, int serverPort)
{
    // create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        handleSystemCallError("Failed to create socket");
    }

    // Set up the server address structure
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);

    // check IP validity by converting it to binary
    if (inet_pton(AF_INET, serverIP.c_str(), &serverAddress.sin_addr) <= 0)
    {
        handleSystemCallError("Invalid address or address not supported\n");
        close(clientSocket);
        exit(EXIT_FAILURE);
    }

    // connect to server
    if (connect(clientSocket, reinterpret_cast<struct sockaddr *>(&serverAddress), sizeof(serverAddress)) == -1)
    {
        handleSystemCallError("Error when connecting to server\n");
        close(clientSocket);
        exit(EXIT_FAILURE);
    }

    return clientSocket;
}

// receive messages from server
void receiveMessages(int bytesRead, int clientSocket, char buffer[bufferSize], int bufferSize, std::string password)
{
    while (true)
    {
        bytesRead = recv(clientSocket, buffer, bufferSize, 0);
        if (bytesRead > 0)
        {
            // buffer[bytesRead] = '\0';
            std::string encryptedData(buffer, bytesRead); // Create a string with the received data
            std::string decryptedData = decryptData(encryptedData, password);
            std::cout << encryptedData << "\n";
        }
    }
}

// send messages to server
void sendMessage(int clientSocket, char outMessage[bufferSize], int bufferSize, const std::string &username, std::string password)
{
    while (true)
    {
        std::string userMessage;
        std::getline(std::cin, userMessage);

        if (userMessage.length() > bufferSize - username.length() - 3) // Considering space for ": " and null terminator
        {
            std::cout << "Warning: Message is too long. Please keep it within " << bufferSize - username.length() - 3 << " characters.\n";
            continue;
        }
        if (!userMessage.empty())
        {
            userMessage = username + ": " + userMessage;

            userMessage = encryptData(userMessage, password);

            std::cout << userMessage << std::endl;

            send(clientSocket, userMessage.c_str(), userMessage.length() + 1, 0);
        }
    }
}

// decrypts data using a given password
std::string decryptData(const std::string &data, const std::string &key)
{
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.c_str()), nullptr))
    {
        std::cerr << "Error initializing decryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    int len;
    int plaintextLen;

    // Dynamically allocate memory based on the size of the ciphertext
    std::string plaintext(data.size() + AES_BLOCK_SIZE, '\0');

    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]), &len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()))
    {
        std::cerr << "Error updating decryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    plaintextLen = len;

    // Finalize the decryption, including handling any padding
    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&plaintext[len]), &len))
    {
        // Check if the error is due to wrong final block length
        unsigned long error = ERR_get_error();
        if (ERR_GET_REASON(error) == EVP_R_WRONG_FINAL_BLOCK_LENGTH)
        {
            std::cerr << "Padding error. Ignoring." << std::endl;
        }
        else
        {
            std::cerr << "Error finalizing decryption." << std::endl;

            // Print OpenSSL error information
            char errorString[256];
            ERR_error_string_n(error, errorString, sizeof(errorString));
            std::cerr << "OpenSSL Error: " << errorString << std::endl;

            exit(EXIT_FAILURE);
        }
    }

    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    // Resize the string to the actual length of the decrypted data
    plaintext.resize(plaintextLen);

    return plaintext;
}

// encrypts data using a given password
std::string encryptData(const std::string &data, const std::string &key)
{
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.c_str()), nullptr))
    {
        std::cerr << "Error initializing encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    int len;
    int ciphertextLen;
    std::string ciphertext(data.size() + AES_BLOCK_SIZE, '\0');

    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(&ciphertext[0]), &len, reinterpret_cast<const unsigned char *>(data.c_str()), data.size()))
    {
        std::cerr << "Error updating encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    ciphertextLen = len;

    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&ciphertext[len]), &len))
    {
        std::cerr << "Error finalizing encryption." << std::endl;
        exit(EXIT_FAILURE);
    }

    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext.substr(0, ciphertextLen);
}