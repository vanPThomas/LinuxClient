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
void receiveMessages(int clientSocket, int bufferSize, std::string password);
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

    std::thread first(receiveMessages, clientSocket, bufferSize, encrPSWD);
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
void receiveMessages(int clientSocket, int bufferSize, std::string password)
{
    char receiveBuffer[bufferSize];

    while (true)
    {
        int bytesRead = recv(clientSocket, receiveBuffer, bufferSize, 0);
        if (bytesRead > 0)
        {
            std::string encryptedData(receiveBuffer, bytesRead); // Create a string with the received data
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

            // userMessage = encryptData(userMessage, password);

            // std::cout << userMessage << std::endl;

            send(clientSocket, userMessage.c_str(), userMessage.length() + 1, 0);
        }
    }
}

std::string decryptData(const std::string &data, const std::string &key)
{
    // Initialization Vector (IV) should be the same size as the block size
    std::string iv = key.substr(0, 16);

    // Set up the OpenSSL decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Initialize the decryption operation with AES 256 CBC and the provided key and IV
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char *>(key.c_str()), reinterpret_cast<const unsigned char *>(iv.c_str()));

    // Provide the message to be decrypted
    int len;
    int plaintext_len;
    unsigned char *plaintext = new unsigned char[data.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    // Perform the decryption
    EVP_DecryptUpdate(ctx, plaintext, &len, reinterpret_cast<const unsigned char *>(data.c_str()), data.length());
    plaintext_len = len;

    // Finalize the decryption
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    // Convert the decrypted data to a string
    std::string decryptedData(reinterpret_cast<char *>(plaintext), plaintext_len);

    // Clean up allocated memory
    delete[] plaintext;

    return decryptedData;
}

std::string encryptData(const std::string &data, const std::string &key)
{
    // Initialization Vector (IV) should be the same size as the block size
    std::string iv = key.substr(0, 16);

    // Set up the OpenSSL encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Initialize the encryption operation with AES 256 CBC and the provided key and IV
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char *>(key.c_str()), reinterpret_cast<const unsigned char *>(iv.c_str()));

    // Provide the message to be encrypted
    int len;
    int ciphertext_len;
    unsigned char *ciphertext = new unsigned char[data.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];

    // Perform the encryption
    EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char *>(data.c_str()), data.length());
    ciphertext_len = len;

    // Finalize the encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);

    // Convert the encrypted data to a string
    std::string encryptedData(reinterpret_cast<char *>(ciphertext), ciphertext_len);

    // Clean up allocated memory
    delete[] ciphertext;

    return encryptedData;
}
