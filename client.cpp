#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>

void handleSystemCallError(std::string errorMsg);
int createClientSocket(const std::string &serverIP, int serverPort);
void receiveMessages(int bytesRead, int clientSocket, char buffer[1024], int bufferSize);
void sendMessage(int clientSocket, char outMessage[1024], int bufferSize, const std::string &username);

int main()
{
    const int bufferSize = 10240;
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

    std::thread first(receiveMessages, bytesRead, clientSocket, buffer, bufferSize);
    std::thread second(sendMessage, clientSocket, outMessage, bufferSize, username);

    first.join();
    second.join();

    close(clientSocket);
}

void handleSystemCallError(std::string errorMsg)
{
    std::cout << errorMsg << ", errno: " << errno << "\n";
    exit(EXIT_FAILURE);
}

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

void receiveMessages(int bytesRead, int clientSocket, char buffer[10240], int bufferSize)
{
    while (true)
    {
        bytesRead = recv(clientSocket, buffer, bufferSize, 0);
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            std::cout << buffer << "\n";
        }
    }
}

void sendMessage(int clientSocket, char outMessage[10240], int bufferSize, const std::string &username)
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

            send(clientSocket, userMessage.c_str(), userMessage.length(), 0);
        }
    }
}
