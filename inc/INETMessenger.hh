#pragma once
#ifndef INETMESSENGER__HH
#define INETMESSENGER__HH

/* INETMessenger class is an interface to give any process a 2-way
 * communication through TCP sockets. It creates a detached thread that
 * listens for incoming connections and requests. You may also connect to
 * any other INETMessenger connected process and send messages of dynamic size.
 * Various hooks are provided so you may create your own functions that are
 * called when events take place such as messages are received or clients
 * are connected among other important events.
 */

 /* Update this value to ensure that all instances are on the same page
  * For instance, if data you are sending has changed on the server, the
  * version should be updated here so that any existing clients cannot connect
  * and know they need to update definitions of what data they are expecting.
  * This avoids making dynamic data structures.
  */
constexpr unsigned int _SERVER_VERSION = 2;

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include "retcode.hh"
#include "TasQ.hh"
#include "Hook.hh"
#include "profiler.hh"
#include "Logger.hh"
#include "MessageTypes.hh"

#include <vector>
#include <string>
#include <sys/types.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <fcntl.h>
#include <queue>
#include <signal.h>
#include <sstream>

#pragma comment(lib,"ws2_32.lib")

/* CONNECTION is the struct we hold information on connections with */
struct CONNECTION
{
    unsigned short port;
    char address[INET6_ADDRSTRLEN];

    // port + address = 2b + 46b = 48 bytes

    bool operator == (const CONNECTION& other) const
    {
        return !strncmp(address, other.address, INET6_ADDRSTRLEN) &&
            port == other.port;
    }

    CONNECTION(unsigned short in_port, char in_address[INET6_ADDRSTRLEN])
        : port(in_port)
    {
        memcpy(address, in_address, sizeof(address));
    }

    CONNECTION()
        : port(-1), address{ 0 }
    { }

    friend std::ostream& operator<< (std::ostream& out, CONNECTION const& connection) {

        out << connection.address << ":" << connection.port;
        return out;
    }
};

/* This custom hash funciton is used in m_FDMap and m_ClientMap maps */
namespace std
{
    template<>
    struct hash<CONNECTION>
    {
        size_t operator() (const CONNECTION& key) const
        {
            return std::hash<std::string>()(key.address) << 1 ^ key.port;
        }
    };
}

/* -- INET_HEADER --
 * This contains information on who is sending a message
 * Meta information about the message such as type and size
 */
struct INET_HEADER
{
    CONNECTION connection; // Where this message comes from
    size_t message_size; // Size of payload only
    unsigned int data_type; // User can define here to differentiate messages
};


#pragma warning(disable:4200) // payload[0] is used as a void* for data
/* -- INET_PACKAGE --
 * Full packet of data sent between INETMessenger instances
 * This contains who sent the message, meta data about the message,
 * and the actual data being sent.
 */
struct INET_PACKAGE
{
    INET_HEADER header; // Info about the message
    char payload[0]; // The data of the message
};

/* -- ACKNOWLEDGE --
 * Used as handshake package between instances of INETMessengers
 * If the server version is not the same then connection can be refused
 * The version should be updated so all clients can concur on the schema
 * and meta data.
 */
struct ACKNOWLEDGE
{
    // _SERVER_VERSION is used for this
    unsigned int server_version;

    ACKNOWLEDGE(unsigned int version)
        : server_version(version)
    {}

    ACKNOWLEDGE()
        : server_version(-1) // intentional overflow to denote bad version
    {}
};

// get sockaddr, IPv4 or IPv6:
static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* Convienience function as many functions accept the port number as strings */
inline static std::string PortIntToString(int port)
{
    std::stringstream portstream;
    portstream << port;
    return portstream.str();
}

/* Convienience function as data sent only needs the int value
 * and not a string
 */
static int PortStringToInt(const std::string& port)
{
    int converted_port = -1;
    std::stringstream portstream(port);
    portstream >> converted_port;

    if (portstream.bad())
    {
        return -1;
    }

    return converted_port;
}

// Used to verify handshake from socket -- client must send handhake in 1 second
static RETCODE ReceiveAck(SOCKET socket)
{
    RETCODE retcode = RTN_OK;

    // Timeout at 1 second to wait for recv
    struct timeval time_value;
    // Th 1 second time limit is defined below
    time_value.tv_sec = 1; // Should make this a config variable
    time_value.tv_usec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time_value, sizeof(time_value));

    INET_PACKAGE& handshake = *reinterpret_cast<INET_PACKAGE*>(new char[sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE)]);

    int bytes_received =
        recv(socket, reinterpret_cast<char*>(&handshake), sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE), 0);

    ACKNOWLEDGE& acknowledge =
        *reinterpret_cast<ACKNOWLEDGE*>(handshake.payload);

    // Reset
    time_value.tv_sec = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time_value, sizeof(time_value));

    if (sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE) != bytes_received ||
        handshake.header.data_type != MESSAGE_TYPE::ACK ||
        _SERVER_VERSION != acknowledge.server_version)
    {
        /* The __INET_BLACKLIST define can be set to block all
         * incoming connections from non-local IP addresses. It also sends
         * a nastygram.
         */
#if __INET_BLACKLIST
         // Sniff any bad handshake attempts
        char* attempted_ack = reinterpret_cast<char*>(&handshake);
        attempted_ack[sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE) - 1] = '\0';
        LOG_INFO("Acknowledge failed. Connection sent: ", attempted_ack);

        // Non-block set for smooth receives and sends
        if (fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) | O_NONBLOCK) < 0)
        {
            return RTN_FAIL;
        }

        char more_buffer[4096] = { 0 };
        while (0 < recv(socket, more_buffer, sizeof(more_buffer) - 1, 0));
        {
            more_buffer[4096 - 1] = '\0';
            LOG_INFO("More: ", more_buffer);
            memset(more_buffer, 0, sizeof(more_buffer));
        }

        if (0 > send(socket, "SUCK MY <b>ENTIRE</b> DICK",
            sizeof("SUCK MY <b>ENTIRE</b> DICK"), 0)) // Config file for custom blacklist message
        {
            LOG_WARN("Could not send aggressive response!");
        }
#endif
        retcode = RTN_CONNECTION_FAIL;
    }

    delete& handshake;

    return retcode;
}

/* This must be called right after connecting -- it is called
 * in the proper place in Connect()
*/
static RETCODE SendAck(SOCKET socket, INET_PACKAGE& handshake)
{
    handshake.header.data_type = MESSAGE_TYPE::ACK;
    if (-1 == send(socket, reinterpret_cast<char*>(&handshake), sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE), 0))
    {
        return RTN_CONNECTION_FAIL;
    }

    return RTN_OK;
}

/* Example function for a message callback would be
 * static void SampleRecvMessage(const INET_PACKAGE* packet)
 * {
 *     std::cout << packet->header.connection.address
 *               << " on "
 *               << packet->header.connection.address << ":"
 *               << packet->header.connection.port
 *               << " has a payload of type: "
 *               << packet->header.data_type
 *               << " and size of: "
 *               << packet->header.message_size
 *               << " with message: "
 * }
 *
 * and then can add the function to the hook
 *
 *   connection.m_OnReceive += SampoleRecvMessage;
 *
 * ------------------------------------
 * A class function call would be
 *
 * class Example
 * {
 *     void ExampleCall(const INET_PACKAGE* packet)
 *     {
 *         std::cout << packet->header.connection.address
 *               << " on "
 *               << packet->header.connection.address << ":"
 *               << packet->header.connection.port
 *               << " has a payload of type: "
 *               << packet->header.data_type
 *               << " and size of: "
 *               << packet->header.message_size
 *               << " with message: "
 *     }
 * };
 *
 *
 *
 * Example ex;
 * connection.m_OnReceive += [&](const INET_PACKAGE* packet){ ex.ExampleCall(packet) }
 */

 // @TODO: Figure out how to pass queue reference rather than pointer
class PollThread : public DaemonThread<int>
{

public:

    RETCODE SendAll(INET_PACKAGE* package)
    {
        PROFILE_FUNCTION();

        if (!m_Ready)
        {
            return RTN_CONNECTION_FAIL;
        }

        for (std::unordered_map<SOCKET, CONNECTION>::iterator iter = m_FDMap.begin(); iter != m_FDMap.end(); ++iter)
        {
            INET_PACKAGE* message = reinterpret_cast<INET_PACKAGE*>(new char[sizeof(INET_PACKAGE) + package->header.message_size]);
            message->header.message_size = package->header.message_size;
            message->header.connection = iter->second;
            message->header.data_type = package->header.data_type;
            memcpy(message->payload, package->payload, message->header.message_size);
            m_SendQueue.Push(message);
        }

        return RTN_OK;
    }

    // Use your own memory -- Recieve() will need to delete memory
    RETCODE Send(INET_PACKAGE* package)
    {
        PROFILE_FUNCTION();

        if (!m_Ready)
        {
            return RTN_CONNECTION_FAIL;
        }

        // Wait until send goes through
        m_SendQueue.Push(package);
        return RTN_OK;
    }

    // Send packed data -- structs without other references
    // In other words the DATA must be coniguous
    // Make a character array and copy bits into it, ok!?
    template<class DATA>
    RETCODE Send(const DATA& data, const CONNECTION& connection)
    {
        PROFILE_FUNCTION();

        if (!m_Ready)
        {
            return RTN_CONNECTION_FAIL;
        }

        INET_PACKAGE* package = new char[sizeof(DATA) + sizeof(INET_PACKAGE)];
        package->header.message_size = sizeof(DATA);
        package->header.connection = connection;
        memcpy(&(package->payload[0]), *data, sizeof(DATA));
        m_SendQueue.Push(package);
        return RTN_OK;
    }

    // Used by client to try and get data from queue
    // User must delete message aftger use
    RETCODE Receive(INET_PACKAGE* message)
    {
        PROFILE_FUNCTION();

        if (!m_Ready)
        {
            return RTN_CONNECTION_FAIL;
        }

        // Try to get a value
        return m_ReceiveQueue.TryPop(message) ? RTN_OK : RTN_NOT_FOUND;
    }

    // Body of the DaemonThread for managing data
    void execute(int dummy = 0)
    {
        PROFILE_FUNCTION();
        RETCODE retcode = RTN_OK;
        int num_poll_events = 0;
        INT timeout = 10; /* in milliseconds */

        while (StopRequested() == false)
        {
            retcode = HandleSends();
            if (RTN_OK != retcode)
            {
                LOG_WARN("Could not handle sends");
            }

            retcode = HandleAccepts();
            if (RTN_OK != retcode)
            {
                LOG_WARN("Failed to handle accepts");
            }

            if (m_PollFDVector.empty())
            {
                /* No connections so just continue */
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            num_poll_events = WSAPoll(&m_PollFDVector[0], static_cast<ULONG>(m_PollFDVector.size()), timeout);

            if (0 == num_poll_events)
            {
                // timeout so just continue and check again
                continue;
            }

            if (num_poll_events == SOCKET_ERROR)
            {
                /* Error */
                LOG_FATAL("Error in epoll wait: ", WSAGetLastError());
                break;
            }

            for (WSAPOLLFD& poll : m_PollFDVector )
            {
                /*
                * We have event(s) from client so read what they have to say
                */
                CONNECTION& connection = m_FDMap[poll.fd];
                retcode = HandleEvent(connection, poll);

                if (RTN_CONNECTION_FAIL == retcode)
                {
                    // Send signal that it's not available for sending??
                }

            }

            /* @TODO: change the sleep value to config so user can
                * determine how often to check for messages
                */
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

        }

        LOG_DEBUG("Stopped polling thread");
    }

    PollThread(const std::string& portNumber = "") :
        m_Ready(false), m_PollFDVector(),
        m_ListeningSocket(INVALID_SOCKET),
        m_AcceptPollSocket(),
        m_Port(portNumber), m_Address(),
        m_SendQueue(), m_ReceiveQueue()
    {
        PROFILE_FUNCTION();

        RETCODE retcode = LoadWinsockLibrary();

        if (RTN_OK != retcode)
        {
            LOG_FATAL("Could not load Winsock library");
            return;
        }


        retcode = SetupListeningSocket();
        if (RTN_OK != retcode)
        {
            LOG_FATAL("Could not set up listening socket");
            return;
        }

        m_Ready = true; // Nothing else can happen unles this is set
    }

    RETCODE StartPoll(void)
    {
        if (m_Ready)
        {
            Start(0);

            m_Address = "127.0.0.1";
            CONNECTION self_connection;
            strncpy_s(self_connection.address, m_Address.c_str(), sizeof(self_connection.address));
            self_connection.port = PortStringToInt(m_Port);
            m_OnServerConnect(self_connection);

            return RTN_OK;
        }

        LOG_WARN("Poll thread cannot start without being ready");
        return RTN_CONNECTION_FAIL;
    }

    RETCODE LoadWinsockLibrary(void)
    {
        // Initialize Winsock -- needed for Windows connections
        WSADATA wsaData = { 0 };
        int startupError = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (NO_ERROR != startupError) {
            LOG_FATAL("Failed to load Winsock library: ", WSAGetLastError());
            return RTN_CONNECTION_FAIL;
        }

        return RTN_OK;
    }

    RETCODE CleanupWinsockLibrary(void)
    {
        WSACleanup();
        return RTN_OK;
    }

    RETCODE SetupListeningSocket(void)
    {
        PROFILE_FUNCTION();
        RETCODE retcode = RTN_OK;
        ULONG sockOptionFlag = 1;

        SOCKADDR_STORAGE  addrLoopback = { 0 };
        addrLoopback.ss_family = AF_INET;
        INETADDR_SETLOOPBACK((SOCKADDR*)&addrLoopback);
        SS_PORT((SOCKADDR*)&addrLoopback) = htons(PortStringToInt(m_Port));

        /* Create listening socket */
        SOCKET& listeningSocket = m_AcceptPollSocket.fd;
        listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (INVALID_SOCKET == listeningSocket)
        {
            LOG_FATAL("Could not create listening socket: ", WSAGetLastError());
            retcode |= CleanupWinsockLibrary();
            retcode |= RTN_CONNECTION_FAIL;
        }

        /* Set non-block */
        if (SOCKET_ERROR == ioctlsocket(listeningSocket, FIONBIO, &sockOptionFlag))
        {
            LOG_FATAL("Could not set listening socket option: ", WSAGetLastError());
            closesocket(listeningSocket);
            retcode |= CleanupWinsockLibrary();
            retcode |= RTN_CONNECTION_FAIL;
            return retcode;
        }

        /* Set bind for listening socket */
        if (SOCKET_ERROR == bind(listeningSocket, (SOCKADDR*)&addrLoopback, sizeof(addrLoopback)))
        {
            LOG_FATAL("Could not bind listening socket: ", WSAGetLastError());
            closesocket(listeningSocket);
            retcode |= CleanupWinsockLibrary();
            retcode |= RTN_CONNECTION_FAIL;
            return retcode;
        }

        /* Start listening for connections */
        if (SOCKET_ERROR == listen(listeningSocket, SOMAXCONN))
        {
            LOG_FATAL("Winsock error: ", WSAGetLastError(), "Failed to start listening on socket : ", listeningSocket);
            closesocket(listeningSocket);
            retcode |= CleanupWinsockLibrary();
            retcode |= RTN_CONNECTION_FAIL;
            return retcode;
        }

        m_AcceptPollSocket.events = POLLRDNORM;

        return retcode;
    }

    RETCODE HandleAccepts(void)
    {
        int num_accepts = WSAPoll(&m_AcceptPollSocket, 1, 5);

        if (0 == num_accepts)
        {
            return RTN_OK;
        }

        if (INVALID_SOCKET == num_accepts)
        {
            return RTN_CONNECTION_FAIL;
        }

        if (m_AcceptPollSocket.revents & POLLRDNORM)
        {
            return AcceptNewClient();
        }

        /* Should never be hit */
        return RTN_OK;
    }

    RETCODE GetConnectionForSelf(void)
    {
        PROFILE_FUNCTION();
        RETCODE retcode = RTN_OK;
        struct addrinfo hints = { 0 };
        struct addrinfo* returnedAddrInfo = nullptr;
        struct addrinfo* currentAddrInfo = nullptr;
        int getInfoStatus = 0;
        const char sockOptionFlag = 1;

        SOCKADDR_STORAGE  addrLoopback = { 0 };
        addrLoopback.ss_family = AF_INET6;
        INETADDR_SETLOOPBACK((SOCKADDR*)&addrLoopback);
        SS_PORT((SOCKADDR*)&addrLoopback) = htons(PortStringToInt(m_Port));

        /* Set how we want the results to come as */
        hints.ai_family = AF_UNSPEC; /* IPV4 or IPV6 */

        /* slower, yet reliable should be configurable */
        hints.ai_socktype = SOCK_STREAM;

        /* fill in IP for me */
        hints.ai_flags = AI_PASSIVE;

        /* Get address for self */
        if ((getInfoStatus = getaddrinfo(nullptr, m_Port.c_str(), &hints, &returnedAddrInfo)) != 0)
        {
            LOG_FATAL("getaddrinfo error: ", gai_strerror(getInfoStatus));
            retcode |= CleanupWinsockLibrary();
            return retcode;
        }
        else
        {
            char accepted_address[INET6_ADDRSTRLEN];

            /* Get linked list of connections */
            inet_ntop(returnedAddrInfo->ai_addr->sa_family,
                get_in_addr((struct sockaddr*)&returnedAddrInfo),
                accepted_address,
                sizeof(accepted_address));

        }

        // Find connection address for us
        for (currentAddrInfo = returnedAddrInfo; currentAddrInfo != NULL; currentAddrInfo = currentAddrInfo->ai_next)
        {

            if (INVALID_SOCKET == (m_ListeningSocket = WSASocket(currentAddrInfo->ai_family, currentAddrInfo->ai_socktype, currentAddrInfo->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED)))
            {
                LOG_WARN("Could not create TCP socket for listening");
                continue;
            }

            if (SOCKET_ERROR == setsockopt(m_ListeningSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &sockOptionFlag, sizeof(const char)))
            {
                LOG_FATAL("Failed to set socket exclusivity");
                retcode |= CleanupWinsockLibrary();
                return retcode;
            }

            if (-1 == bind(m_ListeningSocket, currentAddrInfo->ai_addr, static_cast<int>(currentAddrInfo->ai_addrlen)))
            {
                closesocket(m_ListeningSocket);
                LOG_WARN("Could not bind socket: ", m_ListeningSocket, " for listening on: ", get_in_addr(currentAddrInfo->ai_addr)); // @TODO: Fix print of listening address
                continue;
            }

            if (SOCKET_ERROR == setsockopt(m_ListeningSocket, SOL_SOCKET, SO_KEEPALIVE, &sockOptionFlag, sizeof(const char)))
            {
                LOG_FATAL("Failed to set socket keep alive option");
                retcode |= CleanupWinsockLibrary();
                return retcode;
            }

            break;
        }

        /* Start listening for connections */
        if (SOCKET_ERROR == listen(m_ListeningSocket, SOMAXCONN))
        {
            LOG_FATAL("Winsock error: ", WSAGetLastError(), "Failed to start listening on socket : ", m_ListeningSocket);
            closesocket(m_ListeningSocket);
            retcode |= CleanupWinsockLibrary();
            return retcode |= RTN_CONNECTION_FAIL;
        }

        freeaddrinfo(returnedAddrInfo);
        if (nullptr == currentAddrInfo)
        {
            retcode |= CleanupWinsockLibrary();
            return retcode;
        }

        m_Address = "127.0.0.1";
        CONNECTION self_connection;
        strncpy_s(self_connection.address, m_Address.c_str(), sizeof(self_connection.address));
        self_connection.port = PortStringToInt(m_Port);
        m_OnServerConnect(self_connection);

        return retcode;
    }

    /* Overload if you have a CONNECTION you want to connect to */
    RETCODE Connect(const CONNECTION& connection)
    {
        std::string port = PortIntToString(connection.port);
        return Connect(std::string(connection.address), port);
    }

    /* Can send to this connection using Send() with CONNECTION
     * using the address and port in the args
     */
    RETCODE Connect(const std::string& address, const std::string& port)
    {
        PROFILE_FUNCTION();

        if (!m_Ready)
        {
            return RTN_CONNECTION_FAIL;
        }

        struct addrinfo hints = { 0 };
        struct addrinfo* returnedAddrInfo = nullptr;
        struct addrinfo* currentAddrInfo = nullptr;
        int rv = -1;
        SOCKET connectedSocket = INVALID_SOCKET;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        if ((rv = getaddrinfo(address.c_str(), port.c_str(), &hints, &returnedAddrInfo)) != 0)
        {
            LOG_FATAL("getaddrinfo: ", gai_strerror(rv));
            return RTN_NOT_FOUND;
        }

        // loop through all the results and connect to the first good one
        for (currentAddrInfo = returnedAddrInfo;
            currentAddrInfo != NULL;
            currentAddrInfo = currentAddrInfo->ai_next)
        {
            if (INVALID_SOCKET == (connectedSocket = socket(currentAddrInfo->ai_family, currentAddrInfo->ai_socktype, currentAddrInfo->ai_protocol)))
            {
                LOG_FATAL("Error creating client socket");
                continue;
            }

            // Send initial connection
            if (SOCKET_ERROR ==
                connect(connectedSocket,
                currentAddrInfo->ai_addr,
                static_cast<int>(currentAddrInfo->ai_addrlen)))
            {
                closesocket(connectedSocket);
                LOG_FATAL("Client failed to connect to ", address, ":", port);
                continue;
            }

            break;
        }

        if (currentAddrInfo == NULL)
        {
            freeaddrinfo(returnedAddrInfo);
            return RTN_CONNECTION_FAIL;
        }

        char accepted_address[INET6_ADDRSTRLEN];

        inet_ntop(returnedAddrInfo->ai_addr->sa_family,
            get_in_addr((struct sockaddr*)&returnedAddrInfo),
            accepted_address,
            sizeof(accepted_address));

        freeaddrinfo(returnedAddrInfo);

        /*( We must send handshake with server version
         * or they will reject us. Just a precaution to ensure that we
         * need to update to the server data definitions and version
         */
        ACKNOWLEDGE ack = { _SERVER_VERSION };
        CONNECTION conn;
        INET_PACKAGE& handshake = *reinterpret_cast<INET_PACKAGE*>(new char[sizeof(INET_PACKAGE) + sizeof(ACKNOWLEDGE)]);
        memcpy(handshake.header.connection.address,
            m_Address.c_str(),
            sizeof(handshake.header.connection.address));
        //handshake.header.connection.port = m_PollFD;
        handshake.header.message_size = sizeof(ACKNOWLEDGE);
        memcpy(handshake.payload, &ack, sizeof(ACKNOWLEDGE));

        // Send our server version to server to match
        RETCODE retcode = SendAck(connectedSocket, handshake);
        if (RTN_OK == retcode)
        {
#if 0
            // Non-block set for smooth receives and sends
            if (fcntl(connectedSocket, F_SETFL, fcntl(connectedSocket, F_GETFL) | O_NONBLOCK) < 0)
            {
                return RTN_FAIL;
            }
#endif
            memcpy(conn.address, accepted_address, sizeof(conn.address));
            conn.port = PortStringToInt(port);
            retcode |= AddConnection(connectedSocket, conn);
        }

        if (RTN_OK != retcode)
        {
            LOG_WARN(
                "Failed to add: ",
                address,
                " on port: ",
                port);
        }

        delete& handshake;
        return retcode;
    }

    /* Stop listening, but don't destruct */
    RETCODE StopListeningForAccepts()
    {
        PROFILE_FUNCTION();
        if (m_Ready)
        {
            m_Ready = false;
            Stop();
            closesocket(m_ListeningSocket);
            return RTN_OK;
        }

        return RTN_OK;
    }

    /* Handle both accepts, disconnects, and of course incoming messages */
    RETCODE HandleEvent(const CONNECTION& connection, const WSAPOLLFD& poll)
    {
        PROFILE_FUNCTION();
        RETCODE retcode = RTN_OK;
        int recv_ret = -1;
        INET_HEADER inet_header = {};

        // Need to get connection that matches fd to call disconnect delegate
        if (poll.revents & POLLERR)
        {
            retcode = RemoveConnection(poll.fd, connection);
            return RTN_CONNECTION_FAIL;
        }

        if (poll.revents & POLLHUP)
        {
            RemoveConnection(poll.fd, connection);
            return RTN_OK;
        }

        if (poll.revents & POLLRDNORM)
        {
            recv_ret = recv(poll.fd, reinterpret_cast<char *>(&inet_header), sizeof(INET_HEADER), 0);
            if (0 == recv_ret)
            {
                RemoveConnection(poll.fd, connection);
                return RTN_OK;
            }

            if (INVALID_SOCKET == recv_ret)
            {
                /* WSAEWOULDBLOCK means end of data */
                int error = WSAGetLastError();
                if (WSAEWOULDBLOCK != error)
                {
                    LOG_WARN("Failed receiving message header from: ", inet_header.connection, " with error: ", error);
                    RemoveConnection(poll.fd, connection);
                    return RTN_CONNECTION_FAIL;
                }
            }


            /* Dynamically create memory for whole package size */
            /* Maybe needs size limiting to avoid giant packages */
            INET_PACKAGE* package = reinterpret_cast<INET_PACKAGE*>(new char[sizeof(INET_PACKAGE) + inet_header.message_size]);
            memcpy(&(package->header.connection), &m_FDMap[poll.fd], sizeof(CONNECTION));
            package->header.message_size = inet_header.message_size;
            package->header.data_type = inet_header.data_type;
            size_t remaining_message = package->header.message_size;

            while (0 < (recv_ret = recv(poll.fd, package->payload + inet_header.message_size - remaining_message, static_cast<int>(remaining_message), 0)))
            {
                remaining_message -= static_cast<size_t>(recv_ret);
            }
#if 0

            if (0 == recv_ret)
            {
                LOG_INFO("Client: ", inet_header.connection.address, ":", inet_header.connection.port, " closed their connection.");
                RemoveConnection(poll.fd, connection);
                return RTN_OK;
            }
#endif

            if (INVALID_SOCKET == recv_ret)
            {
                /* WSAEWOULDBLOCK means end of data */
                int error = WSAGetLastError();
                if(WSAEWOULDBLOCK != error)
                {
                    LOG_WARN("Failed receiving data from: ", inet_header.connection.address, ":", inet_header.connection.port, " with error: ", WSAGetLastError());
                    RemoveConnection(poll.fd, connection);
                    delete[] package;
                    return RTN_CONNECTION_FAIL;
                }
            }

            if (remaining_message != 0)
            {
                LOG_WARN("Received less bytes than promised from: ", inet_header.connection.address, ":", inet_header.connection.port, "  mssing: ", remaining_message, " bytes");
            }

            m_TotalDataRecv += package->header.message_size;
            m_OnReceive(package);
            delete[] package;
            return RTN_OK;
        }

        return RTN_OK;

    }

    /* Pick up messages in the send queue  and send */
    RETCODE HandleSends(void)
    {
        PROFILE_FUNCTION();
        int message_length = 0;
        INET_PACKAGE* packet = nullptr;

        while (m_SendQueue.TryPop(packet))
        {
#if 0
            std::unordered_map<SOCKET, CONNECTION>::iterator connection =
                m_FDMap.find(packet->header.connection);
#endif

            /* @TODO figure out a way to lookkup packet fd in O(1) */
            std::unordered_map<SOCKET, CONNECTION>::iterator connection = m_FDMap.begin();
            for (; connection != m_FDMap.end(); connection++)
            {
                if (connection->second == packet->header.connection)
                {
                    break;
                }
            }

            if (connection != m_FDMap.end())
            {
                message_length = static_cast<int>(packet->header.message_size + sizeof(INET_PACKAGE));
                while (message_length > 0)
                {
                    message_length -=
                        send(connection->first, reinterpret_cast<const char*>(packet), message_length, 0);
                }

                m_TotalDataSent += packet->header.message_size;
            }
            else
            {
                LOG_WARN("Could not find: ",
                    packet->header.connection,
                    "sending failed!");
            }

            delete[] packet;
        }

        return RTN_OK;
    }

    /* Accept connects and require a handshake */
    RETCODE AcceptNewClient()
    {
        PROFILE_FUNCTION();
        RETCODE retcode = RTN_OK;
        struct sockaddr incoming_accepted_address;
        socklen_t incoming_address_size = sizeof(incoming_accepted_address);
        SOCKET accept_socket = -1;
        char accepted_address[INET6_ADDRSTRLEN];
        int err = 0;

        CONNECTION connection;
        ACKNOWLEDGE acknowledge = { 0 };

        accept_socket = accept(m_AcceptPollSocket.fd,
            (struct sockaddr*)&incoming_accepted_address,
            &incoming_address_size);

        if (0 < accept_socket)
        {
            inet_ntop(incoming_accepted_address.sa_family,
                get_in_addr((struct sockaddr*)&incoming_accepted_address),
                accepted_address, sizeof(accepted_address));

            // Wait for client to send ack
            retcode = ReceiveAck(accept_socket);

            if (RTN_OK == retcode)
            {
                memcpy(connection.address, accepted_address, sizeof(connection.address));
                connection.port = PortStringToInt(m_Port);
                ULONG nonBockModeSet = 1;

                // Non-block set for smooth receives and sends
                if (SOCKET_ERROR == ioctlsocket(accept_socket, FIONBIO, &nonBockModeSet))
                {
                    LOG_FATAL("Could not set non-block status for accepted socket: ", accept_socket, " with error: ", WSAGetLastError());
                    return RTN_FAIL;
                }

                if (RTN_OK != AddConnection(accept_socket, connection))
                {
                    LOG_WARN("Bad connection: ", connection);
                    closesocket(accept_socket);
                    return RTN_FAIL;
                }

                return RTN_OK;
            }
            else
            {
                LOG_WARN("Failed to accept client: ", connection);
                closesocket(accept_socket);
                return RTN_CONNECTION_FAIL;
            }
        }
        else
        {
            err = errno;
            if (err == EAGAIN)
            {
                /* Socket busy so we just try again next time around */
                return RTN_OK;
            }

            /* Error */
            LOG_FATAL("Error in accept(): ", WSAGetLastError());
            return RTN_FAIL;
        }

    }

    /* Add file descriptor to poll so we can listen for events */
    RETCODE AddFDToPoll(SOCKET fd)
    {
        PROFILE_FUNCTION();
        m_PollFDVector.push_back(WSAPOLLFD{ fd, 0, 0 });
        m_PollFDVector.back().events = POLLIN;
        return RTN_OK;
    }

    /* Add connection to both m_FDMap and m_ConnectionMap for 2 way lookup */
    RETCODE AddConnection(SOCKET fd, const CONNECTION& connection)
    {

#if 0
        if (m_ConnectionMap.find(connection) != m_ConnectionMap.end())
        {
            // Already have this connection so just ignore
            return RTN_CONNECTION_FAIL;
        }
#endif

        for (std::unordered_map<SOCKET, CONNECTION>::iterator iter = m_FDMap.begin(); iter != m_FDMap.end(); iter++)
        {
            if (iter->second == connection)
            {
                return RTN_CONNECTION_FAIL;
            }
        }

        /* __INET_BLACKLIST define cuts out all non-local connections */
#if __INET_BLACKLIST
        //Blacklist on outside connections -- remove later
        if (0 != strncmp(connection.address,
            "192.168.0.",
            sizeof("192.168.0.") - 1))
        {
            closesocket(fd);
            return RTN_CONNECTION_FAIL;
        }
#endif

        RETCODE retcode = AddFDToPoll(fd);


        if (RTN_OK == retcode)
        {
            /* Assume fd is unique, right? right?? */
            m_FDMap[fd] = connection;

            m_OnClientConnect(connection);
        }

        return retcode;
    }

    /* Disconnect a client from listening */
    RETCODE RemoveConnection(SOCKET fd, const CONNECTION& connection)
    {
        RETCODE retcode = RemoveFDFromPoll(fd);
        if (RTN_OK == retcode)
        {
            m_OnDisconnect(connection);
            // Must erase only after completey done as is a referenece
            m_FDMap.erase(fd);
        }

        return retcode;
    }


    /* Remove file descriptor from poll */
    RETCODE RemoveFDFromPoll(SOCKET fd)
    {
        PROFILE_FUNCTION();
        size_t pollIndex = 0;

        for (; pollIndex < m_PollFDVector.size(); ++pollIndex)
        {
            if (fd == m_PollFDVector.at(pollIndex).fd)
            {
                m_PollFDVector.erase(m_PollFDVector.begin() + pollIndex);

                if (closesocket(fd))
                {
                    LOG_FATAL("Failed to close socket: ",
                        fd,
                        " from polling with error: ",
                        WSAGetLastError());
                    return RTN_FAIL;
                }

                return RTN_OK;
            }
        }

        LOG_WARN("Error could not find fd for removal: ", fd);
        return RTN_NOT_FOUND;
    }

    /* Remove all clients from polling and inovke disconnect for each client */
    RETCODE StopPoll()
    {
        RETCODE retcode = RTN_OK;
        m_SendQueue.done();
        m_ReceiveQueue.done();
        Stop();

        for (std::unordered_map<SOCKET, CONNECTION>::iterator iter =
            m_FDMap.begin(); iter != m_FDMap.end(); ++iter)
        {
            retcode |= RemoveConnection(iter->first, iter->second);
        }

        retcode |= RemoveFDFromPoll(m_ListeningSocket);
        m_FDMap.clear();

        m_OnStop(0);

        return retcode;

    }

    /* Getters/Setters */
    std::string GetTCPAddress()
    {
        return m_Address;
    }

    std::string GetTCPPort()
    {
        return m_Port;
    }

    SOCKET GetTCPSocket()
    {
        return m_ListeningSocket;
    }

    /* private class members */
    bool m_Ready;
    std::vector<WSAPOLLFD> m_PollFDVector;
    ULONG m_PollFDArraySize;
    SOCKET m_ListeningSocket;
    WSAPOLLFD m_AcceptPollSocket;
    std::string m_Port;
    std::string m_Address;
    TasQ<INET_PACKAGE*> m_SendQueue;
    TasQ<INET_PACKAGE*> m_ReceiveQueue;

    /* Both need to be in step so we can look up either way */
    std::unordered_map<SOCKET, CONNECTION> m_FDMap;
    /* Hooks which are called in the appropriate events.
     * Users can define their own functions to be called when these
     * events happen. See definition of Hook for examples.
     */
    Hook<const CONNECTION&> m_OnClientConnect;
    Hook<const CONNECTION&> m_OnServerConnect;
    Hook<const CONNECTION&> m_OnDisconnect;
    Hook<const INET_PACKAGE*> m_OnReceive;
    // @TODO: figure out how to template an argument pack with no args (void)
    Hook<int> m_OnStop;

public:

    /* max of 18446.744073709553049 petabytes sent should be enough */
    unsigned long long int m_TotalDataSent;
    unsigned long long int m_TotalDataRecv;
};


#endif