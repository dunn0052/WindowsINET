#include "../inc/CLI.hh"
#include "../inc/INETMessenger.hh"

static BOOL g_Running = false;

class WriteThread : public DaemonThread<TasQ<INET_PACKAGE*>*>
{
    void execute(TasQ<INET_PACKAGE*>* p_queue)
    {
        std::string user_input;
        INET_PACKAGE* message = nullptr;
        RETCODE retcode = RTN_OK;

        TasQ<INET_PACKAGE*>& messages = *p_queue;

        while (StopRequested() == false)
        {
            //std::cin.clear();
            //std::cin.sync();
            //std::getline(std::cin, user_input);

            std::cin >> user_input;

            if (!user_input.empty())
            {
                message = reinterpret_cast<INET_PACKAGE*>(new char[sizeof(INET_PACKAGE) + user_input.length() + 1]);
                message->header.message_size = user_input.length() + 1;
                message->header.data_type = MESSAGE_TYPE::TEXT;
                strncpy_s(message->payload, message->header.message_size, user_input.c_str(), user_input.length());
                messages.Push(message);
            }
        }
    }

};

void endServer(int signal)
{
    LOG_INFO("Received signal: ", signal);

    if (SIGINT == signal)
    {
        g_Running = false;
    }
}

int main(int argc, char* argv[])
{
    signal(SIGINT, endServer);

    CLI::Parser parse("Listener", "Listen for database updates");
    CLI::CLI_StringArgument connectionAddressArg("-c", "Connection address for Other", false);
    CLI::CLI_StringArgument connectionPortArg("-p", "Connection port for Other", false);
    CLI::CLI_StringArgument listeningPortArg("-l", "Listening port", true);
    CLI::CLI_FlagArgument helpArg("-h", "Shows usage", false);

    parse
        .AddArg(connectionAddressArg)
        .AddArg(connectionPortArg)
        .AddArg(listeningPortArg)
        .AddArg(helpArg);


    RETCODE parseRetcode = parse.ParseCommandLineArguments(argc, argv);

    if (helpArg.IsInUse())
    {
        parse.Usage();
        return 0;
    }

    if (RTN_OK == parseRetcode)
    {
        LOG_INFO("Got ", listeningPortArg.GetValue(), " for listeining port number!");
        PollThread messenger(listeningPortArg.GetValue());

        messenger.m_OnStop += [&](int _) { LOG_INFO("Stopped server!"); };
        messenger.m_OnClientConnect += [&](const CONNECTION& connection) { LOG_INFO("Connected to ", connection.address, ":", connection.port); };
        messenger.m_OnServerConnect += [&](const CONNECTION& connection) { LOG_INFO("Started server on ", connection.address, ":", connection.port); };
        messenger.m_OnDisconnect += [&](const CONNECTION& connection) { LOG_INFO("Client ", connection.address, ":", connection.port, " disconnected"); };
        messenger.m_OnReceive += [&](const INET_PACKAGE* p_package)
        {
            const INET_PACKAGE& package = *p_package;
            const CONNECTION& connection = package.header.connection;

            switch (package.header.data_type)
            {
                case MESSAGE_TYPE::TEXT:
                    LOG_INFO("Client ", connection, "-> ", package.payload);
                    break;
                default:
                    LOG_INFO("Unknown message type from client: ", connection, "-> ", package.header.data_type);
            }
        };


        messenger.StartPoll();

        if (connectionAddressArg.IsInUse() && connectionPortArg.IsInUse())
        {
            RETURN_RETCODE_IF_NOT_OK(messenger.Connect(connectionAddressArg.GetValue(), connectionPortArg.GetValue()));
        }

        TasQ<INET_PACKAGE*> messages;
        WriteThread* writer_thread = new WriteThread();
        writer_thread->Start(&messages);

        INET_PACKAGE* message;

        g_Running = true;

        // Wait 10 seconds
        while(g_Running)
        {
            while (messages.TryPop(message))
            {
                messenger.SendAll(message);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        parseRetcode |= messenger.StopPoll();
    }
    else
    {
        parse.Usage();
    }

    return parseRetcode;
}