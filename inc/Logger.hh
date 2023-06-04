#pragma once
#ifndef _LOGGER_H
#define _LOGGER_H

// #define options
// __LOG_ENABLE -- perform any logging at all
// __LOG_SHOW_LINE -- shows exactly which file.line the log is generated
// __LOG_SHOW_TIME --  show time log was generated

#include <ostream>
#include <sstream>
#include <iostream>
#include <string>
#include <mutex>

#if __LOG_SHOW_TIME
#include <chrono>
#include <ctime>
#endif

#if __LOG_ENABLE
#define LOG_TEMPLATE( LEVEL, ... ) Log::Logger::Instance().Log(std::cout, Log::LogLevel::LEVEL, #LEVEL, __FILE__, __LINE__, ##__VA_ARGS__ )
#define LOG_FATAL_TEMPLATE( LEVEL, ... ) Log::Logger::Instance().Log(std::cerr, Log::LogLevel::LEVEL, #LEVEL, __FILE__, __LINE__, ##__VA_ARGS__ )
#else
#define LOG_TEMPLATE( LEVEL, ... )
#define LOG_FATAL_TEMPLATE( LEVEL, ...)
#endif

#define LOG_DEBUG( ... ) LOG_TEMPLATE( DEBUG, ##__VA_ARGS__ )
#define LOG_INFO( ... ) LOG_TEMPLATE( INFO, ##__VA_ARGS__ )

#define LOG_WARN( ... ) LOG_FATAL_TEMPLATE( WARN, ##__VA_ARGS__ )
#define LOG_FATAL( ... ) LOG_FATAL_TEMPLATE( FATAL, ##__VA_ARGS__ )

namespace Log
{
    enum class LogLevel
    {
        DEBUG,
        INFO,
        WARN,
        FATAL,
        NONE
    };

    class Logger
    {

    public:

        template<typename Stream, typename... RestOfArgs>
        Stream& Log(Stream& stream, LogLevel level, const char* debugLevel, const char* fileName, int lineNum, const RestOfArgs& ... args)
        {
            /* Internal string stream used to ensure thread safety when printing.
             * It is passed through to collect the arguments into a single string,
             * which will do a single << to the input stream at the end
             */
            std::stringstream internalStream;
            return Log(stream, internalStream, level, debugLevel, fileName, lineNum, args...);
        }

        template<typename Stream, typename... RestOfArgs>
        Stream& Log(Stream& stream, std::stringstream& internalStream, LogLevel level, const char* debugLevel, const char* fileName, int lineNum, const RestOfArgs& ... args)
        {

            internalStream << "[" << debugLevel << "]";

#if __LOG_SHOW_LINE
            internalStream << "[" << fileName << ":" << lineNum << "]";
#endif

#if __LOG_SHOW_TIME
            time_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            internalStream
                << "["
                << strtok(std::ctime(&currentTime), "\n")
                << "]";
#endif

            internalStream << " "; // Space between decorator and user text
            return Log(stream, internalStream, args...);
        }

        template<typename Stream, typename ThisArg, typename... RestOfArgs>
        Stream& Log(Stream& stream, std::stringstream& internalStream, const ThisArg& arg1, const RestOfArgs&... args)
        {
            internalStream << arg1;
            return Log(stream, internalStream, args...);
        }

        template<typename Stream, typename ThisArg>
        Stream& Log(Stream& stream, std::stringstream& internalStream, const ThisArg& arg1)
        {
            internalStream << arg1;
            return (stream << internalStream.str() << std::endl);
        }

        static Logger& Instance(void)
        {
            static Logger instance;
            return instance;
        }

        ~Logger()
        {
        }

        Logger() {};

    private:

        Logger(Logger const&) = delete;
        void operator = (Logger const&) = delete;
        LogLevel m_LogLevel = LogLevel::NONE;
        std::stringstream m_InternalStream;


    };

}

#endif