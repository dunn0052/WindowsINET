#pragma once
#ifndef _PROFILER_HH
#define _PROFILER_HH

/* View data by loading the resulting JSON file to chrome://tracing

 * For C++ 0X -- The profiler must be initialized in the main thread or
 * there is danger of the ProfPool singleton being multi-initialized.

 * Usage: Call PROFILE_FUNCTION() or PROFILE_SCOPE() to start profiling.
 * START_PROFILING() can be called to start the profiler threads without
 * logging profile metrics.

 * Notes: If program dies before the profiler destructor is called the
 * individual writer files will still be around and you can manually combine
 * all of them together.
 */


 /* CMAKE: add_definitions(-D__ENABLE_PROFILING) */
#ifdef __ENABLE_PROFILING
// linux only!!
#define FUNCTION_SIG __PRETTY_FUNCTION__

#define CAT_(A, B) A ## B
#define CAT(A, B) CAT_(A, B)
#define UNIQUE_LOCAL( VARIABLE ) CAT( VARIABLE, __LINE__)

// Profile a scope such as a tight loop in a function
#define PROFILE_SCOPE( NAME ) Timer UNIQUE_LOCAL(timer)( NAME )
// Profile with function name - place at function entry
#define PROFILE_FUNCTION() PROFILE_SCOPE(FUNCTION_SIG)
// Used for initializing profiling without profiling the scope itself
#define START_PROFILING()  ProfPool::Instance()

#else

// If __ENABLE_PROFILING isn't set then all is simply compiled out of the build
#define PROFILE_SCOPE( NAME )
#define PROFILE_FUNCTION()
#define START_PROFILING()
#endif

#include <string>
#include <fstream>
#include <sstream>

#include <processthreadsapi.h>
#include <sysinfoapi.h>

#include <sys/types.h>
#include <errno.h>  // `errno`
#include <stdint.h> // `UINT64_MAX`
#include <stdio.h>  // `printf()`
#include <string.h> // `strerror(errno)`
#include <time.h>   // `clock_gettime()` and `timespec_get()`
#include <queue>
#include <sstream>
#include <iostream>
#include <mutex>
#include <condition_variable>

#include "DaemonThread.hh"

// Program name for profile json
// Not portable outside of glibc
extern char* program_invocation_name;
extern char* program_invocation_short_name;

typedef uint64_t nanosec;

static const std::string JSON_EXT = ".json";

static inline nanosec SEC_TO_NS(time_t sec) { return (sec * 1000000000U); }

struct ProfileResult
{
    ProfileResult(ProfileResult&& other) noexcept
        : m_Name(std::move(other.m_Name)), m_Start(std::move(other.m_Start)),
        m_End(std::move(other.m_End)), m_ThreadID(std::move(other.m_ThreadID)),
        m_ProcessName(std::move(other.m_ProcessName))
    {
    }

    ProfileResult& operator=(ProfileResult&& other) noexcept
    {
        m_Name = std::move(other.m_Name);
        m_Start = std::move(other.m_Start);
        m_End = std::move(other.m_End);
        m_ThreadID = std::move(other.m_ThreadID);
        m_ProcessName = std::move(other.m_ProcessName);
        return *this;
    }

    ProfileResult(const ProfileResult& other)
        : m_Name(other.m_Name), m_Start(other.m_Start),
        m_End(other.m_End), m_ThreadID(other.m_ThreadID),
        m_ProcessName(other.m_ProcessName)
    { }

    ProfileResult(const std::string& name, nanosec& start, nanosec& end,
        DWORD& threadid, const std::string& processName)
        : m_Name(name), m_Start(start), m_End(end), m_ThreadID(threadid),
        m_ProcessName(processName)
    {}

    ProfileResult()
        : m_Name(), m_Start(), m_End(), m_ThreadID(),
        m_ProcessName()
    {}

    std::string m_Name;
    nanosec m_Start;
    nanosec m_End;
    DWORD m_ThreadID;
    std::string m_ProcessName;
};

class ProfQueue
{
private:
    std::queue<ProfileResult> m_ResultQueue;
    bool m_Done;
    std::mutex n_Mutex;
    std::condition_variable n_ReadyCondition;

public:
    ProfQueue()
        : m_ResultQueue(), m_Done(false), n_Mutex(), n_ReadyCondition()
    {
    }

    void done()
    {
        n_Mutex.lock();
        m_Done = true;
        n_Mutex.unlock();

        n_ReadyCondition.notify_all();
    }

    bool Pop(ProfileResult& result)
    {
        std::unique_lock<std::mutex> lock = std::unique_lock<std::mutex>{ n_Mutex };
        while (m_ResultQueue.empty() && !m_Done)
        {
            n_ReadyCondition.wait(lock);
        }

        if (m_ResultQueue.empty())
        {
            result.m_End = 0; // Denote empty result
            return false;
        }

        result = std::move(m_ResultQueue.front());
        m_ResultQueue.pop();

        return true;
    }

    bool TryPop(ProfileResult& result)
    {

        if (!n_Mutex.try_lock())
        {
            result.m_End = 0;
            return false;
        }

        if (m_ResultQueue.empty())
        {
            n_Mutex.unlock();
            result.m_End = 0;
            return false;
        }

        result = std::move(m_ResultQueue.front());
        m_ResultQueue.pop();

        n_Mutex.unlock();

        return true;
    }

    void Push(ProfileResult&& result)
    {
        n_Mutex.lock();
        m_ResultQueue.push(std::move(result));
        n_Mutex.unlock();

        n_ReadyCondition.notify_one();
    }

    bool TryPush(ProfileResult&& result)
    {
        if (!n_Mutex.try_lock())
        {
            return false;
        }

        m_ResultQueue.push(std::move(result));

        n_Mutex.unlock();
        n_ReadyCondition.notify_one();
        return true;
    }
};

class ProfileWriter : public DaemonThread<std::vector<ProfQueue>*>
{

private:
    bool m_FirstEntry;
    std::ofstream m_json_stream;
    std::string m_json_filename;
    size_t writer_index;
    bool m_Running;

    ProfileWriter& operator=(const ProfileWriter&) {}

public:

    ProfileWriter(const ProfileWriter&) :
        m_FirstEntry(true),
        m_Running(false),
        writer_index(0)
    { }

    void execute(std::vector<ProfQueue>* results_queue)
    {

        ProfileResult result;
        result.m_End = 0;
        std::vector<ProfQueue>& queue = *results_queue;

        if (!m_json_stream.is_open())
        {
            m_json_stream.open(m_json_filename, std::fstream::trunc);
        }

        while (!StopRequested())
        {
            // Steal tasks
            for (size_t queueIndex = 0; queueIndex != queue.size(); ++queueIndex)
            {
                if (queue[(queueIndex + writer_index) %
                    queue.size()].TryPop(result))
                {
                    break;
                }
            }

            // Otherwise wait for ours
            if (!result.m_End && !queue[writer_index].Pop(result))
            {
                // Once done, just wait for the thread to be stopped
                continue;
            }

            WriteProfile(result);
        }

        // If we stopped before our queue is empty then
        while (queue[writer_index].Pop(result))
        {
            WriteProfile(result);
        }

        m_json_stream.close();
    }

    ProfileWriter(const std::string& filepath, size_t writer_id)
        : m_FirstEntry(true), m_json_filename(filepath),
        writer_index(writer_id), m_Running(false)
    {
    }

    ~ProfileWriter()
    {
        if (!m_Running)
        {
            // We've already extracted the file contents
            // to the main profiler json. No need for them now.
            remove(m_json_filename.c_str());
        }
    }

    void WriteProfile(const ProfileResult& result)
    {

        /* next item timed */
        if (!m_FirstEntry)
        {
            m_json_stream << ",\n";
        }
        else
        {
            m_FirstEntry = false;
        }

        // creates timing entry to the JSON file that is read by Chrome.
        m_json_stream
            << "{\"cat\":\"function\",\"dur\":"
            << (result.m_End - result.m_Start)
            << ",\"name\":\""
            << result.m_Name
            << "\",\"ph\":\"X\",\"pid\":\""
            << result.m_ProcessName
            << "\",\"tid\":"
            << result.m_ThreadID
            << ",\"ts\":"
            << result.m_Start << "}";

        /* flush here so data isn't lost in case of crash */
        m_json_stream.flush();
    }

    friend std::ofstream& operator<< (std::ofstream& os, ProfileWriter& p)
    {
        std::string data;
        std::ifstream profile_data;

        if (!p.m_json_stream.is_open())
        {
            p.m_json_stream.close();
        }

        profile_data.open(p.m_json_filename.c_str());
        if (!profile_data.is_open())
        {
            os << "Could not open: " << p.m_json_filename << "!\n";
            return os;
        }

        while (getline(profile_data, data)) {
            os << "\n        " << data;
        }

        profile_data.close();

        return os;
    }

};

class ProfPool
{
    static constexpr size_t ROUNDS = 3;
public:

    // Could try to make this async
    void Log(ProfileResult&& result)
    {
        if (!m_Ready)
        {
            // Bail out to avoid accessing the empty queue array
            return;
        }

        // Keep moving where we start pushing to spread between queues
        m_PushIndex++; // May need to reset to avoid possible integer overflow?

        // Run through queues to see if any are available for a push
        for (size_t queueIndex = 0;
            queueIndex != m_Queues.size() * ROUNDS;
            ++queueIndex)
        {
            if (m_Queues[(m_PushIndex + queueIndex) %
                m_Queues.size()].TryPush(std::move(result)))
            {
                return;
            }
        }

        // All queues are busy, just wait until free;
        m_Queues[m_PushIndex % m_Queues.size()].Push(std::move(result));
    }

    ProfPool(const std::string& file_path = "", bool profiling_enabled = true,
        size_t num_threads = 4)
        : m_Process_ID(std::string(program_invocation_name) +
            "_" +
            std::to_string(_getpid())),
        m_Profile_File_Name(file_path + m_Process_ID + JSON_EXT), m_PushIndex(0),
        m_NumQueues(num_threads), m_Queues(m_NumQueues),
        m_Ready(profiling_enabled),
        m_Profile_JSON(m_Profile_File_Name, std::ofstream::trunc)
    {
        if (!profiling_enabled)
        {
            return;
        }

        WriteHeader();

        m_Writers.reserve(m_NumQueues); // avoid copy constructors
        std::stringstream profile_name;
        DWORD pid = _getpid();
        for (size_t writer_index = 0; writer_index < m_NumQueues; writer_index++)
        {
            profile_name
                << file_path
                << m_Process_ID
                << "_"
                << writer_index
                << JSON_EXT;

            m_Writers.emplace_back(profile_name.str(), writer_index);
            profile_name.str("");
        }

        for (ProfileWriter& writer : m_Writers)
        {
            writer.Start(&m_Queues);
        }
    }

    inline std::string ProcessName() { return m_Process_ID; }

    ~ProfPool()
    {
        if (m_Ready)
        {
            Stop();
            WriteProfileData();
            WriteFooter();
            m_Profile_JSON.close();
        }
    }

    void WriteHeader()
    {
        m_Profile_JSON << "{\"otherData\": {},\"traceEvents\":\n    [";
        m_Profile_JSON.flush();
    }


    void WriteProfileData()
    {
        bool first_line = true;

        for (ProfileWriter& writer : m_Writers)
        {
            if (!first_line)
            {
                m_Profile_JSON << ",";
            }
            first_line = false;
            m_Profile_JSON << writer;

            // Flush data in case of crash we have it
            m_Profile_JSON.flush();
        }
    }

    void WriteFooter()
    {
        /* If the program dies before this can be called,
           "]}" can just be manually added to the end of the json file
        */

        m_Profile_JSON << "\n    ]\n}";
    }

    void Stop()
    {
        // Must be done before we stop writers
        for (ProfQueue& queue : m_Queues)
        {
            queue.done();
        }

        for (ProfileWriter& writer : m_Writers)
        {
            writer.Stop();
        }
    }

    static ProfPool& Instance()
    {
        /* Singleton instance*/
        static ProfPool instance;
        return instance;
    }

private:
    ProfPool(const ProfPool&);
    ProfPool& operator=(const ProfPool&) {}

private:
    std::string m_Process_ID;
    std::string m_Profile_File_Name;
    std::ofstream m_Profile_JSON;
    size_t m_PushIndex;
    size_t m_NumQueues;
    std::vector<ProfileWriter> m_Writers;
    std::vector<ProfQueue> m_Queues;
    bool m_Ready;
};

// Probe for timing - Starts at construction and stops on destruction
class Timer
{

public:
    Timer(const char* name)
        :m_Name(name), m_Start(now())
    {
        // Introduce timer delays so we can test optimizations
        // Delay everything except function you want to see if an
        // optimization would work.
    }

    ~Timer()
    {
        // Stop in destructor to measure full function time
        Stop();
    }


private:

    // Windows port of clock_gettime()
    struct timespec { __int64 tv_sec; __int64 tv_nsec; };    //header part
    int clock_gettime(struct timespec* spec)      //C-file part
    {
        __int64 wintime = 0i64;
        GetSystemTimeAsFileTime((FILETIME*)&wintime);
        wintime -= 116444736000000000i64;  //1jan1601 to 1jan1970
        spec->tv_sec = wintime / 10000000i64;           //seconds
        spec->tv_nsec = wintime % 10000000i64 * 100;      //nano-seconds
        return 0;
    }

    void Stop()
    {
        nanosec end_time = now();
        // The process name is static so we set it here
        static std::string processName = ProfPool::Instance().ProcessName();

        // This is Windows specific!!
        DWORD threadID = GetCurrentProcessId();

        ProfileResult result = ProfileResult(m_Name, m_Start, end_time,
            threadID, processName);

        ProfPool::Instance().Log(std::move(result));
    }

    nanosec now()
    {
        nanosec nano_seconds = 0; // If unchanged then indicates error
        struct timespec ts;
        int return_code = clock_gettime(&ts);

        if (-1 != return_code)
        {
            nano_seconds = (static_cast<nanosec>(ts.tv_sec) * 1000000000i64) +
                static_cast<nanosec>(ts.tv_nsec);
        }

        return nano_seconds;
    }

    const std::string m_Name;
    nanosec m_Start;
};

#endif