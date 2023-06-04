#pragma once
#ifndef DAEMON_THREAD_HH
#define DAEMON_THREAD_HH

#include <future>
#include <chrono>

/*
 * Class that encapsulates promise and future object and
 * provides API to set exit signal for the thread
 */
template <typename... ARGS>
class DaemonThread
{
    bool m_Running;
    std::thread* m_RunningThread;
    std::promise<void> m_exitSignal;
    std::future<void> m_futureObj;

public:
    DaemonThread() :
        m_Running(false), m_RunningThread(nullptr), m_futureObj(m_exitSignal.get_future())
    { }

    DaemonThread(DaemonThread&& obj)
        : m_Running(std::move(obj.m_Running)), m_RunningThread(std::move(obj.m_RunningThread)), m_exitSignal(std::move(obj.m_exitSignal)), m_futureObj(std::move(obj.m_futureObj))
    { }

    DaemonThread& operator=(DaemonThread&& obj)
    {
        m_exitSignal = std::move(obj.m_exitSignal);
        m_futureObj = std::move(obj.m_futureObj);
        m_Running = std::move(obj.m_Running);
        m_RunningThread = std::move(obj.m_RunningThread);
        return *this;
    }

    // Task need to provide definition for this function
    // It will be called by thread function
    virtual void execute(ARGS... args) = 0;

    // Thread function to be executed by thread
    void operator()()
    {
        if (!m_Running)
        {
            return;
        }

        execute();
    }

    void Start(ARGS... args)
    {

        if (m_Running)
        {
            return;
        }

        m_RunningThread = new std::thread([this, args...]()
        {
            this->execute(args...);
        });

        m_Running = true;
    }

    //Checks if thread is requested to stop
    bool StopRequested()
    {
        // checks if value in future object is available
        if (m_futureObj.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout)
        {
            return false;
        }

        return true;
    }

    // Request the thread to stop by setting value in promise object
    void Stop()
    {
        if (m_Running)
        {
            m_Running = false;
            // Issues signal for execute() to stop
            m_exitSignal.set_value();
            m_RunningThread->join();
            if (nullptr != m_RunningThread)
            {
                delete m_RunningThread;
                m_RunningThread = nullptr;
            }

        }
    }
};

#endif