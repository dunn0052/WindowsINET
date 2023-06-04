#pragma once
#ifndef __TASQ_HH
#define __TASQ_HH

#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include "DaemonThread.hh"

template <class Key, class Element>
class TasM
{
private:
    std::unordered_map<Key, Element> m_ElementMap;
    bool m_Done;
    std::mutex n_Mutex;
    std::condition_variable n_ReadyCondition;

public:
    TasM()
        : m_ElementMap(), m_Done(false), n_Mutex(), n_ReadyCondition()
    {
    }

    void done()
    {
        n_Mutex.lock();
        m_Done = true;
        n_Mutex.unlock();

        n_ReadyCondition.notify_all();
    }

    bool Get(Key& key, Element& result)
    {
        std::unique_lock lock = std::unique_lock{ n_Mutex };
        while (m_ElementMap.find(key) == m_ElementMap.end() && !m_Done)
        {
            n_ReadyCondition.wait(lock);
        }

        if (m_ElementMap.find(key) == m_ElementMap.end())
        {
            return false;
        }

        result = m_ElementMap.at(key);

        return true;
    }

    bool TryGet(Key& key, Element& result)
    {

        if (!n_Mutex.try_lock())
        {
            return false;
        }

        if (m_ElementMap.find(key) == m_ElementMap.end())
        {
            n_Mutex.unlock();
            return false;
        }

        result = m_ElementMap.at(key);

        n_Mutex.unlock();

        return true;
    }

    void Put(Key& key, Element& result)
    {
        n_Mutex.lock();
        m_ElementMap.emplace(key, result);
        n_Mutex.unlock();

        n_ReadyCondition.notify_one();
    }

    bool TryPut(Key& key, Element& result)
    {
        if (!n_Mutex.try_lock())
        {
            return false;
        }

        m_ElementMap.emplace(key, result);

        n_Mutex.unlock();
        n_ReadyCondition.notify_one();
        return true;
    }
};

template <class Element>
class TasQ
{
private:
    std::queue<Element> m_ResultQueue;
    bool m_Done;
    std::mutex n_Mutex;
    std::condition_variable n_ReadyCondition;

public:
    TasQ()
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

    bool Pop(Element& result)
    {
        std::unique_lock lock = std::unique_lock{ n_Mutex };
        while (m_ResultQueue.empty() && !m_Done)
        {
            n_ReadyCondition.wait(lock);
        }

        if (m_ResultQueue.empty())
        {
            return false;
        }

        result = std::move(m_ResultQueue.front());
        m_ResultQueue.pop();

        return true;
    }

    bool TryPop(Element& result)
    {

        if (!n_Mutex.try_lock())
        {
            return false;
        }

        if (m_ResultQueue.empty())
        {
            n_Mutex.unlock();
            return false;
        }

        result = std::move(m_ResultQueue.front());
        m_ResultQueue.pop();

        n_Mutex.unlock();

        return true;
    }

    void Push(Element& result)
    {
        n_Mutex.lock();
        m_ResultQueue.push(result);
        n_Mutex.unlock();

        n_ReadyCondition.notify_one();
    }

    bool TryPush(Element& result)
    {
        if (!n_Mutex.try_lock())
        {
            return false;
        }

        m_ResultQueue.push(result);

        n_Mutex.unlock();
        n_ReadyCondition.notify_one();
        return true;
    }
};

#if 0
template <class Element>
class TaskWorker : public DaemonThread<std::vector<TasQ<Element>>*>
{

private:
    size_t worker_id;
    bool m_Running;

    TaskWorker& operator=(const TaskWorker&);

public:

    TaskWorker(const TaskWorker&) { }

    void execute(std::vector<TasQ<Element>>* results_queue)
    {

        Element result;
        result.m_End = 0;
        std::vector<TasQ<Element>>& queue = *results_queue;

        while (!StopRequested())
        {
            // Steal tasks
            for (size_t queueIndex = 0; queueIndex != queue.size(); ++queueIndex)
            {
                if (queue[(queueIndex + worker_id) %
                    queue.size()].TryPop(result))
                {
                    break;
                }
            }

            // Otherwise wait for ours
            if (!result.m_End && !queue[worker_id].Pop(result))
            {
                // Once done, just wait for the thread to be stopped
                continue;
            }

            PerformTask(result);
        }

        // If we stopped before our queue is empty then
        while (queue[worker_id].Pop(result))
        {
            PerformTask(result);
        }

        m_json_stream.close();
    }

    TaskWorker(size_t writer_id)
        : worker_id(writer_id), m_Running(false)
    {
    }

    ~TaskWorker()
    {
    }

    void PerformTask(const Element& result)
    {
    }

};

template <class Element>
class TasqPool
{
    static constexpr size_t ROUNDS = 3;
public:

    // Could try to make this async
    void PushTask(Element&& result)
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

    TasqPool(const std::string& file_path = "", bool enabled = true,
        size_t num_threads = 4)
        : m_PushIndex(0), m_NumQueues(num_threads), m_Queues(m_NumQueues),
        m_Ready(enabled),
    {
        if (!enabled)
        {
            return;
        }

        m_Workers.reserve(m_NumQueues); // avoid copy constructors
        for (size_t worker_id = 0; worker_id < m_NumQueues; worker_id++)
        {
            m_Workers.emplace_back(worker_id);
        }

        for (TaskWorker& worker : m_Workers)
        {
            worker.Start(&m_Queues);
        }
    }

        ~TasqPool()
    {
        if (m_Ready)
        {
            Stop();
        }
    }

    void Stop()
    {
        // Must be done before we stop writers
        for (TasQ& queue : m_Queues)
        {
            queue.done();
        }

        for (TaskWorker& writer : m_Workers)
        {
            writer.Stop();
        }
    }

    static TasqPool& Instance()
    {
        /* Singleton instance*/
        static TasqPool instance;
        return instance;
    }

private:
    TasqPool(const TasqPool&);
    TasqPool& operator=(const TasqPool&);

private:
    size_t m_PushIndex;
    size_t m_NumQueues;
    std::vector<TaskWorker> m_Workers;
    std::vector<TasQ> m_Queues;
    bool m_Ready;
};

#endif
#endif