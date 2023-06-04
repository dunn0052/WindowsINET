#pragma once
#ifndef HOOK_HH
#define HOOK_HH
#include <vector>
#include <algorithm>
#include <functional>

/* EXAMPLE */

/*

 class ExampleHookDelegateClass
 {
     void ExampleClassHookFunction(const std::string& arg1, int arg2)
     {
         std::cout << "arg1: " << arg1 << " arg2: " << arg2 << "\n";
     }
 }

 void ExampleStaticHookFunction(const std::string& arg1, int arg2)
 {
     std::cout << "arg1: " << arg1 << " arg2: " << arg2 << "\n";
 }

 Hook<const std::string&, int> example_hook;

 example_hook += ExampleStaticHookFunction;

 ExampleHookDelegateClass example; // class instance

 // Encapuslate call with lambda function as the signature for the
 // class function cannot be captured directly (as far as I know)
 example_hook += [&](const std::string& arg1, int arg2){ example.ExampleClassHookFunction(arg1, arg2); };

*/

template <typename...EventArgs>
class Hook
{

public:

    Hook() {}
    ~Hook() {}

    using DelegateType = std::function<void(EventArgs...)>;

    void operator()(EventArgs...args)
    {
        for (DelegateType& delegate : m_Delegates)
        {
            delegate(args...);
        }
    }

    void Clear()
    {
        m_Delegates.clear();
    }

    void operator +=(DelegateType&& delegate)
    {
        m_Delegates.push_back(std::move(delegate));
    }

    void operator -=(DelegateType& delegate)
    {
        m_Delegates.erase(std::move(m_Delegates.begin(), m_Delegates.end(), delegate),
            m_Delegates.end());
    }

private:
    std::vector<DelegateType> m_Delegates;
};

#endif