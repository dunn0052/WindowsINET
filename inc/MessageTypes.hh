#pragma once
#ifndef __MESSAGE_TYPES_HH
#define __MESSAGE_TYPES_HH

enum MESSAGE_TYPE
{
    NONE = 0, // Empty (ping)
    TEXT, // Value contains text to be read
    ACK, // An acknowledge that connection succeeded
    DB_READ, // Message with object values
    DB_WRITE // Message meant to have write data
};

#endif