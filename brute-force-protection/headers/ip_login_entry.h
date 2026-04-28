#ifndef IP_LOGIN_ENTRY_H
#define IP_LOGIN_ENTRY_H

struct IPLoginEntry {
    char ip_addr[16];
    char status[10];
    int failed_attempts;
    int is_blocked;
};

#endif