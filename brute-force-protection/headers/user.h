#ifndef USER_H
#define USER_H

struct User {
    char username[20];
    char password[20];
    char ip_addr[16];
    char role[10];
};

#endif