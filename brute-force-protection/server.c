#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/login_ipc_socket"
#define USERS_IP_FILE "users_info/user_ip.txt"
#define USERS_PASSWORD_FILE "users_info/user_credentials.txt"
#define BLOCKED_IPS_FILE "system_actions/blocked_ips.txt"

#define MAX_USERS 100U
#define MAX_IPS 100U

#include "headers/user.h"
#include "headers/ip_login_entry.h"

static struct User users[MAX_USERS];
static int user_count = 0;

static struct IPLoginEntry ips[MAX_IPS];
static int ip_count = 0;

static void trim_newline(char *s) {
    s[strcspn(s, "\r\n")] = '\0';
}

static void load_users() {
    FILE *f_ip = fopen(USERS_IP_FILE, "r");
    FILE *f_pass = fopen(USERS_PASSWORD_FILE, "r");

    if (f_ip == 0 || f_pass == 0) {
        perror("Error opening user files");
        exit(1U);
    }

    char buff_a[64U], buff_b[64U];
    while ((fgets(buff_a, sizeof(buff_a), f_ip) != NULL) &&
           (fgets(buff_b, sizeof(buff_b), f_pass) != NULL)) {

        buff_a[strcspn(buff_a, "\n")] = '\0';
        buff_b[strcspn(buff_b, "\n")] = '\0';

        char user_a[20U], user_b[20U], role[10U];

        if ((sscanf(buff_a, "%19[^@]@%15s %9s", user_a, users[user_count].ip_addr, role) == 3) &&
            (sscanf(buff_b, "%19[^:]:%19s", user_b, users[user_count].password) == 2) &&
            (strcmp(user_a, user_b) == 0)) {

            (void)strcpy(users[user_count].username, user_a);
            (void)strcpy(users[user_count].role, role);
            user_count++;
        }
    }

    (void)fclose(f_ip);
    (void)fclose(f_pass);
}

static int validateCreds(const char *username, const char *password, char *role) {
    for (int i = 0; i < user_count; i++) {
        if ((strcmp(users[i].username, username) == 0) &&
            (strcmp(users[i].password, password) == 0)) {
            (void)strcpy(role, users[i].role);
            return 1U;
        }
    }
    return 0U;
}

static struct IPLoginEntry* get_ip(const char *ip) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ips[i].ip_addr, ip) == 0) {
            return &ips[i];
        }
    }

    if (ip_count < (int)MAX_IPS) {
        (void)strcpy(ips[ip_count].ip_addr, ip);
        (void)strcpy(ips[ip_count].status, "active");
        ips[ip_count].failed_attempts = 0U;
        ips[ip_count].is_blocked = 0U;

        return &ips[ip_count++];
    }

    return NULL;
}

static void block_ip(struct IPLoginEntry *ip) {
    ip->is_blocked = 1U;
    (void)strcpy(ip->status, "blocked");

    FILE *f = fopen(BLOCKED_IPS_FILE, "a");
    if (f != NULL) {
        (void)fprintf(f, "%s\n", ip->ip_addr);
        (void)fclose(f);
    }
}

static void handle_login(const int client_fd, const char *ip, const char *user, const char *pass) {
    struct IPLoginEntry *entry = get_ip(ip);
    char role[10U];

    if (entry == NULL) {
        (void)write(client_fd, "ERROR", 5U);
        return;
    }

    if (entry->is_blocked == 1U) {
        (void)write(client_fd, "YOU CANNOT PERFORM ACTION", 25U);
        return;
    }

    if (validateCreds(user, pass, role) == 1U) {
        entry->failed_attempts = 0U;
        (void)write(client_fd, "SUCCESS", 7U);
    } else {
        entry->failed_attempts++;

        if (entry->failed_attempts >= 10U) {
            block_ip(entry);
            (void)write(client_fd, "BLOCKED", 7U);
        } else if (entry->failed_attempts >= 5U) {
            (void)write(client_fd, "SUSPICIOUS", 10U);
        } else {
            (void)write(client_fd, "FAILED", 6U);
        }
    }
}

static void handle_admin(const int client_fd, const char *role) {
    if (strcmp(role, "admin") != 0) {
        (void)write(client_fd, "ACCESS DENIED", 13U);
        return;
    }

    char buffer[1024] = "";

    for (int i = 0; i < ip_count; i++) {
        if (ips[i].is_blocked != 0U) {
            (void)strcat(buffer, ips[i].ip_addr);
            (void)strcat(buffer, "\n");
        }
    }

    if (strlen(buffer) == 0U) {
        (void)strcpy(buffer, "No blocked IPs");
    }

    (void)write(client_fd, buffer, strlen(buffer));
}

static void handle_client(int client_fd) {
    char buf[256];
    int n = read(client_fd, buf, sizeof(buf) - 1U);

    if (n <= 0) {
        return;
    }

    buf[n] = '\0';

    if (strncmp(buf, "LOGIN", 5U) == 0) {
        char ip[16], user[32], pass[32];
        (void)sscanf(buf, "LOGIN %15s %31s %31s", ip, user, pass);
        handle_login(client_fd, ip, user, pass);
    } else if (strncmp(buf, "ADMIN LIST", 10U) == 0) {
        char user[32], pass[32], role[10];
        (void)sscanf(buf, "LOGIN %31s %31s", user, pass);

        if (validateCreds(user, pass, role) == 1U) {
            handle_admin(client_fd, role);
        }
    } else {
        (void)write(client_fd, "UNKNOWN COMMAND", 15U);
    }
}

int main() {
    load_users();

    const int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    (void)unlink(SOCKET_PATH);

    (void)memset(&addr, 0U, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strcpy(addr.sun_path, SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    (void)listen(server_fd, 5U);

    printf("Server running...\n");

    while (1) {
        const int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }

        handle_client(client_fd);
        (void)close(client_fd);
    }

    (void)close(server_fd);
    (void)unlink(SOCKET_PATH);
    return 0;
}