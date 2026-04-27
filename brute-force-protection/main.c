#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/login_ipc_socket"
#define USERS_IP_FILE "user_ip.txt"
#define USERS_PASSWORD_FILE "user_credentials.txt"
#define BLOCKED_IPS_FILE "blocked_ips.txt"

#define MAX_USERS 100
#define MAX_IPS 100

#include "user.c"
#include "ip_login_entry.c"

struct User users[MAX_USERS];
int user_count = 0;

struct IPLoginEntry ips[MAX_IPS];
int ip_count = 0;

// Function to trim newline characters from user input
void trim_newline(char *s) {
    s[strcspn(s, "\r\n")] = '\0';
}

void load_users() {
    FILE *f_ip = fopen(USERS_IP_FILE, "r");
    FILE *f_pass = fopen(USERS_PASSWORD_FILE, "r");

    if (f_ip == 0 || f_pass == 0) {
        perror("Error opening user files");
        exit(1);
    }

    char line1[64], line2[64];
    while (fgets(line1, sizeof(line1), f_ip) && fgets(line2, sizeof(line2), f_pass)) {
        line1[strcspn(line1, "\n")] = 0;
        line2[strcspn(line2, "\n")] = 0;

        char user1[20], user2[20], role[10];

        if (sscanf(line1, "%19[^@]@%15s %9s", user1, users[user_count].ip_addr, role) == 3 &&
            sscanf(line2, "%19[^:]:%19s", user2, users[user_count].password) == 2 &&
            strcmp(user1, user2) == 0) {

            strcpy(users[user_count].username, user1);
            strcpy(users[user_count].role, role);  // Store the role
            user_count++;
        }
    }

    fclose(f_ip);
    fclose(f_pass);
}

int validateCreds(char *username, char *password, char *role) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            strcpy(role, users[i].role);
            return 1;
        }
    }
    return 0;
}

struct IPLoginEntry* get_ip(const char *ip) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ips[i].ip_addr, ip) == 0)
            return &ips[i];
    }

    if (ip_count < MAX_IPS) {
        strcpy(ips[ip_count].ip_addr, ip);
        strcpy(ips[ip_count].status, "active");
        ips[ip_count].failed_attempts = 0;
        ips[ip_count].is_blocked = 0;
        return &ips[ip_count++];
    }

    return NULL;
}

void block_ip(struct IPLoginEntry *ip) {
    ip->is_blocked = 1;
    strcpy(ip->status, "blocked");

    FILE *f = fopen(BLOCKED_IPS_FILE, "a");
    if (f) {
        fprintf(f, "%s\n", ip->ip_addr);
        fclose(f);
    }
}

void handle_login(int client_fd, char *ip, char *user, char *pass) {
    struct IPLoginEntry *entry = get_ip(ip);
    char role[10];

    if (entry == 0) {
        write(client_fd, "ERROR", 5);
        return;
    }

    if (entry->is_blocked == 1) {
        write(client_fd, "YOU CANNOT PERFORM ACTION", 25);
        return;
    }

    // Validate credentials
    if (validateCreds(user, pass, role) == 1) {
        entry->failed_attempts = 0;
        write(client_fd, "SUCCESS", 7);
    } else {
        entry->failed_attempts++;

        if (entry->failed_attempts >= 10) {
            block_ip(entry);
            write(client_fd, "BLOCKED", 7);
        } else if (entry->failed_attempts >= 5) {
            write(client_fd, "SUSPICIOUS", 10);
        } else {
            write(client_fd, "FAILED", 6);
        }
    }
}

void handle_admin(int client_fd, char *role) {
    if (strcmp(role, "admin") != 0) {
        write(client_fd, "ACCESS DENIED", 13);
        return;
    }

    char buffer[1024] = "";

    for (int i = 0; i < ip_count; i++) {
        if (ips[i].is_blocked) {
            strcat(buffer, ips[i].ip_addr);
            strcat(buffer, "\n");
        }
    }

    if (strlen(buffer) == 0)
        strcpy(buffer, "No blocked IPs");

    write(client_fd, buffer, strlen(buffer));
}

void handle_client(int client_fd) {
    char buf[256];
    int n = read(client_fd, buf, sizeof(buf) - 1);

    if (n <= 0) return;

    buf[n] = '\0';

    if (strncmp(buf, "LOGIN", 5) == 0) {
        char ip[16], user[32], pass[32];
        sscanf(buf, "LOGIN %15s %31s %31s", ip, user, pass);
        handle_login(client_fd, ip, user, pass);
    } else if (strncmp(buf, "ADMIN LIST", 10) == 0) {
        char user[32], pass[32], role[10];
        sscanf(buf, "LOGIN %31s %31s", user, pass);

        if (validateCreds(user, pass, role) == 1) {
            handle_admin(client_fd, role);
        }

        //
        // printf("Enter admin credentials:\n");
        // printf("Username: ");
        // fgets(username, sizeof(username), stdin);
        // trim_newline(username);
        // printf("Password: ");
        // fgets(password, sizeof(password), stdin);
        // trim_newline(password);

        // Validate the admin credentials here
        // if (validateCreds(username, password, role)) {
        //     handle_admin(client_fd, role);
        // } else {
        //     write(client_fd, "INVALID ADMIN CREDENTIALS", 25);
        // }
    } else {
        write(client_fd, "UNKNOWN COMMAND", 15);
    }
}

int main() {
    load_users();

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    unlink(SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    listen(server_fd, 5);

    printf("Server running...\n");

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        handle_client(client_fd);
        close(client_fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}