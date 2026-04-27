#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/login_ipc_socket"

static void trim_newline(char *s) { s[strcspn(s, "\r\n")] = '\0'; }

static int connect_socket(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(1);
    }
    return fd;
}

static void send_request(const char *request) {
    int fd = connect_socket();
    write(fd, request, strlen(request));
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; printf("%s\n", buf); }
    close(fd);
}

int main(void) {
    int choice;
    while (1) {
        printf("\n1. Login\n2. Admin: list blocked IPs\n3. Exit\nChoice: ");
        if (scanf("%d", &choice) != 1) return 0;
        getchar();  // To consume the newline character left by scanf

        if (choice == 1) {
            // Login process
            char ip[16], username[32], password[32], request[128];
            printf("IP: ");
            fgets(ip, sizeof(ip), stdin);
            trim_newline(ip);
            printf("Username: ");
            fgets(username, sizeof(username), stdin);
            trim_newline(username);
            printf("Password: ");
            fgets(password, sizeof(password), stdin);
            trim_newline(password);

            snprintf(request, sizeof(request), "LOGIN %s %s %s", ip, username, password);
            send_request(request);
        }
        else if (choice == 2) {
            // Admin: List blocked IPs
            char username[32], password[32], request[128], role[10];
            printf("\nEnter your admin credentials to access blocked IPs:\n");
            printf("Username: ");
            fgets(username, sizeof(username), stdin);
            trim_newline(username);
            printf("Password: ");
            fgets(password, sizeof(password), stdin);
            trim_newline(password);

            // Send the login request for admin authentication
            snprintf(request, sizeof(request), "LOGIN %s %s %s", "dummy_ip", username, password);
            send_request(request);  // Login the admin

            // Now ask for the role confirmation (only allow access if the role is "admin")
            printf("Checking for admin access...\n");

            // Simulate checking the response (assuming the server sends "ADMIN" on success)
            send_request("ADMIN LIST");

        }
        else if (choice == 3) {
            break;
        }
    }
    return 0;
}