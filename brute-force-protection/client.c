#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/login_ipc_socket"

static void trim_newline(char *s) { s[strcspn(s, "\r\n")] = '\0'; }

static int connect_socket(void) {
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un addr;
    (void) memset(&addr, 0U, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void) strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1U);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        (void) close(fd);
        exit(1);
    }
    return fd;
}

static void send_request(const char *request) {
    const int fd = connect_socket();
    (void) write(fd, request, strlen(request));
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1U);

    if (n > 0) {
        buf[n] = '\0';
        printf("%s\n", buf);
    }

    (void) close(fd);
}

int main(void) {
    int choice;
    while (1) {
        (void) printf("\n1. Login\n2. Admin: list blocked IPs\n3. Exit\nChoice: ");
        if (scanf("%d", &choice) != 1) {
            return 0;
        }

        (void) getchar();

        if (choice == 1) {
            char ip[16], username[32], password[32], request[128];
            (void) printf("IP: ");
            (void) fgets(ip, sizeof(ip), stdin);
            trim_newline(ip);
            (void) printf("Username: ");
            (void) fgets(username, sizeof(username), stdin);
            trim_newline(username);
            (void) printf("Password: ");
            (void) fgets(password, sizeof(password), stdin);
            trim_newline(password);

            (void) snprintf(request, sizeof(request),
                            "LOGIN %s %s %s", ip, username, password);

            send_request(request);
        } else if (choice == 2) {
            char username[32], password[32], request[128], role[10];
            (void) printf("\nEnter your admin credentials to access blocked IPs:\n");
            (void) printf("Username: ");
            (void) fgets(username, sizeof(username), stdin);
            trim_newline(username);
            (void) printf("Password: ");
            (void) fgets(password, sizeof(password), stdin);
            trim_newline(password);

            (void) snprintf(request, sizeof(request),
                            "LOGIN %s %s %s", "dummy_ip", username, password);
            send_request(request);
            (void) printf("Checking for admin access...\n");
            send_request("ADMIN LIST");
        } else if (choice == 3) {
            break;
        }
    }
    return 0;
}