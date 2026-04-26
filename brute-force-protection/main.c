#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "user.c"
#include "login_ip.c"

int validateCreds(struct User *users, int size, char *username, char *password) {
    for (int i = 0; i < size; ++i) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return 1;
        }
    }

    return 0;
}

int check_brute_force(struct login_ip *lip) {
    //TODO: rework return value
    if (lip->failed_attempts >= 10) {
        return 1;
    } else if (lip->failed_attempts >= 5) {
        return 2;
    }

    return 0;
}

void block_ip(struct login_ip *lip) {
    FILE *fp = fopen("/home/mint/CLionProjects/brute-force-protection/blocked_ips.txt", "a");

    if (fp == NULL) {
        perror("Couldnt open blocked_ips.txt");
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char date[20];
    strftime(date, sizeof(date), "%d-%m-%Y", t);

    fprintf(fp, "%s: %s has been blocked!\n", date, lip->ip_addr);

    lip->is_blocked = 1;
    strcpy(lip->status, "blocked");

    printf("IP address %s has been blocked!", lip->ip_addr);

    fclose(fp);
}

void login(struct User *users, struct login_ip *lip, int size) {
    char ip_addr[16];
    char username[20];
    char password[20];

    scanf(" %15[^-] - %19[^:]:%19s", ip_addr, username, password);

    // Read structs from registered login IPs
    lip = malloc(sizeof(struct login_ip));

    strcpy(lip->ip_addr, ip_addr);
    lip->failed_attempts = 0;
    lip->is_blocked = 0;

    // Validate credentials
    if (validateCreds(users, size, username, password)) {
        printf("Login successful!\n");
    } else {
        lip->failed_attempts++;

        if (check_brute_force(lip) == 1) {
            block_ip(lip);
        } else {
            // set warning
        }

        printf("Failed attempt!\n");
    }

    printf("%s %s %s\n", ip_addr, username, password);

    free(lip);
    lip = NULL;
}

int parse_user(const char *user_ip_buff, const char *user_creds_buff, struct User *user) {
    int r1 = sscanf(user_ip_buff, " %19[^@]@%15s", user->username, user->ip_addr);
    int r2 = sscanf(user_creds_buff, " %19[^:]:%19s", user->username, user->password);

    return r1 + r2 == 4;
}

int main(void) {
    // Read users file
    FILE *uip = fopen("/home/mint/CLionProjects/brute-force-protection/user_ip.txt", "r");
    FILE *ucr = fopen("/home/mint/CLionProjects/brute-force-protection/user_credentials.txt", "r");

    if (uip == NULL) {
        perror("File could not be read!");
        return 1;
    }

    if (ucr == NULL) {
        perror("File could not be read!");
        return 1;
    }

    struct login_ip *lip;
    struct User *users;
    users = malloc(sizeof(struct User));

    if (users == NULL) {
        perror("Couldnt allocate memory!");
        return 1;
    }

    int count = 1;
    int index = 0;
    char user_ip_buff[64];
    char user_creds_buff[64];

    while (fgets(user_ip_buff, sizeof(user_ip_buff), uip) != NULL) {
        fgets(user_creds_buff, sizeof(user_creds_buff), ucr);

        user_ip_buff[strcspn(user_ip_buff, "\n")] = '\0';
        user_creds_buff[strcspn(user_creds_buff, "\n")] = '\0';

        if (parse_user(user_ip_buff, user_creds_buff, &users[index])) {
            count++;

            struct User *temp_users;
            temp_users = realloc(users, sizeof(struct User) * count);

            if (temp_users == NULL) {
                perror("Couldnt reallocate memory!");
                return 1;
            }

            users = temp_users;
            index++;

            memset(user_ip_buff, '\0', sizeof(user_ip_buff));
            temp_users = NULL;
        }
    }

    fclose(uip);
    fclose(ucr);

    login(users, lip, count);

    for (int i = 0; i < count - 1; i++) {
        printf("User %s - %s\n", users[i].username, users[i].ip_addr);
    }

    free(users);
    users = NULL;

    return 0;
}
