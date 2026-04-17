#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "user.c"

int validateCreds(struct User *users, int size, char *username, char *password) {
    for (int i = 0; i < size; ++i) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return 1;
        }
    }

    return 0;
}

void login(struct User *users, int size) {
    char ip_addr[16];
    char username[20];
    char password[20];

    scanf(" %15[^-] - %19[^:]:%19s", ip_addr, username, password);

    // Validate credentials
    if (validateCreds(users, size, username, password)) {
        printf("Login successful!\n");
    } else {
        printf("Failed attempt!\n");
    }

    printf("%s %s %s\n", ip_addr, username, password);
}

int parse_user(const char *line, struct User *user) {
    return sscanf(line, " %15[^-] - %19[^:]:%19s", user->ip_addr, user->username, user->password) == 3;
}

int main(void) {
    // Read users file
    FILE *fp = fopen("/home/mint/CLionProjects/brute-force-protection/users.txt", "r");

    if (fp == NULL) {
        perror("File could not be read!");
        return 1;
    }

    struct User *users;
    users = malloc(sizeof(struct User));

    if (users == NULL) {
        perror("Couldnt allocate memory!");
        return 1;
    }

    int count = 1;
    int index = 0;
    char buff[64];

    while (fgets(buff, sizeof(buff), fp) != NULL) {
        buff[strcspn(buff, "\n")] = '\0';

        if (parse_user(buff, &users[index])) {
            count++;

            struct User *temp_users;
            temp_users = realloc(users, sizeof(struct User) * count);

            if (temp_users == NULL) {
                perror("Couldnt reallocate memory!");
                return 1;
            }

            users = temp_users;
            index++;
            
            memset(buff, '\0', sizeof(buff));
            temp_users = NULL;
        }
    }

    fclose(fp);

    login(users, count);

    for (int i = 0; i < count - 1; i++) {
        printf("User %s - %s\n", users[i].username, users[i].ip_addr);
    }

    free(users);
    users = NULL;

    return 0;
}
