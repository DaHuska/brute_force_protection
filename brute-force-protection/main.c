#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "user.c"

int parse_user(const char *line, struct User *user) {
    return sscanf(line, " %19[^-] - %15s", user->username, user->ip_addr) == 2;
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

    int count = 0;
    char buff[256];

    while (fgets(buff, sizeof(buff), fp) != NULL) {
        buff[strcspn(buff, "\n")] = '\0';

        if (parse_user(buff, &users[count])) {
            count++;

            struct User *temp_users;
            temp_users = realloc(users, sizeof(struct User) * count);

            if (temp_users == NULL) {
                perror("Couldnt reallocate memory!");
                return 1;
            }

            users = temp_users;
        }
    }

    fclose(fp);

    for (int i = 0; i < count; i++) {
        printf("User %s - %s\n", users[i].username, users[i].ip_addr);
    }

    free(users);
    return 0;
}
