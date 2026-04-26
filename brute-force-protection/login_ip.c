struct login_ip {
    char ip_addr[16];
    char status[7];
    int failed_attempts;
    int is_blocked;
};
