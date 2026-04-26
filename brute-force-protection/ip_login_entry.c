struct IPLoginEntry {
    char ip_addr[16];
    int failed_attempts;
    int suspicious;
    int blocked;
};
