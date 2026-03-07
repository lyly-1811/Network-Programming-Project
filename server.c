#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define PORT 8888 // Đổi sang cổng 8888
#define GOOGLE_DNS "8.8.8.8"
#define DNS_PORT 53
#define BUF_SIZE 2048
#define CACHE_SIZE 100

typedef struct {
    char domain[256];
    char ip[INET_ADDRSTRLEN];
    time_t expire_time;
    int is_nxdomain; 
} CacheEntry;

CacheEntry cache[CACHE_SIZE];
int cache_count = 0;

struct DNS_HEADER {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

void format_dns_name(unsigned char* dns, unsigned char* host) {
    int lock = 0, i;
    strcat((char*)host, ".");
    for (i = 0; i < strlen((char*)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int check_cache(const char* domain, char* result_ip, int* remaining_ttl, int* is_nx) {
    time_t now = time(NULL);
    for (int i = 0; i < cache_count; i++) {
        if (strcmp(cache[i].domain, domain) == 0) {
            if (now < cache[i].expire_time) {
                *remaining_ttl = (int)(cache[i].expire_time - now);
                *is_nx = cache[i].is_nxdomain;
                if (!*is_nx) strcpy(result_ip, cache[i].ip);
                return 1;
            }
        }
    }
    return 0; 
}

void add_to_cache(const char* domain, const char* ip, int ttl, int is_nx) {
    if (cache_count >= CACHE_SIZE) cache_count = 0; 
    strcpy(cache[cache_count].domain, domain);
    cache[cache_count].is_nxdomain = is_nx;
    if (!is_nx) strcpy(cache[cache_count].ip, ip);
    cache[cache_count].expire_time = time(NULL) + ttl;
    cache_count++;
}

void resolve_dns(char* domain, char* response_msg) {
    char ip_result[INET_ADDRSTRLEN];
    int rem_ttl = 0, is_nx = 0;

    if (check_cache(domain, ip_result, &rem_ttl, &is_nx)) {
        printf("[DEBUG] Phục vụ từ Cache.\n");
        if (is_nx) {
            snprintf(response_msg, BUF_SIZE, "Error: NXDOMAIN '%s' does not exist.\nSource: Cache\nTTL: %ds remaining\n", domain, rem_ttl);
        } else {
            snprintf(response_msg, BUF_SIZE, "Result: %s -> %s\nSource: Cache hit\nTTL: %ds remaining\n", domain, ip_result, rem_ttl);
        }
        return;
    }

    printf("[DEBUG] Truy vấn Google DNS (8.8.8.8)...\n");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct timeval tv;
    tv.tv_sec = 3; tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(GOOGLE_DNS);

    unsigned char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);

    struct DNS_HEADER *dns = (struct DNS_HEADER *)&buf;
    dns->id = (unsigned short)htons(getpid());
    dns->flags = htons(0x0100); 
    dns->q_count = htons(1);
    dns->ans_count = 0; dns->auth_count = 0; dns->add_count = 0;

    unsigned char *qname = &buf[sizeof(struct DNS_HEADER)];
    char domain_copy[256];
    strcpy(domain_copy, domain);
    format_dns_name(qname, (unsigned char*)domain_copy);

    unsigned char *qinfo = qname + strlen((const char*)qname) + 1;
    *((uint16_t*)qinfo) = htons(1);      
    *((uint16_t*)(qinfo + 2)) = htons(1);  

    int query_len = sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1 + 4;
    sendto(sockfd, buf, query_len, 0, (struct sockaddr*)&dest, sizeof(dest));

    socklen_t len = sizeof(dest);
    int recv_len = recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr*)&dest, &len);
    close(sockfd);

    if (recv_len < 0) {
        snprintf(response_msg, BUF_SIZE, "Error: Timeout reaching 8.8.8.8. Lỗi mạng máy ảo!\n");
        return;
    }

    dns = (struct DNS_HEADER *)buf;
    int rcode = ntohs(dns->flags) & 0x000F;

    if (rcode == 3) {
        add_to_cache(domain, "", 300, 1); 
        snprintf(response_msg, BUF_SIZE, "Error: NXDOMAIN '%s' does not exist.\n", domain);
        return;
    }

    int ans_count = ntohs(dns->ans_count);
    if (ans_count > 0) {
        unsigned char *reader = &buf[query_len];
        reader += 2; 
        uint16_t type = ntohs(*((uint16_t*)reader)); reader += 2;
        reader += 2; 
        uint32_t ttl = ntohl(*((uint32_t*)reader)); reader += 4;
        uint16_t data_len = ntohs(*((uint16_t*)reader)); reader += 2;

        if (type == 1 && data_len == 4) { 
            struct in_addr a;
            memcpy(&a, reader, 4);
            strcpy(ip_result, inet_ntoa(a));
            
            add_to_cache(domain, ip_result, ttl, 0); 
            snprintf(response_msg, BUF_SIZE, "Result: %s -> %s\nSource: DNS query (fresh)\nTTL: %ds\n", domain, ip_result, ttl);
            printf("[DEBUG] Thành công! Lấy được IP: %s\n", ip_result);
        } else {
            snprintf(response_msg, BUF_SIZE, "Error: Không tìm thấy bản ghi A (IPv4) hợp lệ.\n");
        }
    } else {
        snprintf(response_msg, BUF_SIZE, "Error: DNS trả về gói tin rỗng.\n");
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUF_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Bật chế độ INADDR_ANY để nhận mọi gói tin
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Resolver Server listening on port %d...\n", PORT);

    while (1) {
        socklen_t len = sizeof(client_addr);
        memset(buffer, 0, BUF_SIZE);

        // Báo hiệu Server đang thức và chờ đợi
        printf("\n[DEBUG] Server đang chờ nhận gói tin...\n");
        
        int n = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &len);
        
        if (n < 0) {
            perror("[LỖI] recvfrom thất bại");
            continue;
        }
        
        buffer[n] = '\0';
        printf("[DEBUG] SERVER ĐÃ BẮT ĐƯỢC %d bytes từ Client!\n", n);

        char *nl = strchr(buffer, '\n'); if (nl) *nl = '\0';
        char *cr = strchr(buffer, '\r'); if (cr) *cr = '\0';

        printf("--- Nhận yêu cầu: '%s' ---\n", buffer);

        char response[BUF_SIZE] = {0};
        resolve_dns(buffer, response);

        sendto(sockfd, response, strlen(response), 0, (const struct sockaddr *)&client_addr, len);
    }
    close(sockfd);
    return 0;
}
