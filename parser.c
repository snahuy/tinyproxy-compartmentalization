#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <seccomp.h>
#include <errno.h>
#include <ctype.h>

#define MAX_URL_LEN 2048

// Struct to hold parsed URL components
struct request_s {
    char *host;
    char *path;
    int port;
};

// Sanitize: remove user:pass@host
void strip_username_password(char *host) {
    char *p = strchr(host, '@');
    if (!p)
        return;

    p++; // Skip '@'
    while (*p)
        *host++ = *p++;
    *host = '\0';
}

// Strip port from host:port and return port as int
int strip_return_port(char *host) {
    char *colon = strrchr(host, ':');
    if (!colon)
        return 0;

    // Don't strip from IPv6 literals [::1]:8080
    if (strchr(colon, ']'))
        return 0;

    *colon = '\0';
    int port;

    if (sscanf(colon + 1, "%d", &port) != 1)
        return 0;

    return port;
}

// Extract host, path, port from a full URL into struct
int extract_url(const char *url, int default_port, struct request_s *request) {
    char *p = strchr(url, '/');
    if (p != NULL) {
        int len = p - url;
        request->host = strndup(url, len);
        request->path = strdup(p);
    } else {
        request->host = strdup(url);
        request->path = strdup("/");
    }

    if (!request->host || !request->path)
        goto ERROR_EXIT;

    strip_username_password(request->host);
    int port = strip_return_port(request->host);
    request->port = (port != 0) ? port : default_port;

    // Remove IPv6 brackets
    p = strrchr(request->host, ']');
    if (p && request->host[0] == '[') {
        memmove(request->host, request->host + 1, strlen(request->host) - 2);
        request->host[strlen(request->host) - 2] = '\0';
    }

    return 0;

ERROR_EXIT:
    if (request->host)
        free(request->host);
    if (request->path)
        free(request->path);
    return -1;
}

// Drop to user 'nobody'
void drop_privileges() {
    struct passwd *pw = getpwnam("nobody");
    if (pw) {
        if (setuid(pw->pw_uid) != 0) {
            perror("setuid failed");
            exit(1);
        }
    }
}

// Apply seccomp syscall filter
void apply_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL); // kill on anything not allowed
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        exit(1);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);

    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "seccomp_load failed\n");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
}

int main() {
    char url[MAX_URL_LEN];

    // Read input (raw URL string)
    if (!fgets(url, sizeof(url), stdin)) {
        fprintf(stderr, "{\"error\": \"input read failed\"}\n");
        return 1;
    }

    // Strip trailing newline
    url[strcspn(url, "\r\n")] = 0;

    // If the input is empty, skip sandbox to avoid bad system call
    if (url[0] == '\0') {
        fprintf(stderr, "{\"error\": \"empty input\"}\n");
        return 1;
    }

    // Sandboxing
    drop_privileges();
    apply_seccomp();

    struct request_s request = {0};

    if (extract_url(url, 80, &request) == 0) {
        printf("{\"host\": \"%s\", \"path\": \"%s\", \"port\": %d}\n",
               request.host, request.path, request.port);
        free(request.host);
        free(request.path);
        return 0;
    } else {
        fprintf(stderr, "{\"error\": \"parsing failed\"}\n");
        return 1;
    }
}
