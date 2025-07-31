#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reqs.h"

// Declare sandbox_extract_url, which is defined in reqs.c
extern int sandbox_extract_url(const char *url, int default_port, struct request_s *request);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        return 1;
    }

    const char *url = argv[1];
    struct request_s req = {0};

    int ret = sandbox_extract_url(url, 8080, &req);

    if (ret == 0) {
        printf("Parsed host: %s\n", req.host);
        printf("Parsed path: %s\n", req.path);
        printf("Parsed port: %d\n", req.port);
        free(req.host);
        free(req.path);
        return 0;
    } else {
        fprintf(stderr, "sandbox_extract_url() failed\n");
        return 1;
    }
}
