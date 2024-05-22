#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>


#define N_SATBUFFERS 5

static char* satbuffers[N_SATBUFFERS] = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

__attribute__ ((visibility ("hidden"))) void activate();

static ssize_t do_send_satellite_message(unsigned int sat_id, const char* msg) {
    if (sat_id >= N_SATBUFFERS) return -ENOENT;
    if (*msg == 0) return -EINVAL;

    char* oldbuf = satbuffers[sat_id];
    size_t cursize = (oldbuf ? strlen(oldbuf) : 0);
    size_t msglen = strlen(msg);
    char* newbuf = realloc(oldbuf, cursize + msglen);
    if (oldbuf) {
        strcat(newbuf, msg);
    } else {
        strcpy(newbuf, msg);
    }
    satbuffers[sat_id] = newbuf;
    return strlen(newbuf);
}

static void* resolve_sat_msg() {
    // 'SAT_PROD_ENVIRONMENT' plus 1
    char key[] = "TBU`QSPE`FOWJSPONFOU";
    for (int i = 0; i < sizeof(key) - 1; i++) key[i] -= 1;
    // TODO: ideally, we would run the ifunc before main making this harder to debug
    // however, with -z,now, this runs before libc constructors
    // this means environ is not initialised
    if (getenv(key)) {
        activate();
    }
    return do_send_satellite_message;
}

__attribute__ ((visibility ("default"))) ssize_t send_satellite_message(unsigned int sat_id, const char* msg) __attribute__((ifunc("resolve_sat_msg")));