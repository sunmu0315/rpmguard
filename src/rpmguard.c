#define _GNU_SOURCE
#include <errno.h>
#include <rpm/rpmplugin.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmte.h>
#include <rpm/rpmts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* ---------- runtime control ---------- */
#define PKGGUARD_DIR "/var/lib/pkgguard"
#define PKGGUARD_STATE_DIR PKGGUARD_DIR "/state"
#define LAST_STATE_FILE PKGGUARD_STATE_DIR "/last_state"
#define STATE_CACHE_FILE "/run/pkgguard/state"
#define LIBSEC_SOCK "/run/libsec/pkgguard.sock"

#define STATE_TTL_SEC 2
#define STATE_QUERY_TIMEOUT_MS 50
#define EVENT_SEND_TIMEOUT_MS 50

typedef enum {
    MODE_OFF = 0,
    MODE_ON = 1,
} runtime_mode_t;

static int ensure_dir(const char *path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

static void ensure_runtime_dirs(void) {
    (void)ensure_dir(PKGGUARD_DIR, 0700);
    (void)ensure_dir(PKGGUARD_STATE_DIR, 0700);
}

static const char *mode_to_s(runtime_mode_t mode) {
    return mode == MODE_ON ? "ON" : "OFF";
}

static runtime_mode_t parse_mode(const char *s) {
    return (s && strcmp(s, "ON") == 0) ? MODE_ON : MODE_OFF;
}

static void write_last_state(runtime_mode_t mode) {
    FILE *fp = fopen(LAST_STATE_FILE, "w");
    if (!fp) return;

    fprintf(fp, "%s\n", mode_to_s(mode));
    fclose(fp);
    chmod(LAST_STATE_FILE, 0600);
}

/* /run/pkgguard/state format: "ON <epoch_sec>" */
static int get_state_from_local_cache(runtime_mode_t *out) {
    FILE *fp = fopen(STATE_CACHE_FILE, "r");
    if (!fp) return -1;

    char mode[16] = {0};
    long ts = 0;
    if (fscanf(fp, "%15s %ld", mode, &ts) != 2) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    long now = (long)time(NULL);
    if (now - ts > STATE_TTL_SEC) return -1;

    *out = parse_mode(mode);
    return 0;
}

static int connect_uds_timeout(const char *path, int timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int query_state_from_libsec(runtime_mode_t *out) {
    int fd = connect_uds_timeout(LIBSEC_SOCK, STATE_QUERY_TIMEOUT_MS);
    if (fd < 0) return -1;

    const char *req = "{\"type\":\"GET_STATE\"}\n";
    if (write(fd, req, strlen(req)) < 0) {
        close(fd);
        return -1;
    }

    char resp[256] = {0};
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n <= 0) return -1;

    if (strstr(resp, "\"state\":\"ON\"")) {
        *out = MODE_ON;
        return 0;
    }
    if (strstr(resp, "\"state\":\"OFF\"")) {
        *out = MODE_OFF;
        return 0;
    }
    return -1;
}

static runtime_mode_t get_state_with_timeout(void) {
    runtime_mode_t mode = MODE_OFF;
    if (get_state_from_local_cache(&mode) == 0) return mode;
    if (query_state_from_libsec(&mode) == 0) return mode;
    return MODE_OFF;
}

static int send_event_json(const char *json) {
    int fd = connect_uds_timeout(LIBSEC_SOCK, EVENT_SEND_TIMEOUT_MS);
    if (fd < 0) return -1;

    if (write(fd, json, strlen(json)) < 0) {
        close(fd);
        return -1;
    }
    (void)write(fd, "\n", 1);

    char ack[128] = {0};
    ssize_t nr = read(fd, ack, sizeof(ack) - 1);
    close(fd);
    if (nr <= 0) return -1;
    return strstr(ack, "\"ack\":true") ? 0 : -1;
}

static int send_deny_event(const char *txid, const char *nevra, const char *rpm_path, const char *reason) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"type\":\"RPM_DENY\",\"mode\":\"ON\",\"decision\":\"DENY\",\"txid\":\"%s\",\"nevra\":\"%s\",\"rpm_path\":\"%s\",\"reason\":\"%s\"}",
             txid ? txid : "-",
             nevra ? nevra : "-",
             rpm_path ? rpm_path : "-",
             reason ? reason : "verify_failed");
    return send_event_json(json);
}

/*
 * Replace these placeholders with your production verification implementation:
 * - OFFICIAL: trusted root signature + header/payload digest checks
 * - CUSTOM  : enterprise custom signature label + consistency checks
 */
static int verify_official_package(rpmte te) {
    (void)te;
    return -1;
}

static int verify_custom_package(rpmte te) {
    (void)te;
    return -1;
}

static int process_one_te(rpmte te, runtime_mode_t mode, const char *txid) {
    if (mode == MODE_OFF) {
        /* Observe mode: no enforcement, allow installation. */
        return RPMRC_OK;
    }

    if (verify_official_package(te) == 0) return RPMRC_OK;
    if (verify_custom_package(te) == 0) return RPMRC_OK;

    const char *nevra = rpmteNEVRA(te);
    const char *name = rpmteN(te);
    (void)send_deny_event(txid, nevra, name, "official_and_custom_verify_failed");
    return RPMRC_FAIL;
}

static int rpmguard_tsm_pre(rpmPlugin plugin, rpmts ts) {
    (void)plugin;
    ensure_runtime_dirs();

    runtime_mode_t cur = get_state_with_timeout();
    char txid[64];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    snprintf(txid, sizeof(txid), "%lld", (long long)tv.tv_sec * 1000LL + tv.tv_usec / 1000);

    rpmtsi it = rpmtsiInit(ts);
    rpmte te;
    while ((te = rpmtsiNext(it, TR_ADDED)) != NULL) {
        int rc = process_one_te(te, cur, txid);
        if (rc != RPMRC_OK) {
            rpmtsiFree(it);
            write_last_state(cur);
            return RPMRC_FAIL;
        }
    }
    rpmtsiFree(it);

    write_last_state(cur);
    return RPMRC_OK;
}

static struct rpmPluginHooks_s rpmguard_hooks = {
    .tsm_pre = rpmguard_tsm_pre,
};

struct rpmPluginHooks_s *rpmPluginHooks = &rpmguard_hooks;
