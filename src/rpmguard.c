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

#define STATE_CACHE_FILE "/run/pkgguard/state"
#define CONTROL_SOCK "/run/libsec/pkgguard.sock"
#define EVENT_SOCK "/rpmguard/events.sock"

#define STATE_TTL_SEC 2
#define CONTROL_TIMEOUT_MS 50
#define EVENT_TIMEOUT_MS 100

#define OFFICIAL_RPMDB_PATH "/var/lib/pkgguard/rpmdb-official"

typedef enum {
    MODE_DISABLED = 0,
    MODE_COLLECT_ONLY = 1,
    MODE_ENFORCE = 2,
} guard_mode_t;

static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}

static const char *mode_to_s(guard_mode_t mode) {
    switch (mode) {
        case MODE_DISABLED: return "MODE_DISABLED";
        case MODE_COLLECT_ONLY: return "MODE_COLLECT_ONLY";
        case MODE_ENFORCE: return "MODE_ENFORCE";
        default: return "MODE_DISABLED";
    }
}

static guard_mode_t parse_mode_value(const char *s) {
    if (!s) return MODE_DISABLED;
    if (strcmp(s, "MODE_ENFORCE") == 0 || strcmp(s, "ON") == 0) return MODE_ENFORCE;
    if (strcmp(s, "MODE_COLLECT_ONLY") == 0) return MODE_COLLECT_ONLY;
    if (strcmp(s, "MODE_DISABLED") == 0 || strcmp(s, "OFF") == 0) return MODE_DISABLED;
    return MODE_DISABLED;
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

/* /run/pkgguard/state format: "MODE_ENFORCE <epoch_sec>" */
static int get_mode_from_local_cache(guard_mode_t *out) {
    FILE *fp = fopen(STATE_CACHE_FILE, "r");
    if (!fp) return -1;

    char mode[64] = {0};
    long ts = 0;
    if (fscanf(fp, "%63s %ld", mode, &ts) != 2) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    long now = (long)time(NULL);
    if (now - ts > STATE_TTL_SEC) return -1;

    *out = parse_mode_value(mode);
    return 0;
}

static int query_mode_from_libsec(guard_mode_t *out) {
    int fd = connect_uds_timeout(CONTROL_SOCK, CONTROL_TIMEOUT_MS);
    if (fd < 0) return -1;

    const char *req = "{\"type\":\"GET_MODE\"}\n";
    if (write(fd, req, strlen(req)) < 0) {
        close(fd);
        return -1;
    }

    char resp[256] = {0};
    ssize_t nr = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (nr <= 0) return -1;

    char *mode_pos = strstr(resp, "\"mode\":\"");
    if (!mode_pos) return -1;
    mode_pos += strlen("\"mode\":\"");

    char mode[64] = {0};
    int i = 0;
    while (*mode_pos && *mode_pos != '"' && i < (int)sizeof(mode) - 1) {
        mode[i++] = *mode_pos++;
    }
    mode[i] = '\0';

    *out = parse_mode_value(mode);
    return 0;
}

static guard_mode_t get_runtime_mode(void) {
    guard_mode_t mode = MODE_DISABLED;
    if (get_mode_from_local_cache(&mode) == 0) return mode;
    if (query_mode_from_libsec(&mode) == 0) return mode;
    return MODE_DISABLED;
}

static int send_event_json(const char *json) {
    int fd = connect_uds_timeout(EVENT_SOCK, EVENT_TIMEOUT_MS);
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

static int send_deny_event(const char *txid,
                           const char *mode,
                           const char *nevra,
                           const char *rpm_path,
                           const char *reason) {
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"type\":\"RPM_DENY\",\"mode\":\"%s\",\"decision\":\"DENY\",\"txid\":\"%s\",\"nevra\":\"%s\",\"rpm_path\":\"%s\",\"reason\":\"%s\",\"ts_ms\":%lld}",
             mode ? mode : "MODE_ENFORCE",
             txid ? txid : "-",
             nevra ? nevra : "-",
             rpm_path ? rpm_path : "-",
             reason ? reason : "verify_failed",
             (long long)now_ms());
    return send_event_json(json);
}

static int verify_official_package(const char *rpm_path) {
    if (!rpm_path || rpm_path[0] == '\0') return -1;

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "rpmkeys --dbpath '%s' --checksig --verbose '%s' 2>&1",
             OFFICIAL_RPMDB_PATH, rpm_path);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char out[8192] = {0};
    size_t used = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        size_t n = strlen(line);
        if (used + n + 1 < sizeof(out)) {
            memcpy(out + used, line, n);
            used += n;
            out[used] = '\0';
        }
    }

    int rc = pclose(fp);
    if (rc != 0) return -1;

    if (strstr(out, "digests signatures OK") ||
        (strstr(out, "Header") && strstr(out, "Payload") && strstr(out, "OK"))) {
        return 0;
    }
    return -1;
}

/*
 * CUSTOM verification delegates to libsec validator.
 * Expected ack: {"result":"OK"} or contains "\"result\":\"OK\"".
 */
static int verify_custom_package(const char *txid, const char *nevra, const char *rpm_path) {
    int fd = connect_uds_timeout(CONTROL_SOCK, CONTROL_TIMEOUT_MS);
    if (fd < 0) return -1;

    char req[2048];
    snprintf(req, sizeof(req),
             "{\"type\":\"VERIFY_CUSTOM\",\"txid\":\"%s\",\"nevra\":\"%s\",\"rpm_path\":\"%s\"}\n",
             txid ? txid : "-",
             nevra ? nevra : "-",
             rpm_path ? rpm_path : "-");

    if (write(fd, req, strlen(req)) < 0) {
        close(fd);
        return -1;
    }

    char resp[512] = {0};
    ssize_t nr = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (nr <= 0) return -1;

    return strstr(resp, "\"result\":\"OK\"") ? 0 : -1;
}

static int process_one_te(rpmte te, guard_mode_t mode, const char *txid) {
    if (mode == MODE_DISABLED || mode == MODE_COLLECT_ONLY) {
        return RPMRC_OK;
    }

    const char *nevra = rpmteNEVRA(te);
    const char *rpm_path = rpmteN(te); /* TODO: replace with transaction-local RPM file path API if available. */

    if (verify_official_package(rpm_path) == 0) {
        return RPMRC_OK;
    }

    if (verify_custom_package(txid, nevra, rpm_path) == 0) {
        return RPMRC_OK;
    }

    (void)send_deny_event(txid, mode_to_s(mode), nevra, rpm_path,
                          "official_and_custom_verify_failed");
    return RPMRC_FAIL;
}

static int rpmguard_tsm_pre(rpmPlugin plugin, rpmts ts) {
    (void)plugin;

    guard_mode_t mode = get_runtime_mode();

    char txid[64];
    snprintf(txid, sizeof(txid), "%lld", (long long)now_ms());

    rpmtsi tsi = rpmtsiInit(ts);
    rpmte te;
    while ((te = rpmtsiNext(tsi, TR_ADDED)) != NULL) {
        int rc = process_one_te(te, mode, txid);
        if (rc != RPMRC_OK) {
            rpmtsiFree(tsi);
            return RPMRC_FAIL;
        }
    }
    rpmtsiFree(tsi);

    return RPMRC_OK;
}

static struct rpmPluginHooks_s rpmguard_hooks = {
    .tsm_pre = rpmguard_tsm_pre,
};

struct rpmPluginHooks_s *rpmPluginHooks = &rpmguard_hooks;
