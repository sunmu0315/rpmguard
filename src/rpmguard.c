#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <rpm/header.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmplugin.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmte.h>
#include <rpm/rpmts.h>
#include <stdbool.h>
#include <stdint.h>
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

/* ---------- v3 default paths ---------- */
#define PKGGUARD_DIR "/var/lib/pkgguard"
#define PKGGUARD_STATE_DIR PKGGUARD_DIR "/state"
#define PKGGUARD_CACHE_DIR PKGGUARD_DIR "/cache"
#define LAST_STATE_FILE PKGGUARD_STATE_DIR "/last_state"
#define STATE_CACHE_FILE "/run/pkgguard/state"
#define CACHE_JSONL_FILE PKGGUARD_CACHE_DIR "/exec_digests.jsonl"
#define CACHE_CKPT_FILE PKGGUARD_CACHE_DIR "/exec_digests.ckpt"
#define LIBSEC_SOCK "/run/libsec/pkgguard.sock"

#define STATE_TTL_SEC 2
#define STATE_QUERY_TIMEOUT_MS 50
#define EVENT_SEND_TIMEOUT_MS 50
#define CACHE_MAX_BYTES (100 * 1024 * 1024ULL)

#define BACKFILL_BATCH_MAX_RECORDS 500
#define BACKFILL_BATCH_MAX_BYTES (1024 * 1024)

typedef enum {
    MODE_OFF = 0,
    MODE_ON = 1,
} runtime_mode_t;

typedef struct {
    const char *txid;
    runtime_mode_t mode;
} ctx_t;

typedef struct {
    char *path;
    char *algo;
    char *digest;
    mode_t mode;
} digest_entry_t;

typedef struct {
    char *path;
    char *target;
    mode_t mode;
} symlink_entry_t;

static int ensure_dir(const char *path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static void ensure_runtime_dirs(void) {
    (void)ensure_dir(PKGGUARD_DIR, 0700);
    (void)ensure_dir(PKGGUARD_STATE_DIR, 0700);
    (void)ensure_dir(PKGGUARD_CACHE_DIR, 0700);
}

static const char *mode_to_s(runtime_mode_t mode) {
    return mode == MODE_ON ? "ON" : "OFF";
}

static runtime_mode_t parse_mode(const char *s) {
    return (s && strcmp(s, "ON") == 0) ? MODE_ON : MODE_OFF;
}

static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + tv.tv_usec / 1000;
}

static int read_last_state(runtime_mode_t *out) {
    FILE *fp = fopen(LAST_STATE_FILE, "r");
    if (!fp) {
        *out = MODE_OFF;
        return -1;
    }
    char buf[32] = {0};
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        *out = MODE_OFF;
        return -1;
    }
    fclose(fp);
    buf[strcspn(buf, "\r\n")] = '\0';
    *out = parse_mode(buf);
    return 0;
}

static void write_last_state(runtime_mode_t mode) {
    FILE *fp = fopen(LAST_STATE_FILE, "w");
    if (!fp) {
        return;
    }
    fprintf(fp, "%s\n", mode_to_s(mode));
    fclose(fp);
    chmod(LAST_STATE_FILE, 0600);
}

/* /run/pkgguard/state format: "ON <epoch_sec>" */
static int get_state_from_local_cache(runtime_mode_t *out) {
    FILE *fp = fopen(STATE_CACHE_FILE, "r");
    if (!fp) {
        return -1;
    }
    char mode[16] = {0};
    long ts = 0;
    if (fscanf(fp, "%15s %ld", mode, &ts) != 2) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    long now = (long)time(NULL);
    if (now - ts > STATE_TTL_SEC) {
        return -1;
    }
    *out = parse_mode(mode);
    return 0;
}

static int connect_uds_timeout(const char *path, int timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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
    if (get_state_from_local_cache(&mode) == 0) {
        return mode;
    }
    if (query_state_from_libsec(&mode) == 0) {
        return mode;
    }
    return MODE_OFF;
}

static int send_event_json(const char *json) {
    int fd = connect_uds_timeout(LIBSEC_SOCK, EVENT_SEND_TIMEOUT_MS);
    if (fd < 0) return -1;
    ssize_t nw = write(fd, json, strlen(json));
    if (nw < 0) {
        close(fd);
        return -1;
    }
    const char *nl = "\n";
    (void)write(fd, nl, 1);

    char ack[128] = {0};
    ssize_t nr = read(fd, ack, sizeof(ack) - 1);
    close(fd);
    if (nr <= 0) return -1;
    return strstr(ack, "\"ack\":true") ? 0 : -1;
}

static int append_jsonl_record(const char *line) {
    FILE *fp = fopen(CACHE_JSONL_FILE, "a");
    if (!fp) return -1;
    if (fprintf(fp, "%s\n", line) < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    chmod(CACHE_JSONL_FILE, 0600);
    return 0;
}

static void enforce_cache_size_limit(void) {
    struct stat st;
    if (stat(CACHE_JSONL_FILE, &st) != 0) return;
    if ((uint64_t)st.st_size <= CACHE_MAX_BYTES) return;

    /* simple truncate half-old policy: keep the newest half */
    FILE *in = fopen(CACHE_JSONL_FILE, "r");
    if (!in) return;

    char tmpf[PATH_MAX];
    snprintf(tmpf, sizeof(tmpf), "%s.tmp", CACHE_JSONL_FILE);
    FILE *out = fopen(tmpf, "w");
    if (!out) {
        fclose(in);
        return;
    }

    long start = st.st_size / 2;
    fseek(in, start, SEEK_SET);
    char buf[4096];
    while (fgets(buf, sizeof(buf), in)) {
        fputs(buf, out);
    }
    fclose(in);
    fclose(out);
    rename(tmpf, CACHE_JSONL_FILE);

    (void)send_event_json("{\"type\":\"CACHE_TRUNCATED\",\"reason\":\"size_limit\"}");
}

static bool is_executable_mode(mode_t m) {
    return S_ISREG(m) && (m & 0111);
}

static bool is_symlink_mode(mode_t m) {
    return S_ISLNK(m);
}

static char *xstrdup_safe(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (!out) return NULL;
    memcpy(out, s, n);
    return out;
}

static int append_digest_entry(digest_entry_t **arr, size_t *count, size_t *cap,
                               const char *path, mode_t mode, const char *algo, const char *digest) {
    if (*count == *cap) {
        size_t ncap = (*cap == 0) ? 16 : (*cap * 2);
        void *p = realloc(*arr, ncap * sizeof((*arr)[0]));
        if (!p) return -1;
        *arr = (digest_entry_t *)p;
        *cap = ncap;
    }
    (*arr)[*count].path = xstrdup_safe(path);
    (*arr)[*count].algo = xstrdup_safe(algo ? algo : "unknown");
    (*arr)[*count].digest = xstrdup_safe(digest ? digest : "");
    (*arr)[*count].mode = mode;
    if (!(*arr)[*count].path || !(*arr)[*count].algo || !(*arr)[*count].digest) return -1;
    (*count)++;
    return 0;
}

static int append_symlink_entry(symlink_entry_t **arr, size_t *count, size_t *cap,
                                const char *path, mode_t mode, const char *target) {
    if (*count == *cap) {
        size_t ncap = (*cap == 0) ? 16 : (*cap * 2);
        void *p = realloc(*arr, ncap * sizeof((*arr)[0]));
        if (!p) return -1;
        *arr = (symlink_entry_t *)p;
        *cap = ncap;
    }
    (*arr)[*count].path = xstrdup_safe(path);
    (*arr)[*count].target = xstrdup_safe(target ? target : "");
    (*arr)[*count].mode = mode;
    if (!(*arr)[*count].path || !(*arr)[*count].target) return -1;
    (*count)++;
    return 0;
}

static void free_digest_entries(digest_entry_t *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].path);
        free(arr[i].algo);
        free(arr[i].digest);
    }
    free(arr);
}

static void free_symlink_entries(symlink_entry_t *arr, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(arr[i].path);
        free(arr[i].target);
    }
    free(arr);
}

static const digest_entry_t *find_digest_entry(const digest_entry_t *arr, size_t count, const char *path) {
    if (!path) return NULL;
    for (size_t i = 0; i < count; i++) {
        if (arr[i].path && strcmp(arr[i].path, path) == 0) {
            return &arr[i];
        }
    }
    return NULL;
}

static const symlink_entry_t *find_symlink_entry(const symlink_entry_t *arr, size_t count, const char *path) {
    if (!path) return NULL;
    for (size_t i = 0; i < count; i++) {
        if (arr[i].path && strcmp(arr[i].path, path) == 0) {
            return &arr[i];
        }
    }
    return NULL;
}

static char *normalize_abs_path(const char *path) {
    if (!path || path[0] != '/') return NULL;
    char *tmp = xstrdup_safe(path);
    if (!tmp) return NULL;

    char *segments[256];
    int top = 0;
    char *save = NULL;
    char *tok = strtok_r(tmp, "/", &save);
    while (tok) {
        if (strcmp(tok, ".") == 0 || strcmp(tok, "") == 0) {
            /* skip */
        } else if (strcmp(tok, "..") == 0) {
            if (top > 0) top--;
        } else if (top < (int)(sizeof(segments) / sizeof(segments[0]))) {
            segments[top++] = tok;
        }
        tok = strtok_r(NULL, "/", &save);
    }

    size_t need = 2;
    for (int i = 0; i < top; i++) need += strlen(segments[i]) + 1;
    char *out = (char *)malloc(need);
    if (!out) {
        free(tmp);
        return NULL;
    }
    size_t pos = 0;
    out[pos++] = '/';
    for (int i = 0; i < top; i++) {
        size_t l = strlen(segments[i]);
        memcpy(out + pos, segments[i], l);
        pos += l;
        if (i != top - 1) out[pos++] = '/';
    }
    out[pos] = '\0';
    free(tmp);
    return out;
}

static char *dirname_of(const char *path) {
    if (!path) return xstrdup_safe("/");
    const char *last = strrchr(path, '/');
    if (!last || last == path) return xstrdup_safe("/");
    size_t len = (size_t)(last - path);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, path, len);
    out[len] = '\0';
    return out;
}

static char *resolve_link_target_path(const char *link_path, const char *target) {
    if (!target || target[0] == '\0') return NULL;
    if (target[0] == '/') {
        return normalize_abs_path(target);
    }

    char *dir = dirname_of(link_path);
    if (!dir) return NULL;
    size_t n = strlen(dir) + 1 + strlen(target) + 1;
    char *combined = (char *)malloc(n);
    if (!combined) {
        free(dir);
        return NULL;
    }
    snprintf(combined, n, "%s/%s", dir, target);
    free(dir);

    char *norm = normalize_abs_path(combined);
    free(combined);
    return norm;
}

static const digest_entry_t *resolve_symlink_to_digest(const symlink_entry_t *sym_arr,
                                                       size_t sym_count,
                                                       const digest_entry_t *dig_arr,
                                                       size_t dig_count,
                                                       const symlink_entry_t *start,
                                                       char **resolved_real_path) {
    const symlink_entry_t *cur = start;
    char *candidate = NULL;

    for (int depth = 0; depth < 8 && cur; depth++) {
        free(candidate);
        candidate = resolve_link_target_path(cur->path, cur->target);
        if (!candidate) break;

        const digest_entry_t *dig = find_digest_entry(dig_arr, dig_count, candidate);
        if (dig) {
            *resolved_real_path = candidate;
            return dig;
        }

        cur = find_symlink_entry(sym_arr, sym_count, candidate);
    }

    free(candidate);
    return NULL;
}

static int buffer_digest_record(const char *txid,
                                const char *nevra,
                                const char *rpm_path,
                                const char *file_path,
                                mode_t mode,
                                const char *algo,
                                const char *digest,
                                const char *decision) {
    char line[4096];
    snprintf(line, sizeof(line),
             "{\"type\":\"EXEC_DIGEST_BUFFERED\",\"txid\":\"%s\",\"decision\":\"%s\",\"nevra\":\"%s\",\"rpm_path\":\"%s\",\"file_path\":\"%s\",\"mode\":%u,\"algo\":\"%s\",\"digest\":\"%s\",\"ts_ms\":%lld}",
             txid ? txid : "-",
             decision ? decision : "OBSERVE",
             nevra ? nevra : "-",
             rpm_path ? rpm_path : "-",
             file_path ? file_path : "-",
             (unsigned)mode,
             algo ? algo : "unknown",
             digest ? digest : "",
             (long long)now_ms());
    return append_jsonl_record(line);
}

static int send_collect_event(const char *txid,
                              const char *mode,
                              const char *decision,
                              const char *nevra,
                              const char *rpm_path,
                              const char *file_path,
                              const char *real_path,
                              mode_t fmode,
                              const char *algo,
                              const char *digest) {
    char json[4096];
    snprintf(json, sizeof(json),
             "{\"type\":\"EXEC_DIGEST_COLLECT\",\"mode\":\"%s\",\"decision\":\"%s\",\"txid\":\"%s\",\"nevra\":\"%s\",\"rpm_path\":\"%s\",\"file_path\":\"%s\",\"real_path\":\"%s\",\"file_mode\":%u,\"digest_algo\":\"%s\",\"digest\":\"%s\"}",
             mode,
             decision,
             txid ? txid : "-",
             nevra ? nevra : "-",
             rpm_path ? rpm_path : "-",
             file_path ? file_path : "-",
             real_path ? real_path : file_path ? file_path : "-",
             (unsigned)fmode,
             algo ? algo : "unknown",
             digest ? digest : "");
    return send_event_json(json);
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

/* Placeholder for v2 official/custom checks. Replace with real cryptographic checks. */
static int verify_official_package(rpmte te) {
    (void)te;
    return -1;
}

static int verify_custom_package(rpmte te) {
    (void)te;
    return -1;
}

/* Collect all executable files (x-bit set) digest from header metadata only. */
static int collect_exec_digests(rpmte te, ctx_t *ctx, const char *decision) {
    Header h = rpmteHeader(te);
    if (!h) return -1;

    rpmfi fi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_KEEPHEADER);
    if (!fi) {
        headerFree(h);
        return -1;
    }

    const char *nevra = rpmteNEVRA(te);
    const char *pkgpath = rpmteN(te);

    digest_entry_t *digests = NULL;
    size_t digest_count = 0, digest_cap = 0;
    symlink_entry_t *symlinks = NULL;
    size_t symlink_count = 0, symlink_cap = 0;

    while (rpmfiNext(fi) >= 0) {
        const char *path = rpmfiFN(fi);
        mode_t mode = rpmfiFMode(fi);
        const char *digest = rpmfiFDigestHex(fi, NULL);
        const char *link_target = rpmfiFLink(fi);
        const char *algo = "unknown";

        if (is_executable_mode(mode)) {
            (void)append_digest_entry(&digests, &digest_count, &digest_cap, path, mode, algo, digest);
        } else if (is_symlink_mode(mode) && link_target && link_target[0] != '\0') {
            (void)append_symlink_entry(&symlinks, &symlink_count, &symlink_cap, path, mode, link_target);
        }
    }

    for (size_t i = 0; i < digest_count; i++) {
        if (ctx->mode == MODE_ON) {
            if (send_collect_event(ctx->txid, "ON", decision, nevra, pkgpath,
                                   digests[i].path, digests[i].path, digests[i].mode,
                                   digests[i].algo, digests[i].digest) != 0) {
                /* send failure must not block rpm transaction */
                (void)buffer_digest_record(ctx->txid, nevra, pkgpath,
                                           digests[i].path, digests[i].mode,
                                           digests[i].algo, digests[i].digest, decision);
            }
        } else {
            (void)buffer_digest_record(ctx->txid, nevra, pkgpath,
                                       digests[i].path, digests[i].mode,
                                       digests[i].algo, digests[i].digest, "OBSERVE");
        }
    }

    for (size_t i = 0; i < symlink_count; i++) {
        char *real_path = NULL;
        const digest_entry_t *real = resolve_symlink_to_digest(symlinks, symlink_count,
                                                                digests, digest_count,
                                                                &symlinks[i], &real_path);
        if (!real || !real_path) {
            free(real_path);
            continue;
        }

        if (ctx->mode == MODE_ON) {
            if (send_collect_event(ctx->txid, "ON", decision, nevra, pkgpath,
                                   symlinks[i].path, real_path, symlinks[i].mode,
                                   real->algo, real->digest) != 0) {
                (void)buffer_digest_record(ctx->txid, nevra, pkgpath,
                                           symlinks[i].path, symlinks[i].mode,
                                           real->algo, real->digest, decision);
            }
        } else {
            (void)buffer_digest_record(ctx->txid, nevra, pkgpath,
                                       symlinks[i].path, symlinks[i].mode,
                                       real->algo, real->digest, "OBSERVE");
        }
        free(real_path);
    }

    free_digest_entries(digests, digest_count);
    free_symlink_entries(symlinks, symlink_count);
    rpmfiFree(fi);
    headerFree(h);
    enforce_cache_size_limit();
    return 0;
}

static off_t read_checkpoint(void) {
    FILE *fp = fopen(CACHE_CKPT_FILE, "r");
    if (!fp) return 0;
    long long off = 0;
    if (fscanf(fp, "%lld", &off) != 1) off = 0;
    fclose(fp);
    return (off_t)off;
}

static void write_checkpoint(off_t off) {
    FILE *fp = fopen(CACHE_CKPT_FILE, "w");
    if (!fp) return;
    fprintf(fp, "%lld\n", (long long)off);
    fclose(fp);
    chmod(CACHE_CKPT_FILE, 0600);
}

static int flush_cache_to_libsec(const char *txid) {
    FILE *fp = fopen(CACHE_JSONL_FILE, "r");
    if (!fp) return 0;

    off_t off = read_checkpoint();
    if (off > 0) fseeko(fp, off, SEEK_SET);

    char line[4096];
    char batch[BACKFILL_BATCH_MAX_BYTES + 512];
    int batch_count = 0;
    size_t batch_len = 0;
    int rc = 0;

    while (fgets(line, sizeof(line), fp)) {
        size_t l = strlen(line);
        if (batch_count == 0) {
            batch_len = snprintf(batch, sizeof(batch),
                                 "{\"type\":\"EXEC_DIGEST_BACKFILL\",\"txid\":\"%s\",\"records\":[",
                                 txid ? txid : "-");
        }

        if (batch_count > 0) {
            batch[batch_len++] = ',';
        }

        if (batch_len + l + 4 >= sizeof(batch) || batch_count >= BACKFILL_BATCH_MAX_RECORDS) {
            batch[batch_len++] = ']';
            batch[batch_len++] = '}';
            batch[batch_len] = '\0';
            if (send_event_json(batch) != 0) {
                rc = -1;
                break;
            }
            write_checkpoint(ftello(fp) - (off_t)l);
            batch_count = 0;
            continue;
        }

        memcpy(batch + batch_len, line, l);
        batch_len += l;
        while (batch_len > 0 && (batch[batch_len - 1] == '\n' || batch[batch_len - 1] == '\r')) {
            batch_len--;
        }
        batch_count++;
    }

    if (rc == 0 && batch_count > 0) {
        batch[batch_len++] = ']';
        batch[batch_len++] = '}';
        batch[batch_len] = '\0';
        rc = send_event_json(batch);
    }

    if (rc == 0) {
        write_checkpoint(ftello(fp));
    }
    fclose(fp);
    return rc;
}

static int process_one_te(rpmte te, ctx_t *ctx) {
    if (ctx->mode == MODE_OFF) {
        (void)collect_exec_digests(te, ctx, "OBSERVE");
        return RPMRC_OK;
    }

    if (verify_official_package(te) == 0) {
        (void)collect_exec_digests(te, ctx, "OFFICIAL");
        return RPMRC_OK;
    }

    if (verify_custom_package(te) == 0) {
        (void)collect_exec_digests(te, ctx, "CUSTOM");
        return RPMRC_OK;
    }

    const char *nevra = rpmteNEVRA(te);
    const char *path = rpmteN(te);
    (void)send_deny_event(ctx->txid, nevra, path, "official_and_custom_verify_failed");
    return RPMRC_FAIL;
}

static int rpmguard_tsm_pre(rpmPlugin plugin, rpmts ts) {
    (void)plugin;
    ensure_runtime_dirs();

    runtime_mode_t cur = get_state_with_timeout();
    runtime_mode_t last = MODE_OFF;
    (void)read_last_state(&last);

    char txid[64];
    snprintf(txid, sizeof(txid), "%lld", (long long)now_ms());

    if (last == MODE_OFF && cur == MODE_ON) {
        (void)flush_cache_to_libsec(txid);
    }

    ctx_t ctx = {
        .txid = txid,
        .mode = cur,
    };

    rpmtsi pi = rpmtsiInit(ts);
    rpmte te;
    while ((te = rpmtsiNext(pi, TR_ADDED)) != NULL) {
        int rc = process_one_te(te, &ctx);
        if (rc != RPMRC_OK) {
            rpmtsiFree(pi);
            write_last_state(cur);
            return RPMRC_FAIL;
        }
    }
    rpmtsiFree(pi);

    write_last_state(cur);
    return RPMRC_OK;
}

static struct rpmPluginHooks_s rpmguard_hooks = {
    .tsm_pre = rpmguard_tsm_pre,
};

struct rpmPluginHooks_s *rpmPluginHooks = &rpmguard_hooks;
