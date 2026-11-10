#ifndef AEG_CONFIG_VALUE_H
#define AEG_CONFIG_VALUE_H
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Declarative KEY=value only. Never evaluates shell, expansion or commands. */
static inline int aeg_config_assignment(const char *line, char *key, size_t kn,
                                        char *value, size_t vn) {
    while (*line == ' ' || *line == '\t') line++;
    size_t k = 0, n = 0;
    while ((*line >= 'A' && *line <= 'Z') || (*line >= '0' && *line <= '9') || *line == '_') {
        if (k + 1 >= kn) return 0;
        key[k++] = *line++;
    }
    key[k] = 0;
    while (*line == ' ' || *line == '\t') line++;
    if (!k || *line++ != '=') return 0;
    while (*line == ' ' || *line == '\t') line++;
    char quote = (*line == '\'' || *line == '"') ? *line++ : 0;
    while (*line && *line != '\n' && *line != '\r') {
        if ((quote && *line == quote) || (!quote && *line == '#')) break;
        if (n + 1 >= vn) return 0;
        value[n++] = *line++;
    }
    if (quote) {
        if (*line++ != quote) return 0;
        while (*line == ' ' || *line == '\t') line++;
        if (*line && *line != '#' && *line != '\r' && *line != '\n') return 0;
    } else {
        while (n && (value[n-1] == ' ' || value[n-1] == '\t')) n--;
    }
    value[n] = 0;
    return 1;
}

/* Strict number: the whole value must parse, be finite, lie in [min, max] and,
 * when integral is set, have no fraction. Returns 1 and sets *out on success. */
static inline int aeg_config_number(const char *val, double min, double max, int integral, double *out) {
    char *end = NULL;
    errno = 0;
    double v = strtod(val, &end);
    if (errno || end == val || *end || !isfinite(v) || v < min || v > max) return 0;
    if (integral && v != (double)(long)v) return 0;
    *out = v;
    return 1;
}

/* Splits buf in place into lines and calls fn for every KEY=value line. */
static inline void aeg_config_each(char *buf, void (*fn)(const char *key, const char *val)) {
    char *p = buf;
    while (p && *p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        char key[80], val[1024];
        if (aeg_config_assignment(p, key, sizeof key, val, sizeof val)) fn(key, val);
        p = nl ? nl + 1 : 0;
    }
}
#endif
