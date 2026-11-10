#ifndef AEG_CONFIG_VALUE_H
#define AEG_CONFIG_VALUE_H
#include <stddef.h>
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
#endif
