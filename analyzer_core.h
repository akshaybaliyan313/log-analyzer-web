/* Shared analysis logic - used by both the CLI (analyzer.c) and the web server (server.c). */
#ifndef ANALYZER_CORE_H
#define ANALYZER_CORE_H

#include <string.h>

#define MAX_INPUT      (1024UL * 1024UL)
#define CASE_SENSITIVE 0

typedef struct {
    unsigned long total;
    unsigned long alphabets;
    unsigned long digits;
    unsigned long specials;
    unsigned long whitespace;
    unsigned long counted;
    unsigned long freq[128];
    int           top_char;
    unsigned long top_count;
} Stats;

static int is_alpha(unsigned char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }
static int is_space(unsigned char c) { return c == ' ' || (c >= '\t' && c <= '\r'); }

static int to_key(unsigned char c)
{
    return (CASE_SENSITIVE == 0 && c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static void analyze(const char *text, Stats *s)
{
    const unsigned char *p;
    int i;

    memset(s, 0, sizeof *s);
    s->top_char = -1;

    for (p = (const unsigned char *)text; *p; p++) {
        unsigned char c = *p;
        s->total++;

        if (is_alpha(c))      s->alphabets++;
        else if (is_digit(c)) s->digits++;
        else if (is_space(c)) s->whitespace++;
        else                  s->specials++;

        if (c < 128 && !is_space(c)) {
            s->freq[to_key(c)]++;
            s->counted++;
        }
    }

    for (i = 0; i < 128; i++) {
        if (s->freq[i] > s->top_count) {
            s->top_count = s->freq[i];
            s->top_char  = i;
        }
    }
}

#endif
