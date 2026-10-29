/* Command-line version. Same output as before; the logic now lives in analyzer_core.h. */
#include <stdio.h>
#include "analyzer_core.h"

int main(void)
{
    static char buf[MAX_INPUT + 1];
    Stats s;
    size_t n;

    printf("Paste your log text, then press Ctrl+Z and hit Enter:\n\n");

    n = fread(buf, 1, MAX_INPUT, stdin);
    buf[n] = '\0';

    analyze(buf, &s);

    printf("\n==========================================\n");
    printf("         INTELLIGENT LOG ANALYZER\n");
    printf("==========================================\n");
    printf(" Total characters   : %lu\n", s.total);
    printf(" Alphabets          : %lu\n", s.alphabets);
    printf(" Digits             : %lu\n", s.digits);
    printf(" Special characters : %lu\n", s.specials);
    printf(" Whitespace         : %lu\n", s.whitespace);
    printf("------------------------------------------\n");

    if (s.top_char > 32 && s.top_char < 127) {
        printf(" Most frequent      : '%c'  (%lu times)\n", s.top_char, s.top_count);
    }
    printf("==========================================\n");

    return 0;
}
