#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Flag stored in memory - players need to leak this
char secret[] = "RSCTF_DYNAMIC_FLAG_04fb926ef4d00a3a0cfba49651c886";

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void echo_service() {
    char buffer[128];

    printf("================================\n");
    printf("   Super Secure Echo Service    \n");
    printf("================================\n\n");

    while (1) {
        printf("> ");

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break;
        }

        // Remove newline
        buffer[strcspn(buffer, "\n")] = 0;

        if (strcmp(buffer, "exit") == 0) {
            printf("Goodbye!\n");
            break;
        }

        // Vulnerable: user input directly as format string
        printf(buffer);
        printf("\n");
    }
}

int main() {
    setup();
    echo_service();
    return 0;
}
