#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    FILE *f = fopen("/flag.txt", "r");
    if (f == NULL) {
        printf("Error: Could not open flag file.\n");
        exit(1);
    }
    char flag[128];
    fgets(flag, sizeof(flag), f);
    printf("%s\n", flag);
    fclose(f);
    exit(0);
}

void vulnerable() {
    char buffer[64];
    
    printf("=============================\n");
    printf("     Welcome to GreetMe!     \n");
    printf("=============================\n\n");
    printf("What's your name? ");
    
    gets(buffer);
    
    printf("\nHey there, %s!\n", buffer);
    printf("Have a nice day!\n");
}

int main() {
    setup();
    vulnerable();
    return 0;
}
