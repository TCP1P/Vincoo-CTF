#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *file;
    char buffer[1024];

    // Open the flag file
    file = fopen("/root/flag.txt", "r");

    if (file == NULL) {
        perror("Error opening /root/flag.txt");
        return 1;
    }

    // Read and display the contents
    printf("Contents of /root/flag.txt:\n");
    printf("==========================\n");

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }

    // Close the file
    fclose(file);

    return 0;
}
