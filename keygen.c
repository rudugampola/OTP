#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ALPHABET_SIZE 26
#define ASCII_OFFSET 65

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }

    int keylength = atoi(argv[1]);

    // Seed the random number generator with the current time
    srand(time(NULL));
    int i;
    for (i = 0; i < keylength; i++)
    {
        // Generate a random number between 1 and 26
        int random_num = rand() % ALPHABET_SIZE + 1;

        // Convert the random number to an ASCII character
        char random_char;
        if (random_num == ALPHABET_SIZE)
        {
            random_char = ' ';
        }
        else
        {
            random_char = random_num + ASCII_OFFSET;
        }

        // Print the character to stdout
        printf("%c", random_char);
    }
    fprintf(stdout, "\n");

    return 0;
}
