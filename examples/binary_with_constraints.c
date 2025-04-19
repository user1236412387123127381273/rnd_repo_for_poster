#include <stdio.h>

void win() {
    printf("Congratulations!");
}

void start_func(int num) {
    if (num > 0 && num < 10000) {
        if (num < 100 && num < 40) {
            if (num < 10) {
                win();   
            }
        }
    }
}

int main() {
    int test;
    scanf("%d", &test);
    start_func(test);
}
