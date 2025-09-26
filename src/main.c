#include <stdio.h>
#include "capture.h"

int main() {
    printf("Starting PCAPture...\n");

    // Begin capturing packets
    start_capture();

    return 0;
}