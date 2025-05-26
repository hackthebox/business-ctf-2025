#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void main() {
    int64_t arr[0x10] = {
        0x3fe68b3700474d9c,
        -0x40614a0a0f4d7add,
        -0x401c3e35c5b4aa97,
        0x3fce2656abde3fbc,
        -0x403a72324c836651,
        -0x404b9042d8c2a455,
        0x3fca7eb6bf444e0e,
        -0x4016e0114d2f5dbc,
        -0x40467c17a89331a1,
        0x3fca7eb6bf444e0e,
        0x3fce2656abde3fbc,
        -0x401bd24e160d887f,
        0x3fe6e965f5275eea,
        -0x404e1bf37b8d3f18,
        0x3fe91feeb2d0a244,
        -0x40175ac258d5842b};
    double ans[0x10];
    memcpy(&ans, &arr, sizeof(ans));
    for (int i = 0; i < 0x10; i++) {
        printf("%lf ", tan(ans[i]));
    }
    puts("%");
}