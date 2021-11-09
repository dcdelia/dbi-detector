#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>

#define TLS_SLOTS   1000

int main() {
    LPVOID ret;
    for (int i = 0; i < TLS_SLOTS; ++i) {
        ret = TlsGetValue(i);
        printf("%d: %p\n", i, ret);
    }

    return 0;
}