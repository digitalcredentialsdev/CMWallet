#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int B64Lookup(char x) {
    if (x >= 0x41 && x <= 0x5a) {
        return x-0x41;
    } else if (x >= 0x61 && x <= 0x7a) {
        return x-0x61+26;
    } else if (x >= 0x30 && x <= 0x39) {
        return x-0x30+52;
    } else if (x == 0x2d) {
        return 62;
    } else if (x == 0x5f) {
        return 63;
    } else {
        return 0;
    }
}

int B64DecodeURL(char* input, char** output) {
    int b64len = strlen(input);
    int output_len = (b64len*3) / 4;
    char* buffer = malloc(output_len+1);
    
    int count = 0;
    for(int i=0; i<b64len; i+=4) {
        uint32_t v = 0;
        for(int j=0; j<4; j++) {
            v = v << 6;
            v += B64Lookup(input[i+j]);
        }
        buffer[count++] = (v >> 16);
        buffer[count++] = (v >> 8) & 0xff;
        buffer[count++] = v & 0xFF;
    }
    *output = buffer;

    if (b64len > 0 && input[b64len-1] == '=') {
        output_len--;
    }
    if (b64len > 1 && input[b64len-2] == '=') {
        output_len--;
    }

    buffer[output_len] = '\0';

    return output_len;
}
