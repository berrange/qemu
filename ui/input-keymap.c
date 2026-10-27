#include "qemu/osdep.h"
#include "keymaps.h"
#include "ui/input.h"

#include "standard-headers/linux/input.h"

int qemu_input_linux_to_qcode(unsigned int lnx)
{
    if (lnx >= qemu_input_map_linux_to_qcode_len) {
        return 0;
    }
    return qemu_input_map_linux_to_qcode[lnx];
}

int qemu_input_key_number_to_qcode(unsigned int nr)
{
    return qemu_input_linux_to_qcode(qemu_input_key_number_to_linux(nr));
}

unsigned int qemu_input_key_number_to_linux(unsigned int nr)
{
    if (nr >= qemu_input_map_qnum_to_linux_len) {
        return KEY_RESERVED;
    }
    return qemu_input_map_qnum_to_linux[nr];
}

unsigned int qemu_input_key_value_to_linux(const KeyValue *value)
{
    switch (value->type) {
    case KEY_VALUE_KIND_NUMBER:
        return qemu_input_key_number_to_linux(value->u.number.data);

    case KEY_VALUE_KIND_QCODE:
        return qemu_input_map_qcode_to_linux[value->u.qcode.data];

    default:
        g_assert_not_reached();
    }
}

int qemu_input_linux_to_scancode(unsigned int lnx, bool down, int *codes)
{
    int keycode = lnx < qemu_input_map_linux_to_qnum_len ?
                  qemu_input_map_linux_to_qnum[lnx] : 0;
    int count = 0;

    if (lnx == KEY_PAUSE) {
        /* specific case */
        int v = down ? 0 : 0x80;
        codes[count++] = 0xe1;
        codes[count++] = 0x1d | v;
        codes[count++] = 0x45 | v;
        return count;
    }
    if (keycode & SCANCODE_GREY) {
        codes[count++] = SCANCODE_EMUL0;
        keycode &= ~SCANCODE_GREY;
    }
    if (!down) {
        keycode |= SCANCODE_UP;
    }
    codes[count++] = keycode;

    return count;
}
