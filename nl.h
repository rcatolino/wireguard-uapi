#include <stdint.h>

// Bindgen knows about stdint fixed sized types, but not about linux ones
#define __u32 uint32_t
#define __u16 uint16_t

#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
