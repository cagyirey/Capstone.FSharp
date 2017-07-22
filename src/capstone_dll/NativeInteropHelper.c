#include <capstone.h>

CAPSTONE_EXPORT
cs_arm* CAPSTONE_API cs_arm_detail(cs_detail *detail) {
        return &detail->arm;
}

CAPSTONE_EXPORT
cs_arm64* CAPSTONE_API cs_arm64_detail(cs_detail *detail) {
        return &detail->arm64;
}

CAPSTONE_EXPORT
cs_x86* CAPSTONE_API cs_x86_detail(cs_detail *detail) {
        return &detail->x86;
}
