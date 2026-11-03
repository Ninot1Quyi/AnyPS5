#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libc/libc.hpp"

extern "C" {

HmacContext* APS5_VABI HMAC_CTX_new_nid_postfix() {
    return static_cast<HmacContext*>(calloc_nid_postfix(1, sizeof(HmacContext)));
}

void APS5_VABI HMAC_CTX_free_nid_postfix(HmacContext* context) {
    if (!context) return;
    HMAC_CTX_cleanup_nid_postfix(context);
    free_nid_postfix(context);
}

}
