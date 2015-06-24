#ifndef __EBLOB_LIBRARY_FOOTER_H
#define __EBLOB_LIBRARY_FOOTER_H

#include "eblob/blob.h"


#ifdef __cplusplus
extern "C" {
#endif

/*
 * eblob_calculate_footer_size() - computes and returns size of footer for any data with @data_size
 *
 * Returns computed size of footer.
 *
 * NB! If eblob is configured with EBLOB_NO_FOOTER flag or @data_size is 0, return value will be 0.
 */
uint64_t eblob_calculate_footer_size(struct eblob_backend *b, uint64_t data_size);

/*
 * eblob_commit_footer() - computes and writes footer for @key pointed by @wc
 *
 * Returns negative error value or zero on success
 */
int eblob_commit_footer(struct eblob_backend *b, struct eblob_key *key, struct eblob_write_control *wc);

#ifdef __cplusplus
}
#endif

#endif /* __EBLOB_LIBRARY_FOOTER_H */
