/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CNE_LOG_H_
#define _CNE_LOG_H_

/**
 * @file
 *
 * CNE Logs API
 *
 * This file provides a log API to CNE applications.
 */

#include <stdio.h>             // for NULL
#include <stdarg.h>            // for va_list
#include <stdint.h>            // for uint32_t
#include "cne_common.h"        // for CNDP_API

#include "cne_branch_prediction.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate an Error log message and return value
 *
 * Same as CNE_LOG(ERR,...) define, but returns -1 to enable this style of coding.
 *   if (val == error) {
 *       CNE_ERR("Error: Failed\n");
 *       return -1;
 *   }
 * Returning _val  to the calling function.
 */
#define CNE_ERR_RET_VAL(_val, ...) \
    do {                           \
        return _val;               \
    } while ((0))

/**
 * Generate an Error log message and return
 *
 * Same as CNE_LOG(ERR,...) define, but returns to enable this style of coding.
 *   if (val == error) {
 *       CNE_ERR("Error: Failed\n");
 *       return;
 *   }
 * Returning to the calling function.
 */
#define CNE_RET(...) CNE_ERR_RET_VAL(, __VA_ARGS__)

/**
 * Generate an Error log message and return -1
 *
 * Same as CNE_LOG(ERR,...) define, but returns -1 to enable this style of coding.
 *   if (val == error) {
 *       CNE_ERR("Error: Failed\n");
 *       return -1;
 *   }
 * Returning a -1 to the calling function.
 */
#define CNE_ERR_RET(...) CNE_ERR_RET_VAL(-1, __VA_ARGS__)

/**
 * Generate an Error log message and return NULL
 *
 * Same as CNE_LOG(ERR,...) define, but returns NULL to enable this style of coding.
 *   if (val == error) {
 *       CNE_ERR("Error: Failed\n");
 *       return NULL;
 *   }
 * Returning a NULL to the calling function.
 */
#define CNE_NULL_RET(...) CNE_ERR_RET_VAL(NULL, __VA_ARGS__)

/**
 * Generate a Error log message and goto label
 *
 * Same as CNE_LOG(ERR,...) define, but goes to a label to enable this style of coding.
 *   if (error condition) {
 *       CNE_ERR("Error: Failed\n");
 *       goto lbl;
 *   }
 */
#define CNE_ERR_GOTO(lbl, ...) \
    do {                       \
        goto lbl;              \
    } while ((0))

#ifdef __cplusplus
}
#endif

#endif /* _CNE_LOG_H_ */
