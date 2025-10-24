#ifndef DQDK_CONTROLLER_H
#define DQDK_CONTROLLER_H

#include "dlog.h"
#include "dqdk.h"

#define DQDK_CONTROLLER_MAX_EVENTS 32
#define SERVER_PORT 9000
#define SERVER_IP "0.0.0.0"
#define BUFFER_SIZE 64

typedef enum {
    DQDK_CMD_QUERY,
    DQDK_CMD_CLOSE
} dqdk_cmd_t;

typedef struct {
    int serverfd;
    int clientfd;
    int epollfd;
    dqdk_ctx_t* ctx;
} dqdk_controller_t;

int dqdk_controller_free(dqdk_controller_t* controller);
dqdk_controller_t* dqdk_controller_start(dqdk_ctx_t* ctx);
int dqdk_controller_report_status(dqdk_controller_t* controller, char* payload);
int dqdk_controller_wait(dqdk_controller_t* controller);
int dqdk_controller_closed(dqdk_controller_t* controller, char* buffer);
int dqdk_controller_error(dqdk_controller_t* controller);

#endif
