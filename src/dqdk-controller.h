#ifndef DQDK_CONTROLLER_H
#define DQDK_CONTROLLER_H

#include "dlog.h"

#define DQDK_CONTROLLER_MAX_EVENTS 32

typedef enum {
    DQDK_STATUS_STARTED,
    DQDK_STATUS_READY,
    DQDK_STATUS_CLOSED,
    DQDK_STATUS_ERROR,
} dqdk_status_t;

typedef enum {
    DQDK_CMD_QUERY,
    DQDK_CMD_CLOSE
} dqdk_cmd_t;

typedef struct {
    int serverfd;
    int clientfd;
    int epollfd;
    _Atomic(dqdk_status_t) status;
} dqdk_controller_t;

int dqdk_controller_free(dqdk_controller_t* controller);
dqdk_controller_t* dqdk_controller_start(u16 port);
int dqdk_controller_report_status(dqdk_controller_t* controller, dqdk_status_t status, char* payload);
int dqdk_controller_wait(dqdk_controller_t* controller);
int dqdk_controller_closed(dqdk_controller_t* controller, char* buffer);
int dqdk_controller_error(dqdk_controller_t* controller);
dqdk_status_t dqdk_controller_status(dqdk_controller_t* cntrl);
char* dqdk_controller_status_string(dqdk_status_t status);

#endif
