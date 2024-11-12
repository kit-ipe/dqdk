#ifndef DQDK_CONTROLLER_H
#define DQDK_CONTROLLER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "dqdk.h"

#define DQDK_CONTROLLER_MAX_EVENTS 32
#define SERVER_PORT 8000
#define SERVER_IP "0.0.0.0"
#define BUFFER_SIZE 64

static char* dqdk_get_status_string(dqdk_status_t status)
{
    char* values[] = { "NONE", "STARTED", "READY", "CLOSED" };
    return values[status];
}

typedef enum {
    DQDK_CMD_QUERY,
    DQDK_CMD_CLOSE
} dqdk_cmd_t;

static char* dqdk_get_cmd_string(dqdk_cmd_t cmd)
{
    char* values[] = { "QUERY", "CLOSE" };
    return values[cmd];
}

typedef struct {
    int serverfd;
    int clientfd;
    int epollfd;
} dqdk_controller_t;

int dqdk_controller_free(dqdk_controller_t* controller)
{
    if (!controller)
        return -1;
    if (controller->epollfd > 0) {
        epoll_ctl(controller->epollfd, EPOLL_CTL_DEL, controller->clientfd, NULL);
        close(controller->epollfd);
    }

    if (controller->clientfd > 0)
        close(controller->clientfd);

    if (controller->serverfd > 0)
        close(controller->serverfd);

    free(controller);
    return 0;
}

dqdk_controller_t* dqdk_controller_start()
{
    int opt = 1;
    int ret;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    dqdk_controller_t* controller = malloc(sizeof(dqdk_controller_t));
    controller->serverfd = -1;
    controller->clientfd = -1;
    controller->epollfd = -1;

    controller->serverfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (controller->serverfd < 0) {
        dlog_error2("socket", controller->serverfd);
        dqdk_controller_free(controller);
        return NULL;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    setsockopt(controller->serverfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(controller->serverfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    ret = bind(controller->serverfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        dlog_error2("bind", ret);
        dqdk_controller_free(controller);
        return NULL;
    }

    ret = listen(controller->serverfd, 1);
    if (ret < 0) {
        dlog_error2("bind", ret);
        dqdk_controller_free(controller);
        return NULL;
    }

    controller->epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (controller->epollfd < 0) {
        dlog_error2("epoll_create1", controller->epollfd);
        dqdk_controller_free(controller);
        return NULL;
    }

    controller->clientfd = accept4(controller->serverfd, (struct sockaddr*)&client_addr, &client_addr_len, SOCK_CLOEXEC);
    if (controller->clientfd < 0) {
        dlog_error2("accept", controller->clientfd);
        dqdk_controller_free(controller);
        return NULL;
    }

    struct epoll_event event;
    memset(&event, 0, sizeof(struct epoll_event));
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR;
    event.data.fd = controller->clientfd;

    ret = epoll_ctl(controller->epollfd, EPOLL_CTL_ADD, controller->clientfd, &event);
    if (ret < 0) {
        dlog_error2("epoll_ctl", ret);
        dqdk_controller_free(controller);
        return NULL;
    }

    dlog_info("Control Software connected!");

    return controller;
}

int dqdk_controller_wait(dqdk_controller_t* controller, dqdk_ctx_t* ctx)
{
    int ret;
    char buffer[BUFFER_SIZE];

    if (controller == NULL)
        return -1;

    struct epoll_event events[DQDK_CONTROLLER_MAX_EVENTS];
    while (1) {
        ret = epoll_wait(controller->epollfd, events, DQDK_CONTROLLER_MAX_EVENTS, 3000);
        if (ret == 0)
            continue;

        if (ret < 0)
            break;

        for (int i = 0; i < ret; i++) {
            int fd = events[i].data.fd;
            u32 fd_events = events[i].events;
            if (fd_events & EPOLLIN) {
                memset(buffer, 0, BUFFER_SIZE);
                int rcvd = recv(fd, buffer, BUFFER_SIZE, 0);
                if (rcvd > 0) {
                    char* cmd_string = dqdk_get_cmd_string(DQDK_CMD_CLOSE);
                    if (!strncmp(buffer, cmd_string, strlen(cmd_string))) {
                        return DQDK_CMD_CLOSE;
                    }

                    cmd_string = dqdk_get_cmd_string(DQDK_CMD_QUERY);
                    if (!strncmp(buffer, cmd_string, strlen(cmd_string))) {
                        char* status_string = dqdk_get_status_string(ctx->status);
                        send(fd, status_string, strlen(status_string), 0);
                    } else {
                        dlog_errorv("Ignoring unknown command: %s", buffer);
                    }
                }
            }

            if ((fd_events & EPOLLRDHUP)
                || (fd_events & EPOLLPRI)
                || (fd_events & EPOLLERR)) {
                dlog_error("Connection to Control Software lost!");
                return -1;
            }
        }
    }

    return 0;
}

int dqdk_controller_closed(dqdk_controller_t* controller)
{
    if (controller == NULL)
        return -1;

    char* status_string = dqdk_get_status_string(DQDK_STATUS_CLOSED);
    int sent = send(controller->clientfd, status_string, strlen(status_string), 0);
    if (sent <= 0) {
        dlog_error2("send", sent);
        return -1;
    }

    dlog_info("DQDK status changed to closed!");
    dqdk_controller_free(controller);
    return 0;
}

#endif
