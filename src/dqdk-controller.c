#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "dlog.h"
#include "ctypes.h"
#include "dqdk-controller.h"

#define SERVER_IP "0.0.0.0"
#define BUFFER_SIZE 64

static int dqdk_set_status(dqdk_controller_t* cntrl, dqdk_status_t status)
{
    if (!cntrl)
        return -EINVAL;

    atomic_store(&cntrl->status, status);
    return 0;
}

static char* dqdk_get_cmd_string(dqdk_cmd_t cmd)
{
    char* values[] = { "QUERY", "CLOSE" };
    return values[cmd];
}

char* dqdk_controller_status_string(dqdk_status_t status)
{
    char* values[] = { "STARTED", "READY", "CLOSED", "ERROR" };
    return values[status];
}

int dqdk_controller_free(dqdk_controller_t* controller)
{
    if (!controller)
        return -EINVAL;

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

dqdk_controller_t* dqdk_controller_start(u16 port)
{
    int opt = 1;
    int ret;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    dqdk_controller_t* controller = malloc(sizeof(dqdk_controller_t));
    controller->serverfd = -1;
    controller->clientfd = -1;
    controller->epollfd = -1;
    atomic_init(&controller->status, DQDK_STATUS_STARTED);

    controller->serverfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (controller->serverfd < 0) {
        dlog_error2("socket", controller->serverfd);
        dqdk_controller_free(controller);
        return NULL;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
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

static int send_status(dqdk_controller_t* controller, char* payload)
{
    dqdk_status_t status = dqdk_controller_status(controller);
    char* status_string = dqdk_controller_status_string(status);

    char string[64];
    snprintf(string, 64, "%s\n", status_string);
    int sent = send(controller->clientfd, string, strlen(string), 0);
    if (sent <= 0) {
        dlog_error2("send", sent);
        return -errno;
    }
    dlog_infov("DQDK status is %s!", status_string);

    if (payload != NULL && strlen(payload) != 0) {
        sent = send(controller->clientfd, payload, strlen(payload), 0);
        if (sent <= 0) {
            dlog_error2("send", sent);
            return -errno;
        }
    }

    return 0;
}

int dqdk_controller_report_status(dqdk_controller_t* controller, dqdk_status_t status, char* payload)
{
    if (dqdk_set_status(controller, status))
        return -EINVAL;

    return send_status(controller, payload);
}

int dqdk_controller_wait(dqdk_controller_t* controller)
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
                        send_status(controller, NULL);
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

int dqdk_controller_closed(dqdk_controller_t* controller, char* buffer)
{
    return dqdk_controller_report_status(controller, DQDK_STATUS_CLOSED, buffer);
}

int dqdk_controller_error(dqdk_controller_t* controller)
{
    return dqdk_controller_report_status(controller, DQDK_STATUS_ERROR, NULL);
}

dqdk_status_t dqdk_controller_status(dqdk_controller_t* controller)
{
    if (!controller)
        return DQDK_STATUS_ERROR;

    return atomic_load(&controller->status);
}
