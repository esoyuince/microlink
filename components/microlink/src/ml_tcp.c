/**
 * @file ml_tcp.c
 * @brief MicroLink v2 TCP Socket API
 *
 * Provides TCP connections over the Tailscale VPN tunnel.
 * Uses standard BSD sockets routed through the WireGuard netif.
 *
 * lwIP routes 100.64.0.0/10 traffic through the WG netif automatically
 * (set up in ml_wg_mgr.c). This module triggers the WG handshake,
 * waits for tunnel establishment, then lets standard TCP through.
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <string.h>

static const char *TAG = "ml_tcp";

/* ============================================================================
 * Internal Types
 * ========================================================================== */

struct microlink_tcp_socket {
    microlink_t *ml;
    int fd;
    uint32_t peer_ip;
    uint16_t peer_port;
    bool connected;
};

static int tcp_connect_bounded(int fd,const struct sockaddr *addr,socklen_t addrlen,uint32_t timeout_ms)
{
#ifdef CONFIG_ML_ENABLE_CELLULAR
    /* AT sockets own their modem-side connect timeout and don't expose SO_ERROR. */
    if(ml_at_socket_is_at_fd(fd))return ml_connect(fd,addr,addrlen);
#endif
    int flags=ml_fcntl(fd,F_GETFL,0);
    if(flags<0)return -1;
    if(ml_fcntl(fd,F_SETFL,flags|O_NONBLOCK)!=0)return -1;

    int rc=ml_connect(fd,addr,addrlen);
    if(rc==0){ml_fcntl(fd,F_SETFL,flags);return 0;}
    int first_err=errno;
    if(first_err!=EINPROGRESS&&first_err!=EWOULDBLOCK&&first_err!=EALREADY){
        ml_fcntl(fd,F_SETFL,flags);errno=first_err;return -1;
    }

    fd_set wfds;FD_ZERO(&wfds);FD_SET(fd,&wfds);
    struct timeval tv={.tv_sec=timeout_ms/1000,.tv_usec=(timeout_ms%1000)*1000};
    rc=ml_select_fds(fd+1,NULL,&wfds,NULL,&tv);
    if(rc<=0){int saved=rc==0?ETIMEDOUT:errno;ml_fcntl(fd,F_SETFL,flags);errno=saved;return -1;}

    int soerr=0;socklen_t slen=sizeof(soerr);
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&soerr,&slen)!=0){int saved=errno;ml_fcntl(fd,F_SETFL,flags);errno=saved;return -1;}
    ml_fcntl(fd,F_SETFL,flags);
    if(soerr!=0){errno=soerr;return -1;}
    return 0;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

microlink_tcp_socket_t *microlink_tcp_connect(microlink_t *ml, uint32_t dest_ip,
                                                uint16_t dest_port,
                                                uint32_t timeout_ms) {
    if (!ml || dest_ip == 0 || dest_port == 0) {
        ESP_LOGE(TAG, "Invalid args");
        return NULL;
    }
    if (ml->state != ML_STATE_CONNECTED) {
        ESP_LOGE(TAG, "Not connected to Tailscale (state=%d)", ml->state);
        return NULL;
    }

    char ip_str[16];
    microlink_ip_to_str(dest_ip, ip_str);
    ESP_LOGI(TAG, "TCP connect to %s:%u (timeout=%lums)", ip_str, dest_port,
             (unsigned long)timeout_ms);

    uint32_t total_budget_ms=timeout_ms>0?timeout_ms:15000;
    int64_t call_started_us=esp_timer_get_time();
    int64_t deadline_us=call_started_us+(int64_t)total_budget_ms*1000;

    /* Trigger WG handshake + DISCO to wake up the peer connection.
     * Reserve part of the caller's deadline for the actual TCP connect instead
     * of spending the entire timeout polling the WG state. */
    ml_wg_mgr_trigger_handshake(ml, dest_ip);
    ml_wg_mgr_send_cmm(ml, dest_ip);

    uint32_t wait_ms=0;
    uint32_t wg_wait_budget=total_budget_ms>1000?total_budget_ms/2:total_budget_ms;
    if(wg_wait_budget>5000)wg_wait_budget=5000;
    bool tunnel_up=ml_wg_mgr_peer_is_up(ml,dest_ip);
    while(!tunnel_up&&wait_ms<wg_wait_budget){
        uint32_t step=(wg_wait_budget-wait_ms)>500?500:(wg_wait_budget-wait_ms);
        if(step==0)break;
        vTaskDelay(pdMS_TO_TICKS(step));wait_ms+=step;
        tunnel_up=ml_wg_mgr_peer_is_up(ml,dest_ip);
        if(!tunnel_up&&(wait_ms%2000)==0){
            ESP_LOGI(TAG,"WG tunnel not up after %lums, re-triggering handshake",(unsigned long)wait_ms);
            ml_wg_mgr_trigger_handshake(ml,dest_ip);ml_wg_mgr_send_cmm(ml,dest_ip);
        }
    }
    if(tunnel_up)ESP_LOGI(TAG,"WG tunnel up after %lums",(unsigned long)wait_ms);
    else ESP_LOGW(TAG,"WG tunnel not up after %lums, attempting bounded connect",(unsigned long)wait_ms);

    /* Create TCP socket */
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        return NULL;
    }

    /* Bind to our VPN IP so lwIP routes through the WG netif.
     * Without this, the PPP default route may catch 100.x.x.x traffic
     * and send it out the cellular modem raw (unroutable). */
    if (ml->vpn_ip != 0) {
        struct sockaddr_in src = {
            .sin_family = AF_INET,
            .sin_port = 0,  /* ephemeral */
            .sin_addr.s_addr = htonl(ml->vpn_ip),
        };
        if (bind(fd, (struct sockaddr *)&src, sizeof(src)) != 0) {
            ESP_LOGW(TAG, "bind() to VPN IP failed: errno=%d (continuing)", errno);
        } else {
            char src_str[16];
            microlink_ip_to_str(ml->vpn_ip, src_str);
            ESP_LOGI(TAG, "TCP socket bound to VPN IP %s", src_str);
        }
    }

    /* Send/recv timeouts apply after connect. connect() itself is bounded
     * separately with O_NONBLOCK + select + SO_ERROR below. */
    uint32_t send_timeout_ms=total_budget_ms>5000?5000:total_budget_ms;
    if(send_timeout_ms==0)send_timeout_ms=1000;
    struct timeval tv={.tv_sec=send_timeout_ms/1000,.tv_usec=(send_timeout_ms%1000)*1000};
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    struct timeval rtv={.tv_sec=10,.tv_usec=0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&rtv,sizeof(rtv));

    int keepalive=1,keepidle=30,keepintvl=10,keepcnt=3;
    setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&keepalive,sizeof(keepalive));
    setsockopt(fd,IPPROTO_TCP,TCP_KEEPIDLE,&keepidle,sizeof(keepidle));
    setsockopt(fd,IPPROTO_TCP,TCP_KEEPINTVL,&keepintvl,sizeof(keepintvl));
    setsockopt(fd,IPPROTO_TCP,TCP_KEEPCNT,&keepcnt,sizeof(keepcnt));
    int nodelay=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&nodelay,sizeof(nodelay));

    struct sockaddr_in dest={.sin_family=AF_INET,.sin_port=htons(dest_port)};
    dest.sin_addr.s_addr=htonl(dest_ip);

    int64_t remaining_us=deadline_us-esp_timer_get_time();
    if(remaining_us<=0){
        ESP_LOGW(TAG,"TCP connect deadline exhausted before socket connect");close(fd);return NULL;
    }
    uint32_t connect_budget_ms=(uint32_t)((remaining_us+999)/1000);
    if(connect_budget_ms==0)connect_budget_ms=1;
    int64_t tcp_started_us=esp_timer_get_time();
    if(tcp_connect_bounded(fd,(struct sockaddr *)&dest,sizeof(dest),connect_budget_ms)!=0){
        int err=errno;int64_t elapsed_ms=(esp_timer_get_time()-tcp_started_us)/1000;
        ESP_LOGE(TAG,"bounded connect to %s:%u failed: errno=%d elapsed=%lldms budget=%lums",ip_str,dest_port,err,elapsed_ms,(unsigned long)connect_budget_ms);
        close(fd);return NULL;
    }

    int64_t t_end=esp_timer_get_time();
    ESP_LOGI(TAG,"TCP connected to %s:%u (tcp=%lldms total=%lldms)",ip_str,dest_port,
             (t_end-tcp_started_us)/1000,(t_end-call_started_us)/1000);

    /* Allocate handle */
    microlink_tcp_socket_t *sock = calloc(1, sizeof(microlink_tcp_socket_t));
    if (!sock) {
        close(fd);
        return NULL;
    }
    sock->ml = ml;
    sock->fd = fd;
    sock->peer_ip = dest_ip;
    sock->peer_port = dest_port;
    sock->connected = true;

    return sock;
}

esp_err_t microlink_tcp_send(microlink_tcp_socket_t *sock, const void *data, size_t len) {
    if (!sock || !sock->connected || sock->fd < 0) return ESP_ERR_INVALID_STATE;
    if (!data || len == 0) return ESP_ERR_INVALID_ARG;

    size_t sent = 0;
    while (sent < len) {
        int n = send(sock->fd, (const uint8_t *)data + sent, len - sent, 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            ESP_LOGE(TAG, "TCP send failed: n=%d errno=%d (sent %d/%d)",
                     n, errno, (int)sent, (int)len);
            sock->connected = false;
            return ESP_FAIL;
        }
        sent += n;
    }

    return ESP_OK;
}

int microlink_tcp_recv(microlink_tcp_socket_t *sock, void *buffer, size_t len,
                        uint32_t timeout_ms) {
    if (!sock || !sock->connected || sock->fd < 0) return -1;
    if (!buffer || len == 0) return -1;

    if (timeout_ms > 0) {
        struct timeval tv = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000,
        };
        setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    int n = recv(sock->fd, buffer, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  /* Timeout, no data */
        }
        ESP_LOGE(TAG, "TCP recv failed: errno=%d", errno);
        sock->connected = false;
        return -1;
    }
    if (n == 0) {
        /* Peer closed connection */
        ESP_LOGI(TAG, "TCP peer closed connection");
        sock->connected = false;
        return -1;
    }

    return n;
}

bool microlink_tcp_is_connected(const microlink_tcp_socket_t *sock) {
    return sock && sock->connected && sock->fd >= 0;
}

void microlink_tcp_close(microlink_tcp_socket_t *sock) {
    if (!sock) return;

    if (sock->fd >= 0) {
        /* Graceful shutdown */
        shutdown(sock->fd, SHUT_RDWR);
        close(sock->fd);
        sock->fd = -1;
    }

    char ip_str[16];
    microlink_ip_to_str(sock->peer_ip, ip_str);
    ESP_LOGI(TAG, "TCP socket to %s:%u closed", ip_str, sock->peer_port);

    sock->connected = false;
    free(sock);
}
