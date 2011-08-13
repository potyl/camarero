#include <libsoup/soup.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>


static void
server_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {

    int status;

    // Get the file size
    GStatBuf st;
    int code = g_stat(path, &st);
    if (code == -1) {
        switch (errno) {
            case EPERM:
                status = SOUP_STATUS_FORBIDDEN;
            break;

            case ENOENT:
                status = SOUP_STATUS_NOT_FOUND;
            break;

            default:
                status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
            break;
        }
        goto DONE;
    }

    // Slurp the file and return it
    int fd = g_open(path, O_RDONLY);
    if (fd == -1) {
        g_printf("Can't open %s; %s\n", path, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }
    gchar *buffer = g_malloc(st.st_size);
    read(fd, buffer, st.st_size);
    close(fd);
    soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, buffer, st.st_size);
    status = SOUP_STATUS_OK;

    DONE:
        soup_message_set_status(msg, status);
        g_printf("Request for %s return status code %d\n", path, status);

    return;
}


int
main (int argc, char ** argv) {
    g_thread_init(NULL);
    g_type_init();

    SoupServer *server = soup_server_new(
        SOUP_SERVER_PORT, 3000,
        SOUP_SERVER_SERVER_HEADER, "simple-httpd ",
        NULL
    );

    soup_server_add_handler(server, NULL, server_callback, NULL, NULL);
    g_printf("\nStarting Server on port %d\n", soup_server_get_port(server));
    soup_server_run_async(server);

    GMainLoop *loop = g_main_loop_new(NULL, TRUE);
    g_main_loop_run(loop);

    return 0;
}
