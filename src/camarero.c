#include <libsoup/soup.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>


static int
array_sort_str (gconstpointer a, gconstpointer b) {
	const char **sa = (const char **)a;
	const char **sb = (const char **)b;
	return g_strcmp0(*sa, *sb);
}


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

    // If we're dealing with a folder do a directory listing
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (dir == NULL) {
            g_printf("Failed to read directory %s; %s\n", path, g_strerror(errno));
            status = SOUP_STATUS_FORBIDDEN;
            goto DONE;
        }

        // Get the folder's contents and sort then by name
        GPtrArray *array = g_ptr_array_new();
        struct dirent *dentry;
        while ( (dentry = readdir(dir)) != NULL ) {
            if (dentry->d_name[0] == '.') {continue;}
            g_ptr_array_add(array, (gpointer) dentry->d_name);
        }
        closedir(dir);

        g_ptr_array_sort(array, (GCompareFunc) array_sort_str);


        // Build an HTML page with the folder contents
        GString *buffer = g_string_new_len(NULL, 4096);
        g_string_append_printf(buffer, "<html><head><title>Dir %s</title></head><body>\n", path);
        g_string_append_printf(buffer, "<h1>Dir %s</h1>\n", path);

        if (array->len) {
            char *lastSlash = strrchr(path, '/');
            g_printf("Last stash: '%s'\n", lastSlash);
            g_printf("Last is NULL: '%s'\n", lastSlash == NULL ? "YES" : "NO");
            g_printf("Last is 0: '%s' %x %c\n", lastSlash[1] != '\0'  ? "YES" : "NO", lastSlash[1], lastSlash[1]);
            const char *separator = (lastSlash == NULL || lastSlash[1] != '\0') ? "/" : "";
            g_printf("separator: '%s'\n", separator);

            g_string_append_printf(buffer, "<p>has %d files</p>\n<ul>\n", array->len);
            for (guint i = 0; i < array->len; ++i) {
                char *name = (char *) array->pdata[i];
                g_string_append_printf(buffer, "  <li><a href='%s%s%s'>%s</li>\n",
                    g_uri_escape_string(path, "/", TRUE),
                    separator,
                    g_uri_escape_string(name, "/", TRUE),
                    name
                );
            }
            g_string_append(buffer, "<ul>\n");
        }
        else {
            g_string_append(buffer, "<p>is empty.</p>\n");
        }
        g_ptr_array_free(array, TRUE);

        g_string_append(buffer, "</body></html>\n");

        soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, buffer->str, buffer->len);
        status = SOUP_STATUS_OK;
        g_string_free(buffer, FALSE);

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
