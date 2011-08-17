#include <libsoup/soup.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>

#include "config.h"


typedef struct _CamareroMemmap {
    void   *mem;
    size_t length;
} CamareroMemmap;


typedef struct _CamareroApp {
    SoupServer *server;
} CamareroApp;
CamareroApp APP = {0,};


static void
camarero_memmap_free (gpointer data) {
    CamareroMemmap *memmap = (CamareroMemmap *) data;
    munmap(memmap->mem, memmap->length);
    g_slice_free(CamareroMemmap, memmap);
}


static int
camarero_array_sort_str (gconstpointer a, gconstpointer b) {
	const char **sa = (const char **)a;
	const char **sb = (const char **)b;
	return g_strcmp0(*sa, *sb);
}


static void
camarero_server_callback (
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

        g_ptr_array_sort(array, (GCompareFunc) camarero_array_sort_str);


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


    // Spit the content's of the file down the pipe
    int fd = g_open(path, O_RDONLY);
    if (fd == -1) {
        g_printf("Can't open %s; %s\n", path, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }


    // Use mmap for sending the file
    CamareroMemmap *memmap = g_slice_new(CamareroMemmap);
    memmap->length = st.st_size;
    memmap->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (memmap->mem == MAP_FAILED) {
        g_slice_free(CamareroMemmap, memmap);
        g_printf("Can't mmap %s; %s\n", path, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }

    SoupBuffer *buffer = soup_buffer_new_with_owner(
        memmap->mem,
        memmap->length,
        memmap,
        camarero_memmap_free
    );
    soup_message_body_append_buffer(msg->response_body, buffer);
    soup_buffer_free(buffer); // It's more of an unref() than a free()

    // Slurp the file's content
    if (0) {
        gchar *buffer = g_malloc(st.st_size);
        read(fd, buffer, st.st_size);
        close(fd);
        soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, buffer, st.st_size);
    }

    status = SOUP_STATUS_OK;

    DONE:
        soup_message_set_status(msg, status);
        g_printf("Request for %s return status code %d\n", path, status);

    return;
}


static void
camarero_signal_end (int signal)
{
    g_printf("Server shutting down\n");
    if (APP.server != NULL) {
        soup_server_quit(APP.server);
        return;
    }

    exit(0);
}


static int
camarero_usage() {
	g_printf(
		"Usage: " PACKAGE_NAME " [OPTION]... FOLDER...\n"
		"Where OPTION is one of:\n"
		"   -p, --port=PORT   the server's port\n"
		"   -v, --version     show the program's version\n"
		"   -h, --help        print this help message\n"
	);
	return 1;
}


int
main (int argc, char ** argv) {

    struct option longopts [] = {
        { "port",       required_argument, NULL, 'p' },
        { "help",       no_argument,       NULL, 'h' },
        { "version",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    unsigned int port = 3000;
    int rc;
    while ( (rc = getopt_long(argc, argv, "phv", longopts, NULL)) != -1 ) {
        switch (rc) {
            case 'p':
                {
                    unsigned int val = (unsigned int) strtol(optarg, NULL, 10);
                    if (val) {
                        g_printf("Parsing port %d\n", val);
                        port = val;
                    }
                    else {
                        g_printf("Can't parse port: %s\n", optarg);
                    }
                }
            break;

            case 'h':
                return camarero_usage();
            break;

            case 'v':
                g_printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
                return 0;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    g_thread_init(NULL);
    g_type_init();

    signal(SIGTERM, camarero_signal_end);
    signal(SIGQUIT, camarero_signal_end);
    signal(SIGINT,  camarero_signal_end);

    APP.server = soup_server_new(
        SOUP_SERVER_PORT, port,
        SOUP_SERVER_SERVER_HEADER, "simple-httpd ",
        NULL
    );
    if (APP.server == NULL) {
        g_printf("Failed to create the server\n");
        return 1;
    }

    soup_server_add_handler(APP.server, NULL, camarero_server_callback, NULL, NULL);
    g_printf("Starting Server on port %d\n", soup_server_get_port(APP.server));
    soup_server_run(APP.server);

    g_printf("Done\n");

    return 0;
}
