/*
 * camarero.c
 * This file is part of camarero
 *
 * Copyright (C) 2011 - Emmanuel Rodriguez
 *
 * camarero is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * camarero is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libgit2-glib; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

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
#include <unistd.h>
#include <sys/param.h>

#include "config.h"

#if GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 30
#   define g_format_size g_format_size_for_display
#endif


typedef struct _CamareroMemmap {
    void   *mem;
    size_t length;
    int    fd;
} CamareroMemmap;


typedef struct _CamareroApp {
    SoupServer  *server;
    gchar       root [MAXPATHLEN + 1];
    size_t      root_len;
    gboolean    jail;
    guint64     bytes;
    uint        requests;
    gchar       *username;
    gchar       *password;
} CamareroApp;
CamareroApp APP = {0,};


static void
camarero_memmap_free (gpointer data) {
    CamareroMemmap *memmap = (CamareroMemmap *) data;
    munmap(memmap->mem, memmap->length);
    close(memmap->fd);
    g_slice_free(CamareroMemmap, memmap);
}


static int
camarero_array_sort_str (gconstpointer a, gconstpointer b) {
	const char **sa = (const char **)a;
	const char **sb = (const char **)b;
	return g_strcmp0(*sa, *sb);
}


static void
camarero_favicon_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {
    soup_message_set_status(msg, SOUP_STATUS_NOT_FOUND);
    soup_message_body_append(msg->response_body, SOUP_MEMORY_STATIC, "", 0);
}

static void
camarero_server_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {
    int status;
    size_t len;
    gchar *error_str = NULL;

    gchar *fpath = g_build_filename(APP.root, path, NULL);
    if (APP.jail) {
        char *rpath = realpath(fpath, NULL);
        if (rpath == NULL) {
            error_str = g_strdup_printf("Can't find real path for %s; %s", fpath, g_strerror(errno));
            status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
            goto DONE;
        }

        int cmp = strncmp(APP.root, rpath, APP.root_len);
        if (cmp != 0 || (rpath[APP.root_len] != '/' && rpath[APP.root_len] != '\0')) {
            error_str = g_strdup_printf("File %s is not under the root folder %s", rpath, APP.root);
            free(rpath);
            status = SOUP_STATUS_FORBIDDEN;

            goto DONE;
        }

        free(rpath);
    }

    // Get the file size
    GStatBuf st;
    int code = g_stat(fpath, &st);
    if (code == -1) {
        switch (errno) {
            case EPERM:
                error_str = g_strdup_printf("Inadequate file permissions %s; %s", fpath, g_strerror(errno));
                status = SOUP_STATUS_FORBIDDEN;
            break;

            case ENOENT:
                error_str = g_strdup_printf("File %s not found; %s", fpath, g_strerror(errno));
                status = SOUP_STATUS_NOT_FOUND;
            break;

            default:
                error_str = g_strdup_printf("Other error for %s; %s", fpath, g_strerror(errno));
                status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
            break;
        }

        goto DONE;
    }

    // If we're dealing with a folder do a directory listing
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(fpath);
        if (dir == NULL) {
            error_str = g_strdup_printf("Failed to read directory %s; %s", fpath, g_strerror(errno));
            status = SOUP_STATUS_FORBIDDEN;
            goto DONE;
        }

        // Get the folder's contents and sort them by name
        GPtrArray *array = g_ptr_array_new();
        struct dirent *dentry;
        while ( (dentry = readdir(dir)) != NULL ) {
            if (dentry->d_name[0] == '.') {continue;}
            g_ptr_array_add(array, (gpointer) g_strdup(dentry->d_name));
        }
        closedir(dir);

        g_ptr_array_sort(array, (GCompareFunc) camarero_array_sort_str);


        // Build an HTML page with the folder contents
        GString *buffer = g_string_new_len(NULL, 4096);
        g_string_append_printf(buffer, "<html><head><title>Dir %s</title></head><body>\n", path);
        g_string_append_printf(buffer, "<h1>Dir %s</h1>\n", path);

        if (array->len) {
            char *lastSlash = strrchr(path, '/');
            const char *separator = (lastSlash == NULL || lastSlash[1] != '\0') ? "/" : "";

            g_string_append_printf(buffer, "<p>has %d files</p>\n<ul>\n", array->len);
            for (guint i = 0; i < array->len; ++i) {
                char *name = (char *) array->pdata[i];
                char *u_path = g_uri_escape_string(path, "/", TRUE);
                char *u_name = g_uri_escape_string(name, "/", TRUE);

                g_string_append_printf(buffer, "  <li><a href='%s%s%s'>%s</li>\n",
                    u_path,
                    separator,
                    u_name,
                    name
                );
                g_free(u_path);
                g_free(u_name);
            }
            g_string_append(buffer, "<ul>\n");
        }
        else {
            g_string_append(buffer, "<p>is empty.</p>\n");
        }
        for (guint i = 0; i < array->len; ++i) {
            g_free(array->pdata[i]);
        }
        g_ptr_array_free(array, TRUE);

        g_string_append(buffer, "</body></html>\n");

        soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, buffer->str, buffer->len);
        len = buffer->len;
        status = SOUP_STATUS_OK;
        g_string_free(buffer, FALSE);

        goto DONE;
    }


    // Spit the content's of the file down the pipe
    int fd = g_open(fpath, O_RDONLY);
    if (fd == -1) {
        error_str = g_strdup_printf("Can't open %s; %s", fpath, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }


    // Use mmap for sending the file
    CamareroMemmap *memmap = g_slice_new(CamareroMemmap);
    memmap->length = st.st_size;
    memmap->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    memmap->fd = fd;
    if (memmap->mem == MAP_FAILED) {
        close(fd);
        g_slice_free(CamareroMemmap, memmap);
        error_str = g_strdup_printf("Can't mmap %s; %s", fpath, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }

    SoupBuffer *buffer = soup_buffer_new_with_owner(
        memmap->mem,
        memmap->length,
        memmap,
        camarero_memmap_free
    );
    len = memmap->length;
    soup_message_body_append_buffer(msg->response_body, buffer);
    soup_buffer_free(buffer); // It's more of an unref() than a free()

    status = SOUP_STATUS_OK;

    DONE:
        soup_message_set_status(msg, status);
        if (fpath != NULL) g_free(fpath);
        if (error_str != NULL) {
            len = strlen(error_str);
            soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, error_str, len);
            gchar *size = g_format_size(len);
            g_printf("%3d %s (%s) - %s\n", status, path, size, error_str);
            g_free(size);
        }
        else {
            gchar *size = g_format_size(len);
            g_printf("%3d %s (%s)\n", status, path, size);
            g_free(size);
        }
        ++APP.requests;
        APP.bytes = len;
}


static gboolean
camarero_auth_callback (
    SoupAuthDomain *auth_domain, SoupMessage *msg,
    const char *username, const char *password, gpointer data
) {
    return strcmp(APP.username, username) == 0 && strcmp(APP.password, password) == 0;
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
		"Usage: " PACKAGE_NAME " [OPTION]... FOLDER\n"
		"Where OPTION is one of:\n"
		"   -u, --username=USER   username that clients have to provide for connecting\n"
		"   -P, --password=PWD    password that clients have to provide for connecting\n"
		"   -j, --jail            only serve files that are under the root folder\n"
		"   -p, --port=PORT       the server's port\n"
		"   -v, --version         show the program's version\n"
		"   -h, --help            print this help message\n"
	);
	return 1;
}


int
main (int argc, char ** argv) {

    struct option longopts [] = {
        { "username",   required_argument, NULL, 'u' },
        { "password",   required_argument, NULL, 'P' },
        { "jail",       no_argument,       NULL, 'j' },
        { "port",       required_argument, NULL, 'p' },
        { "help",       no_argument,       NULL, 'h' },
        { "version",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    unsigned int port = 3000;
    int rc;
    while ( (rc = getopt_long(argc, argv, "uPjphv", longopts, NULL)) != -1 ) {
        switch (rc) {
            case 'u':
                {
                    APP.username = g_strdup(optarg);
                    size_t len = strlen(optarg);
                    memset(optarg, '*', len);
                }
            break;

            case 'P':
                {
                    APP.password = g_strdup(optarg);
                    size_t len = strlen(optarg);
                    memset(optarg, '*', len);
                }
            break;

            case 'j':
                APP.jail = TRUE;
            break;

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

    // Get the root folder
    gchar root [MAXPATHLEN + 1];
    if (argc) {
        memcpy(root, argv[0], strlen(argv[0]) + 1);
    }
    else {
        getcwd(root, sizeof(root));
    }

    char *ptr = realpath(root, APP.root);
    if (ptr == NULL) {
        g_printf("Document folder %s doesn't exist; %s\n", root, g_strerror(errno));
        return 1;
    }
    APP.root_len = strlen(APP.root);

    g_thread_init(NULL);
    g_type_init();

    signal(SIGTERM, camarero_signal_end);
    signal(SIGQUIT, camarero_signal_end);
    signal(SIGINT,  camarero_signal_end);

    APP.server = soup_server_new(
        SOUP_SERVER_PORT, port,
        SOUP_SERVER_SERVER_HEADER, PACKAGE_NAME " ",
        NULL
    );
    if (APP.server == NULL) {
        g_printf("Failed to create the server\n");
        return 1;
    }

    if (APP.username != NULL && APP.password != NULL) {
        SoupAuthDomain *auth_domain = soup_auth_domain_basic_new(
            SOUP_AUTH_DOMAIN_REALM, PACKAGE_NAME,
            SOUP_AUTH_DOMAIN_ADD_PATH, "/",
            SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, camarero_auth_callback,
            NULL
        );
        soup_server_add_auth_domain(APP.server, auth_domain);
        g_object_unref(auth_domain);
    }
    else if (APP.username != NULL) {
        g_printf("Provide a password with --password\n");
        return 1;
    }
    else if (APP.password != NULL) {
        g_printf("Provide a username with --username\n");
        return 1;
    }

    soup_server_add_handler(APP.server, "/favicon.ico", camarero_favicon_callback, NULL, NULL);
    soup_server_add_handler(APP.server, NULL, camarero_server_callback, NULL, NULL);
    g_printf("Starting server on port %d for %s\n", port, APP.root);
    soup_server_run(APP.server);

    g_free(APP.username);
    g_free(APP.password);

    gchar *size = g_format_size(APP.bytes);
    g_print("Served %d requests (%s)\n", APP.requests, size);
    g_free(size);

    g_printf("Done\n");

    return 0;
}
