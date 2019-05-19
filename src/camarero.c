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

#define _XOPEN_SOURCE 500

#include <libsoup/soup.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#define __USE_BSD
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "config.h"
#include "camarero-mime-types.h"
#include "camarero-resources.h"


#if !GLIB_CHECK_VERSION(2, 30, 0)
#   define g_format_size g_format_size_for_display
#endif

#if !GLIB_CHECK_VERSION(2, 24, 0)
#   if defined (_MSC_VER) && !defined(_WIN64)
typedef struct _stat32 GStatBuf;
#   else
typedef struct stat GStatBuf;
#   endif
#endif


#define CHUNK_SIZE 5 * 1024 * 1024

typedef struct _CamareroMemmap {
    void   *mem;
    void   *ptr;
    size_t length;
    int    fd;
    size_t offset;
} CamareroMemmap;


typedef struct _CamareroDirEntry {
    gchar    *name;
    GStatBuf stat;
} CamareroDirEntry;


typedef struct _CamareroApp {
    SoupServer  *server;
    gchar       root [MAXPATHLEN + 1];
    size_t      root_len;
    gboolean    jail;
    guint64     bytes;
    guint       requests;
    gchar       *username;
    gchar       *password;
    GHashTable  *mime_types;
    GResource   *gresource;
} CamareroApp;
CamareroApp APP = {0,};


static void
camarero_app_free () {

    if (APP.server != NULL) {
        g_object_unref(G_OBJECT(APP.server));
        APP.server = NULL;
    }


    if (APP.username != NULL) {
        g_free(APP.username);
        APP.username = NULL;
    }

    if (APP.password != NULL) {
        g_free(APP.password);
        APP.password = NULL;
    }

    if (APP.mime_types != NULL) {
        g_hash_table_unref(APP.mime_types);
        APP.mime_types = NULL;
    }


    if (APP.gresource != NULL) {
        g_resource_unref(APP.gresource);
        APP.gresource = NULL;
    }
}


static void
camarero_memmap_free (CamareroMemmap *memmap) {
    if (memmap->mem != NULL) munmap(memmap->mem, memmap->length);
    close(memmap->fd);
    g_free(memmap);
}


static int
camarero_array_sort_dir_entry (gconstpointer a, gconstpointer b) {
    const CamareroDirEntry **da = (const CamareroDirEntry **) a;
    const CamareroDirEntry **db = (const CamareroDirEntry **) b;

    return g_strcmp0((*da)->name, (*db)->name);
}


static void
camarero_favicon_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {
    GError *error = NULL;
    GBytes *bytes = g_resource_lookup_data(APP.gresource, "/camarero/icons/favicon.ico", G_RESOURCE_LOOKUP_FLAGS_NONE, &error);
    if (bytes != NULL) {
        soup_message_set_status(msg, SOUP_STATUS_OK);
        gsize size;
        gconstpointer data = g_bytes_get_data(bytes, &size);
        soup_message_body_append(msg->response_body, SOUP_MEMORY_COPY, data, size);
        g_bytes_unref(bytes);

        //gchar *size_str = g_format_size(size);
        //g_printf("%3d %s (%s)\n", SOUP_STATUS_OK, path, size_str);
        //g_free(size_str);
        return;
    }

    g_printf("Couldn't find resource for favicon: %s; %s", path, error->message);
    g_error_free(error);

    soup_message_set_status(msg, SOUP_STATUS_NOT_FOUND);
    soup_message_body_append(msg->response_body, SOUP_MEMORY_STATIC, "", 0);
    //g_printf("%3d %s (0 bytes)\n", SOUP_STATUS_NOT_FOUND, path);
}


static void
camarero_memmap_message_free (SoupMessage *msg, gpointer data) {
    CamareroMemmap *memmap = (CamareroMemmap *) data;
    camarero_memmap_free(memmap);
    g_object_unref(msg);
}


static void
camarero_memmap_message_write (SoupMessage *msg, SoupBuffer *buffer, gpointer data) {
    CamareroMemmap *memmap = (CamareroMemmap *) data;

    size_t chunk_len = (memmap->length - memmap->offset);
    if (chunk_len == 0) {
        soup_message_body_complete(msg->response_body);
        soup_server_unpause_message(APP.server, msg);
        return;
    }
    else if (chunk_len > CHUNK_SIZE) {
        chunk_len = CHUNK_SIZE;
    }
    soup_message_body_append(msg->response_body, SOUP_MEMORY_STATIC, memmap->ptr, chunk_len);
    memmap->ptr += chunk_len;
    memmap->offset += chunk_len;
    soup_server_unpause_message(APP.server, msg);
}


static gboolean
camarero_regexp_callback (const GMatchInfo *info, GString *buffer, gpointer data) {
    gchar *match = g_match_info_fetch(info, 0);
    gchar *value = g_hash_table_lookup((GHashTable *)data, match);
    if (value == NULL) value = "";
    g_string_append(buffer, value);
    g_free(match);

    return FALSE;
}


static void
camarero_server_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {
    int status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
    size_t len = 0;
    gchar *error_str = NULL;
    const gchar *content_type = NULL;
    gboolean is_paused = FALSE;


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

        // Make sure that the URI path for a folder ends with / otherwise do a redirect
        gchar *last_slash = strrchr(path, '/');
        if (last_slash == NULL || last_slash[1] != '\0') {
            // The path points to a folder but is missing the last '/'
            gchar *redirect = g_strdup_printf("%s/", path);
            status = SOUP_STATUS_MOVED_PERMANENTLY;
            soup_message_headers_append(msg->response_headers, "Location", redirect);
            g_free(redirect);
            goto DONE;
        }

        // Try to serve an index.html, if there's one
        gchar *index_path = g_build_filename(APP.root, path, "index.html", NULL);
        GStatBuf index_st;
        gboolean show_dir = FALSE;
        code = g_stat(index_path, &index_st);
        g_free(index_path);
        if (code == 0) {
            // The path points to a folder that has an index.html, lets redirect the client there
            gchar *redirect = g_build_filename(path, "index.html", NULL);
            status = SOUP_STATUS_MOVED_PERMANENTLY;
            soup_message_headers_append(msg->response_headers, "Location", redirect);
            g_free(redirect);
            goto DONE;
        }
        else {
            // There's no /index.html, we will list the contents of the folder
            show_dir = TRUE;
        }

        if (show_dir) {
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
                CamareroDirEntry *dir_entry = g_slice_new(CamareroDirEntry);
                dir_entry->name = g_strdup(dentry->d_name);

                // Perform a stat for the entry
                GStatBuf entry_st;
                gchar *entry_path = g_build_filename(APP.root, path, dentry->d_name, NULL);
                code = g_stat(entry_path, &entry_st);
                g_free(entry_path);
                if (code == 0) {
                    memcpy(&(dir_entry->stat), &entry_st, sizeof(entry_st));
                }

                g_ptr_array_add(array, (gpointer) dir_entry);
            }
            closedir(dir);

            g_ptr_array_sort(array, (GCompareFunc) camarero_array_sort_dir_entry);


            // Build an HTML page with the folder contents

            GString *buffer = g_string_sized_new(4096);
            if (array->len) {
                g_string_append_printf(buffer, "<p>%d files</p>\n<ul>\n", array->len);
                for (guint i = 0; i < array->len; ++i) {
                    CamareroDirEntry *entry = (CamareroDirEntry *) array->pdata[i];
                    gchar *u_name = g_uri_escape_string(entry->name, "/", TRUE);
                    if (S_ISDIR(entry->stat.st_mode)) {
                        g_string_append_printf(buffer, "  <li><a href='%s/'>%s/</a></li>\n",
                            u_name, entry->name
                        );
                    }
                    else {
                        gchar *size = g_format_size(entry->stat.st_size);
                        g_string_append_printf(buffer, "  <li><a href='%s'>%s</a> (%s)</li>\n",
                            u_name, entry->name, size
                        );
                        g_free(size);
                    }
                    g_free(u_name);
                    g_free(entry->name);
                    g_slice_free(CamareroDirEntry, entry);
                }
                g_string_append(buffer, "<ul>\n");
            }
            else {
                g_string_append(buffer, "<p>is empty.</p>\n");
            }
            g_ptr_array_free(array, TRUE);


            GBytes *bytes = g_resource_lookup_data(APP.gresource, "/camarero/html/index.html", G_RESOURCE_LOOKUP_FLAGS_NONE, NULL);
            if (bytes == NULL) {
                g_string_free(buffer, TRUE);
                error_str = g_strdup_printf("Can't find document template: %s", "/camarero/html/index.html");
                status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
                goto DONE;
            }

            content_type = "text/html";
            gchar *template = NULL;
            gsize size;
            gconstpointer data = g_bytes_get_data(bytes, &size);
            template = g_strndup(data, size);
            g_bytes_unref(bytes);

            // Create the document's body with all variable interpolated
            GHashTable *vars = g_hash_table_new(g_str_hash, g_str_equal);
            g_hash_table_insert(vars, "$body", buffer->str);
            g_hash_table_insert(vars, "$path", (gpointer) path);

            GRegex *regex = g_regex_new("\\$\\w+", 0, 0, NULL);
            gchar *doc = g_regex_replace_eval(regex, template, -1, 0, 0, camarero_regexp_callback, vars, NULL);
            g_free(template);
            g_hash_table_destroy(vars);
            g_string_free(buffer, FALSE);
            g_regex_unref(regex);

            len = strlen(doc);
            soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, doc, len);
            status = SOUP_STATUS_OK;

            goto DONE;
        }
    }

    char *extension = strrchr(fpath, '.');
    if (extension != NULL) {
        extension = g_ascii_strdown(extension + 1, -1);
        if (extension != NULL) {
            const gchar *mime_type = g_hash_table_lookup(APP.mime_types, extension);
            g_free(extension);
            if (mime_type != NULL) {
                content_type = mime_type;
            }
        }
    }

    if (st.st_size == 0) {
        // Mmap doesn't like to load files with a size of 0
        status = SOUP_STATUS_OK;
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
    CamareroMemmap *memmap = g_new0(CamareroMemmap, 1);
    len = memmap->length = st.st_size;
    memmap->offset = 0;
    memmap->ptr = memmap->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    memmap->fd = fd;
    if (memmap->mem == MAP_FAILED) {
        memmap->mem = NULL;
        camarero_memmap_free(memmap);
        error_str = g_strdup_printf("Can't mmap %s; %s", fpath, g_strerror(errno));
        status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        goto DONE;
    }

    // We can't send a big file  (a DVD image) in one single buffer. If we try
    // to then gio will not like to send that many bytes. What we will do
    // instead is to use callbacks to send the data chunk by chunk. As soon as
    // we write a chunk down the wire we will write the next chunk. This is
    // handled through the signal "wrote-body-data".
    soup_message_headers_set_content_length(msg->response_headers, memmap->length);
    //soup_message_headers_set_encoding(msg->response_headers, SOUP_ENCODING_CHUNKED);
    is_paused = TRUE;
    soup_message_body_set_accumulate(msg->response_body, FALSE);
    g_signal_connect(G_OBJECT(msg), "wrote-body-data", G_CALLBACK(camarero_memmap_message_write), memmap);
    g_signal_connect(G_OBJECT(msg), "finished", G_CALLBACK(camarero_memmap_message_free), memmap);

    status = SOUP_STATUS_OK;

    DONE:
        if (content_type != NULL) {
            soup_message_headers_append(msg->response_headers, "Content-Type", content_type);
        }

        soup_message_set_status(msg, status);
        if (fpath != NULL) g_free(fpath);
        if (error_str != NULL) {
            len = strlen(error_str);
            soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, error_str, len);
            gchar *size = g_format_size(len);
            g_printf("%3d %s (%s) - %s\n", status, path, size, error_str);
            g_free(size);
        }

        if (is_paused) {
            gchar *size = g_format_size(len);
            g_printf("%3d %s (%s)\n", status, path, size);
            g_free(size);

            g_object_ref(msg);
            soup_server_pause_message(APP.server, msg);
            camarero_memmap_message_write(msg, NULL, memmap);
            soup_server_unpause_message(APP.server, msg);
        }

        ++APP.requests;
        APP.bytes += len;
}


static gboolean
camarero_basic_auth_callback (
    SoupAuthDomain *auth_domain, SoupMessage *msg,
    const char *username, const char *password, gpointer data
) {
    return strcmp(APP.username, username) == 0 && strcmp(APP.password, password) == 0;
}


static char*
camarero_digest_auth_callback (
    SoupAuthDomain *auth_domain, SoupMessage *msg,
    const char *username, gpointer data)
{
    if (strcmp(APP.username, username) != 0) {
        return NULL;
    }

    // The password is already the digest
    return g_strdup(APP.password);
}


static void
camarero_signal_end (int signal)
{
    g_printf("Server shutting down\n");
    if (APP.server != NULL) {
        soup_server_quit(APP.server);
        return;
    }

    camarero_app_free();
    exit(0);
}


static int
camarero_usage() {
    g_printf(
        "Usage: " PACKAGE_NAME " [OPTION]... FOLDER\n"
        "Where OPTION is one of:\n"
        "   -s, --show-address    show the URLs where the server can be reached\n"
        "   -c, --ssl-cert=FILE   the SSL certificate\n"
        "   -k, --ssk-key=FILE    the SSL private key\n"
        "   -a, --auth=METHOD     the authorization method to use: digest (default) or basic\n"
        "   -u, --username=USER   username that clients have to provide for connecting\n"
        "   -P, --password=PWD    password that clients have to provide for connecting\n"
        "   -j, --jail            only serve files that are under the root folder\n"
        "   -p, --port=PORT       the server's port (pass 'random' for a random port)\n"
        "   -v, --version         show the program's version\n"
        "   -h, --help            print this help message\n"
    );
    return 1;
}


#if defined DEBUG

static void
camarero_quit_callback (
    SoupServer *server, SoupMessage *msg,
    const char *path, GHashTable *query,
    SoupClientContext *context, gpointer data
) {
    camarero_signal_end(0);
}

#endif


int
main (int argc, char ** argv) {
    int exit_value = 0;

    struct option longopts [] = {
        { "show-address", no_argument,       NULL, 's' },
        { "ssl-cert",     required_argument, NULL, 'c' },
        { "ssl-key",      required_argument, NULL, 'k' },
        { "auth",         required_argument, NULL, 'a' },
        { "username",     required_argument, NULL, 'u' },
        { "password",     required_argument, NULL, 'P' },
        { "jail",         no_argument,       NULL, 'j' },
        { "port",         required_argument, NULL, 'p' },
        { "help",         no_argument,       NULL, 'h' },
        { "version",      no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    unsigned int port = 3000;
    gboolean auth_digest = TRUE;
    gchar *ssl_cert = NULL;
    gchar *ssl_key = NULL;
    gboolean show_addresses = FALSE;
    int rc;
    while ( (rc = getopt_long(argc, argv, "sc:k:a:u:P:jp:hv", longopts, NULL)) != -1 ) {
        switch (rc) {
            case 's':
                show_addresses = TRUE;
            break;

            case 'c':
                    if (optarg == NULL) {
                        g_printf("Missing SSL certificate\n");
                        goto FAIL;
                    }

                    ssl_cert = optarg;
            break;

            case 'k':
                    if (optarg == NULL) {
                        g_printf("Missing SSL private key\n");
                        goto FAIL;
                    }

                    ssl_key = optarg;
            break;

            case 'a':
                {
                    if (optarg == NULL) {
                        g_printf("Missing authentication method name\n");
                        goto FAIL;
                    }
                    else if (strcmp(optarg, "basic") == 0) {
                        auth_digest = FALSE;
                    }
                    else if (strcmp(optarg, "digest") == 0) {
                        auth_digest = TRUE;
                    }
                    else {
                        g_printf("Unrecognized authentication method: %s", optarg);
                        goto FAIL;
                    }
                }
            break;

            case 'u':
                {
                    if (optarg == NULL) {
                        g_printf("Missing username value\n");
                        goto FAIL;
                    }
                    APP.username = g_strdup(optarg);
                    size_t len = strlen(optarg);
                    memset(optarg, '*', len);
                }
            break;

            case 'P':
                {
                    if (optarg == NULL) {
                        g_printf("Missing password value\n");
                        goto FAIL;
                    }
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
                    if (optarg == NULL) {
                        g_printf("Missing port value\n");
                        goto FAIL;
                    }
                    else if (strcmp(optarg, "random") == 0) {
                        port = SOUP_ADDRESS_ANY_PORT;
                    }
                    else {
                        unsigned int val = (unsigned int) strtol(optarg, NULL, 10);
                        if (val) {
                            port = val;
                        }
                        else {
                            g_printf("Can't parse port: %s\n", optarg);
                        }
                    }
                }
            break;

            case 'h':
                camarero_usage();
                goto DONE;
            break;

            case 'v':
                g_printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
                goto DONE;
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
        goto FAIL;
    }
    APP.root_len = strlen(APP.root);

    g_thread_init(NULL);
    g_type_init();

    APP.gresource = camarero_get_resource();

    signal(SIGTERM, camarero_signal_end);
    signal(SIGQUIT, camarero_signal_end);
    signal(SIGINT,  camarero_signal_end);

    // Create the server instance
    if (ssl_cert == NULL && ssl_key == NULL) {
        // HTTP server
        APP.server = soup_server_new(
            SOUP_SERVER_PORT, port,
            SOUP_SERVER_SERVER_HEADER, PACKAGE_NAME "/" PACKAGE_VERSION,
            NULL
        );
    }
    else if (ssl_cert != NULL && ssl_key != NULL) {
        // HTTPS SSL server
        APP.server = soup_server_new(
            SOUP_SERVER_PORT, port,
            SOUP_SERVER_SERVER_HEADER, PACKAGE_NAME "/" PACKAGE_VERSION,
            SOUP_SERVER_SSL_CERT_FILE, ssl_cert,
            SOUP_SERVER_SSL_KEY_FILE,  ssl_key,
            NULL
        );
    }
    else if (ssl_cert == NULL) {
        g_printf("Provide a SSL certificate with --ssl-cert\n");
        goto FAIL;
    }
    else {
        g_printf("Provide a SSL key with --ssl-key\n");
        goto FAIL;
    }

    // A server should be created
    if (APP.server == NULL) {
        g_printf("Failed to create the server\n");
        goto FAIL;
    }
    port = soup_server_get_port(APP.server);


    // Check if the pages have to be protected by a username/password
    if (APP.username != NULL && APP.password != NULL) {
        SoupAuthDomain *auth_domain;
        if (auth_digest) {
            // Since we have a single user/password we can generate the digest
            char *password = APP.password;
            APP.password = soup_auth_domain_digest_encode_password(APP.username, PACKAGE_NAME, APP.password);
            g_free(password);

            auth_domain = soup_auth_domain_digest_new(
                SOUP_AUTH_DOMAIN_REALM, PACKAGE_NAME,
                SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, camarero_digest_auth_callback,
                NULL
            );
        }
        else {
            auth_domain = soup_auth_domain_basic_new(
                SOUP_AUTH_DOMAIN_REALM, PACKAGE_NAME,
                SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, camarero_basic_auth_callback,
                NULL
            );
        }
        soup_auth_domain_add_path(auth_domain, "/");
        soup_server_add_auth_domain(APP.server, auth_domain);
        g_object_unref(auth_domain);
    }
    else if (APP.username != NULL) {
        g_printf("Provide a password with --password\n");
        goto FAIL;
    }
    else if (APP.password != NULL) {
        g_printf("Provide a username with --username\n");
        goto FAIL;
    }


    // Register ou handler and one to get rid of favicon.ico requests
#if defined DEBUG
    soup_server_add_handler(APP.server, "/QUIT", camarero_quit_callback, NULL, NULL);
#endif
    soup_server_add_handler(APP.server, "/favicon.ico", camarero_favicon_callback, NULL, NULL);
    soup_server_add_handler(APP.server, NULL, camarero_server_callback, NULL, NULL);


    // Print the URLs that can be used to reach this server
    if (show_addresses) {
        g_printf("Server is reachable at the following URLs:\n");
        struct ifaddrs *if_addrs = NULL;
        getifaddrs(&if_addrs);
        const char *format = soup_server_is_https(APP.server) ? "  https://%s:%d/n" : "  http://%s:%d/\n";
        GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        for (struct ifaddrs *ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
                // IP4
                char address[INET_ADDRSTRLEN];
                struct in_addr *addr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, addr, address, INET_ADDRSTRLEN);
                struct hostent *host = gethostbyaddr(addr, INET_ADDRSTRLEN, ifa->ifa_addr->sa_family);
                if (host != NULL && g_hash_table_lookup(seen, host->h_name) == NULL) {
                    gchar *name = g_strdup(host->h_name);
                    g_hash_table_insert(seen, name, name);
                    g_printf(format, name, port);
                }
                if (g_hash_table_lookup(seen, address) == NULL) {
                    gchar *name = g_strdup(address);
                    g_hash_table_insert(seen, name, name);
                    g_printf(format, name, port);
                }
            }
        }
        g_hash_table_unref(seen);
        if (if_addrs != NULL) {
            freeifaddrs(if_addrs);
        }
    }

    APP.mime_types = camarero_get_mime_types();

    // Run the server
    g_printf("Starting server for document root: %s\n", APP.root);
    soup_server_run(APP.server);

    // Show some stats
    gchar *size = g_format_size(APP.bytes);
    g_printf("Served %d requests (%s)\n", APP.requests, size);
    g_free(size);


    // Cleanup
    DONE:
    if (0) {
        FAIL:
        exit_value = 1;
    }

    camarero_app_free();
    return exit_value;
}
