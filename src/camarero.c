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


#if GLIB_MAJOR_VERSION <= 2 && GLIB_MINOR_VERSION < 30
#   define g_format_size g_format_size_for_display
#endif


typedef struct _CamareroMemmap {
    void   *mem;
    size_t length;
    int    fd;
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
} CamareroApp;
CamareroApp APP = {0,};


static void
camarero_app_free () {
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
}


static void
camarero_memmap_free (gpointer data) {
    CamareroMemmap *memmap = (CamareroMemmap *) data;
    munmap(memmap->mem, memmap->length);
    close(memmap->fd);
    g_slice_free(CamareroMemmap, memmap);
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
    soup_message_set_status(msg, SOUP_STATUS_NOT_FOUND);
    soup_message_body_append(msg->response_body, SOUP_MEMORY_STATIC, "", 0);
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
            //  The path points to a folder but is missing the last '/'
            gchar *redirect = g_strdup_printf("%s/", path);
            soup_message_headers_append(msg->response_headers, "Location", redirect);
            status = SOUP_STATUS_MOVED_PERMANENTLY;
            g_free(redirect);
            goto DONE;
        }

        // Try to serve an index.html, if thee's one
        gchar *index_path = g_build_filename(APP.root, path, "index.html", NULL);
        GStatBuf index_st;
        gboolean show_dir = FALSE;
        code = g_stat(index_path, &index_st);
        if (code == 0) {
            // Serve /index.html file as an initial file
            g_free(fpath);
            fpath = index_path;
            memcpy(&st, &index_st, sizeof(index_st));
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
            GString *buffer = g_string_new_len(NULL, 4096);
            content_type = "text/html";
            g_string_append_printf(buffer, "<html><head><title>Dir %s</title></head><body>\n", path);
            g_string_append_printf(buffer, "<h1>Dir %s</h1>\n", path);

            if (array->len) {
                g_string_append_printf(buffer, "<p>has %d files</p>\n<ul>\n", array->len);
                for (guint i = 0; i < array->len; ++i) {
                    CamareroDirEntry *entry = (CamareroDirEntry *) array->pdata[i];
                    gchar *u_name = g_uri_escape_string(entry->name, "/", TRUE);
                    gchar *size = g_format_size(entry->stat.st_size);
                    gchar *for_dir = S_ISDIR(entry->stat.st_mode) ? "/" : "";
                    g_string_append_printf(buffer, "  <li><a href='%s%s'>%s%s</a> (%s)</li>\n",
                        u_name, for_dir, entry->name, for_dir, size
                    );
                    g_free(u_name);
                    g_free(size);
                }
                g_string_append(buffer, "<ul>\n");
            }
            else {
                g_string_append(buffer, "<p>is empty.</p>\n");
            }
            for (guint i = 0; i < array->len; ++i) {
                CamareroDirEntry *entry = (CamareroDirEntry *) array->pdata[i];
                g_free(entry->name);
                g_slice_free(CamareroDirEntry, entry);
            }
            g_ptr_array_free(array, TRUE);

            g_string_append(buffer, "</body></html>\n");

            soup_message_body_append(msg->response_body, SOUP_MEMORY_TAKE, buffer->str, buffer->len);
            len = buffer->len;
            status = SOUP_STATUS_OK;
            g_string_free(buffer, FALSE);

            goto DONE;
        }
    }

    char *extension = strrchr(fpath, '.');
    printf("ext is %s\n", extension);
    if (extension != NULL) {
        const gchar *mime_type = g_hash_table_lookup(APP.mime_types, extension + 1);
        if (mime_type != NULL) {
            content_type = mime_type;
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
        else {
            gchar *size = g_format_size(len);
            g_printf("%3d %s (%s)\n", status, path, size);
            g_free(size);
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
        { "ssl-cert",   required_argument, NULL, 'c' },
        { "ssl-key",    required_argument, NULL, 'k' },
        { "auth",       required_argument, NULL, 'a' },
        { "username",   required_argument, NULL, 'u' },
        { "password",   required_argument, NULL, 'P' },
        { "jail",       no_argument,       NULL, 'j' },
        { "port",       required_argument, NULL, 'p' },
        { "help",       no_argument,       NULL, 'h' },
        { "version",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    unsigned int port = 3000;
    gboolean auth_digest = TRUE;
    gchar *ssl_cert = NULL;
    gchar *ssl_key = NULL;
    int rc;
    while ( (rc = getopt_long(argc, argv, "c:k:a:u:P:jp:hv", longopts, NULL)) != -1 ) {
        switch (rc) {
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
    g_printf("Starting server for document root: %s\n", APP.root);


    // Print the URLs that can be used to reach this server
    g_printf("Server is reachable at the following URLs:\n");
    struct ifaddrs *if_addrs = NULL;
    getifaddrs(&if_addrs);
    const char *format = soup_server_is_https(APP.server) ? "  https://%s:%d/n" : "  http://%s:%d/\n";
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    for (struct ifaddrs *ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET) {
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

    APP.mime_types = camarero_get_mime_types();

    // Run the server
    soup_server_run(APP.server);

    // Show some stats
    gchar *size = g_format_size(APP.bytes);
    g_printf("Served %d requests (%s)\n", APP.requests, size);
    g_free(size);
    g_printf("Done\n");


    // Cleanup
    DONE:
    if (0) {
        FAIL:
        exit_value = 1;
    }

    camarero_app_free();
    return exit_value;
}
