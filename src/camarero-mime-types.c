/*
 * camarero-mime-types.c
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

#include "camarero-mime-types.h"


GHashTable*
camarero_get_mime_types () {
    GHashTable *mime_types = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    g_hash_table_insert(mime_types, "3dm", "x-world/x-3dmf");
    g_hash_table_insert(mime_types, "3dmf", "x-world/x-3dmf");
    g_hash_table_insert(mime_types, "a", "application/octet-stream");
    g_hash_table_insert(mime_types, "aab", "application/x-authorware-bin");
    g_hash_table_insert(mime_types, "aam", "application/x-authorware-map");
    g_hash_table_insert(mime_types, "aas", "application/x-authorware-seg");
    g_hash_table_insert(mime_types, "abc", "text/vnd.abc");
    g_hash_table_insert(mime_types, "acgi", "text/html");
    g_hash_table_insert(mime_types, "afl", "video/animaflex");
    g_hash_table_insert(mime_types, "ai", "application/postscript");
    g_hash_table_insert(mime_types, "aif", "audio/aiff");
    g_hash_table_insert(mime_types, "aifc", "audio/aiff");
    g_hash_table_insert(mime_types, "aiff", "audio/aiff");
    g_hash_table_insert(mime_types, "aim", "application/x-aim");
    g_hash_table_insert(mime_types, "aip", "text/x-audiosoft-intra");
    g_hash_table_insert(mime_types, "ani", "application/x-navi-animation");
    g_hash_table_insert(mime_types, "aos", "application/x-nokia-9000-communicator-add-on-software");
    g_hash_table_insert(mime_types, "aps", "application/mime");
    g_hash_table_insert(mime_types, "arc", "application/octet-stream");
    g_hash_table_insert(mime_types, "arj", "application/arj");
    g_hash_table_insert(mime_types, "art", "image/x-jg");
    g_hash_table_insert(mime_types, "asf", "video/x-ms-asf");
    g_hash_table_insert(mime_types, "asm", "text/x-asm");
    g_hash_table_insert(mime_types, "asp", "text/asp");
    g_hash_table_insert(mime_types, "asx", "application/x-mplayer2");
    g_hash_table_insert(mime_types, "au", "audio/basic");
    g_hash_table_insert(mime_types, "avi", "application/x-troff-msvideo");
    g_hash_table_insert(mime_types, "avs", "video/avs-video");
    g_hash_table_insert(mime_types, "bcpio", "application/x-bcpio");
    g_hash_table_insert(mime_types, "bin", "application/mac-binary");
    g_hash_table_insert(mime_types, "bm", "image/bmp");
    g_hash_table_insert(mime_types, "bmp", "image/bmp");
    g_hash_table_insert(mime_types, "boo", "application/book");
    g_hash_table_insert(mime_types, "book", "application/book");
    g_hash_table_insert(mime_types, "boz", "application/x-bzip2");
    g_hash_table_insert(mime_types, "bsh", "application/x-bsh");
    g_hash_table_insert(mime_types, "bz", "application/x-bzip");
    g_hash_table_insert(mime_types, "bz2", "application/x-bzip2");
    g_hash_table_insert(mime_types, "c", "text/plain");
    g_hash_table_insert(mime_types, "c++", "text/plain");
    g_hash_table_insert(mime_types, "cat", "application/vnd.ms-pki.seccat");
    g_hash_table_insert(mime_types, "cc", "text/plain");
    g_hash_table_insert(mime_types, "ccad", "application/clariscad");
    g_hash_table_insert(mime_types, "cco", "application/x-cocoa");
    g_hash_table_insert(mime_types, "cdf", "application/cdf");
    g_hash_table_insert(mime_types, "cer", "application/pkix-cert");
    g_hash_table_insert(mime_types, "cha", "application/x-chat");
    g_hash_table_insert(mime_types, "chat", "application/x-chat");
    g_hash_table_insert(mime_types, "class", "application/java");
    g_hash_table_insert(mime_types, "com", "application/octet-stream");
    g_hash_table_insert(mime_types, "conf", "text/plain");
    g_hash_table_insert(mime_types, "cpio", "application/x-cpio");
    g_hash_table_insert(mime_types, "cpp", "text/x-c");
    g_hash_table_insert(mime_types, "cpt", "application/mac-compactpro");
    g_hash_table_insert(mime_types, "crl", "application/pkcs-crl");
    g_hash_table_insert(mime_types, "crt", "application/pkix-cert");
    g_hash_table_insert(mime_types, "csh", "application/x-csh");
    g_hash_table_insert(mime_types, "css", "application/x-pointplus");
    g_hash_table_insert(mime_types, "cxx", "text/plain");
    g_hash_table_insert(mime_types, "dcr", "application/x-director");
    g_hash_table_insert(mime_types, "deepv", "application/x-deepv");
    g_hash_table_insert(mime_types, "def", "text/plain");
    g_hash_table_insert(mime_types, "der", "application/x-x509-ca-cert");
    g_hash_table_insert(mime_types, "dif", "video/x-dv");
    g_hash_table_insert(mime_types, "dir", "application/x-director");
    g_hash_table_insert(mime_types, "dl", "video/dl");
    g_hash_table_insert(mime_types, "doc", "application/msword");
    g_hash_table_insert(mime_types, "dot", "application/msword");
    g_hash_table_insert(mime_types, "dp", "application/commonground");
    g_hash_table_insert(mime_types, "drw", "application/drafting");
    g_hash_table_insert(mime_types, "dump", "application/octet-stream");
    g_hash_table_insert(mime_types, "dv", "video/x-dv");
    g_hash_table_insert(mime_types, "dvi", "application/x-dvi");
    g_hash_table_insert(mime_types, "dwf", "drawing/x-dwf");
    g_hash_table_insert(mime_types, "dwg", "application/acad");
    g_hash_table_insert(mime_types, "dxf", "application/dxf");
    g_hash_table_insert(mime_types, "dxr", "application/x-director");
    g_hash_table_insert(mime_types, "el", "text/x-script.elisp");
    g_hash_table_insert(mime_types, "elc", "application/x-bytecode.elisp");
    g_hash_table_insert(mime_types, "env", "application/x-envoy");
    g_hash_table_insert(mime_types, "eps", "application/postscript");
    g_hash_table_insert(mime_types, "es", "application/x-esrehber");
    g_hash_table_insert(mime_types, "etx", "text/x-setext");
    g_hash_table_insert(mime_types, "evy", "application/envoy");
    g_hash_table_insert(mime_types, "exe", "application/octet-stream");
    g_hash_table_insert(mime_types, "f", "text/plain");
    g_hash_table_insert(mime_types, "f77", "text/x-fortran");
    g_hash_table_insert(mime_types, "f90", "text/plain");
    g_hash_table_insert(mime_types, "fdf", "application/vnd.fdf");
    g_hash_table_insert(mime_types, "fif", "application/fractals");
    g_hash_table_insert(mime_types, "fli", "video/fli");
    g_hash_table_insert(mime_types, "flo", "image/florian");
    g_hash_table_insert(mime_types, "flx", "text/vnd.fmi.flexstor");
    g_hash_table_insert(mime_types, "fmf", "video/x-atomic3d-feature");
    g_hash_table_insert(mime_types, "for", "text/plain");
    g_hash_table_insert(mime_types, "fpx", "image/vnd.fpx");
    g_hash_table_insert(mime_types, "frl", "application/freeloader");
    g_hash_table_insert(mime_types, "funk", "audio/make");
    g_hash_table_insert(mime_types, "g", "text/plain");
    g_hash_table_insert(mime_types, "g3", "image/g3fax");
    g_hash_table_insert(mime_types, "gif", "image/gif");
    g_hash_table_insert(mime_types, "gl", "video/gl");
    g_hash_table_insert(mime_types, "gsd", "audio/x-gsm");
    g_hash_table_insert(mime_types, "gsm", "audio/x-gsm");
    g_hash_table_insert(mime_types, "gsp", "application/x-gsp");
    g_hash_table_insert(mime_types, "gss", "application/x-gss");
    g_hash_table_insert(mime_types, "gtar", "application/x-gtar");
    g_hash_table_insert(mime_types, "gz", "application/x-compressed");
    g_hash_table_insert(mime_types, "gzip", "application/x-gzip");
    g_hash_table_insert(mime_types, "h", "text/plain");
    g_hash_table_insert(mime_types, "hdf", "application/x-hdf");
    g_hash_table_insert(mime_types, "help", "application/x-helpfile");
    g_hash_table_insert(mime_types, "hgl", "application/vnd.hp-hpgl");
    g_hash_table_insert(mime_types, "hh", "text/plain");
    g_hash_table_insert(mime_types, "hlb", "text/x-script");
    g_hash_table_insert(mime_types, "hlp", "application/hlp");
    g_hash_table_insert(mime_types, "hpg", "application/vnd.hp-hpgl");
    g_hash_table_insert(mime_types, "hpgl", "application/vnd.hp-hpgl");
    g_hash_table_insert(mime_types, "hqx", "application/binhex");
    g_hash_table_insert(mime_types, "hta", "application/hta");
    g_hash_table_insert(mime_types, "htc", "text/x-component");
    g_hash_table_insert(mime_types, "htm", "text/html");
    g_hash_table_insert(mime_types, "html", "text/html");
    g_hash_table_insert(mime_types, "htmls", "text/html");
    g_hash_table_insert(mime_types, "htt", "text/webviewhtml");
    g_hash_table_insert(mime_types, "htx", "text/html");
    g_hash_table_insert(mime_types, "ice", "x-conference/x-cooltalk");
    g_hash_table_insert(mime_types, "ico", "image/x-icon");
    g_hash_table_insert(mime_types, "idc", "text/plain");
    g_hash_table_insert(mime_types, "ief", "image/ief");
    g_hash_table_insert(mime_types, "iefs", "image/ief");
    g_hash_table_insert(mime_types, "iges", "application/iges");
    g_hash_table_insert(mime_types, "igs", "application/iges");
    g_hash_table_insert(mime_types, "ima", "application/x-ima");
    g_hash_table_insert(mime_types, "imap", "application/x-httpd-imap");
    g_hash_table_insert(mime_types, "inf", "application/inf");
    g_hash_table_insert(mime_types, "ins", "application/x-internett-signup");
    g_hash_table_insert(mime_types, "ip", "application/x-ip2");
    g_hash_table_insert(mime_types, "isu", "video/x-isvideo");
    g_hash_table_insert(mime_types, "it", "audio/it");
    g_hash_table_insert(mime_types, "iv", "application/x-inventor");
    g_hash_table_insert(mime_types, "ivr", "i-world/i-vrml");
    g_hash_table_insert(mime_types, "ivy", "application/x-livescreen");
    g_hash_table_insert(mime_types, "jam", "audio/x-jam");
    g_hash_table_insert(mime_types, "jav", "text/plain");
    g_hash_table_insert(mime_types, "java", "text/plain");
    g_hash_table_insert(mime_types, "jcm", "application/x-java-commerce");
    g_hash_table_insert(mime_types, "jfif", "image/jpeg");
    g_hash_table_insert(mime_types, "jfif-tbnl", "image/jpeg");
    g_hash_table_insert(mime_types, "jpe", "image/jpeg");
    g_hash_table_insert(mime_types, "jpeg", "image/jpeg");
    g_hash_table_insert(mime_types, "jpg", "image/jpeg");
    g_hash_table_insert(mime_types, "jps", "image/x-jps");
    g_hash_table_insert(mime_types, "js", "application/x-javascript");
    g_hash_table_insert(mime_types, "jut", "image/jutvision");
    g_hash_table_insert(mime_types, "kar", "audio/midi");
    g_hash_table_insert(mime_types, "ksh", "application/x-ksh");
    g_hash_table_insert(mime_types, "la", "audio/nspaudio");
    g_hash_table_insert(mime_types, "lam", "audio/x-liveaudio");
    g_hash_table_insert(mime_types, "latex", "application/x-latex");
    g_hash_table_insert(mime_types, "lha", "application/lha");
    g_hash_table_insert(mime_types, "lhx", "application/octet-stream");
    g_hash_table_insert(mime_types, "list", "text/plain");
    g_hash_table_insert(mime_types, "lma", "audio/nspaudio");
    g_hash_table_insert(mime_types, "log", "text/plain");
    g_hash_table_insert(mime_types, "lsp", "application/x-lisp");
    g_hash_table_insert(mime_types, "lst", "text/plain");
    g_hash_table_insert(mime_types, "lsx", "text/x-la-asf");
    g_hash_table_insert(mime_types, "ltx", "application/x-latex");
    g_hash_table_insert(mime_types, "lzh", "application/octet-stream");
    g_hash_table_insert(mime_types, "lzx", "application/lzx");
    g_hash_table_insert(mime_types, "m", "text/plain");
    g_hash_table_insert(mime_types, "m1v", "video/mpeg");
    g_hash_table_insert(mime_types, "m2a", "audio/mpeg");
    g_hash_table_insert(mime_types, "m2v", "video/mpeg");
    g_hash_table_insert(mime_types, "m3u", "audio/x-mpequrl");
    g_hash_table_insert(mime_types, "man", "application/x-troff-man");
    g_hash_table_insert(mime_types, "map", "application/x-navimap");
    g_hash_table_insert(mime_types, "mar", "text/plain");
    g_hash_table_insert(mime_types, "mbd", "application/mbedlet");
    g_hash_table_insert(mime_types, "mc$", "application/x-magic-cap-package-1.0");
    g_hash_table_insert(mime_types, "mcd", "application/mcad");
    g_hash_table_insert(mime_types, "mcf", "image/vasa");
    g_hash_table_insert(mime_types, "mcp", "application/netmc");
    g_hash_table_insert(mime_types, "me", "application/x-troff-me");
    g_hash_table_insert(mime_types, "mht", "message/rfc822");
    g_hash_table_insert(mime_types, "mhtml", "message/rfc822");
    g_hash_table_insert(mime_types, "mid", "application/x-midi");
    g_hash_table_insert(mime_types, "midi", "application/x-midi");
    g_hash_table_insert(mime_types, "mif", "application/x-frame");
    g_hash_table_insert(mime_types, "mime", "message/rfc822");
    g_hash_table_insert(mime_types, "mjf", "audio/x-vnd.audioexplosion.mjuicemediafile");
    g_hash_table_insert(mime_types, "mjpg", "video/x-motion-jpeg");
    g_hash_table_insert(mime_types, "mm", "application/base64");
    g_hash_table_insert(mime_types, "mme", "application/base64");
    g_hash_table_insert(mime_types, "mod", "audio/mod");
    g_hash_table_insert(mime_types, "moov", "video/quicktime");
    g_hash_table_insert(mime_types, "mov", "video/quicktime");
    g_hash_table_insert(mime_types, "movie", "video/x-sgi-movie");
    g_hash_table_insert(mime_types, "mp2", "audio/mpeg");
    g_hash_table_insert(mime_types, "mp3", "audio/mpeg3");
    g_hash_table_insert(mime_types, "mpa", "audio/mpeg");
    g_hash_table_insert(mime_types, "mpc", "application/x-project");
    g_hash_table_insert(mime_types, "mpe", "video/mpeg");
    g_hash_table_insert(mime_types, "mpeg", "video/mpeg");
    g_hash_table_insert(mime_types, "mpg", "audio/mpeg");
    g_hash_table_insert(mime_types, "mpga", "audio/mpeg");
    g_hash_table_insert(mime_types, "mpp", "application/vnd.ms-project");
    g_hash_table_insert(mime_types, "mpt", "application/x-project");
    g_hash_table_insert(mime_types, "mpv", "application/x-project");
    g_hash_table_insert(mime_types, "mpx", "application/x-project");
    g_hash_table_insert(mime_types, "mrc", "application/marc");
    g_hash_table_insert(mime_types, "ms", "application/x-troff-ms");
    g_hash_table_insert(mime_types, "mv", "video/x-sgi-movie");
    g_hash_table_insert(mime_types, "my", "audio/make");
    g_hash_table_insert(mime_types, "mzz", "application/x-vnd.audioexplosion.mzz");
    g_hash_table_insert(mime_types, "nap", "image/naplps");
    g_hash_table_insert(mime_types, "naplps", "image/naplps");
    g_hash_table_insert(mime_types, "nc", "application/x-netcdf");
    g_hash_table_insert(mime_types, "ncm", "application/vnd.nokia.configuration-message");
    g_hash_table_insert(mime_types, "nif", "image/x-niff");
    g_hash_table_insert(mime_types, "niff", "image/x-niff");
    g_hash_table_insert(mime_types, "nix", "application/x-mix-transfer");
    g_hash_table_insert(mime_types, "nsc", "application/x-conference");
    g_hash_table_insert(mime_types, "nvd", "application/x-navidoc");
    g_hash_table_insert(mime_types, "o", "application/octet-stream");
    g_hash_table_insert(mime_types, "oda", "application/oda");
    g_hash_table_insert(mime_types, "omc", "application/x-omc");
    g_hash_table_insert(mime_types, "omcd", "application/x-omcdatamaker");
    g_hash_table_insert(mime_types, "omcr", "application/x-omcregerator");
    g_hash_table_insert(mime_types, "p", "text/x-pascal");
    g_hash_table_insert(mime_types, "p10", "application/pkcs10");
    g_hash_table_insert(mime_types, "p12", "application/pkcs-12");
    g_hash_table_insert(mime_types, "p7a", "application/x-pkcs7-signature");
    g_hash_table_insert(mime_types, "p7c", "application/pkcs7-mime");
    g_hash_table_insert(mime_types, "p7m", "application/pkcs7-mime");
    g_hash_table_insert(mime_types, "p7r", "application/x-pkcs7-certreqresp");
    g_hash_table_insert(mime_types, "p7s", "application/pkcs7-signature");
    g_hash_table_insert(mime_types, "part", "application/pro_eng");
    g_hash_table_insert(mime_types, "pas", "text/pascal");
    g_hash_table_insert(mime_types, "pbm", "image/x-portable-bitmap");
    g_hash_table_insert(mime_types, "pcl", "application/vnd.hp-pcl");
    g_hash_table_insert(mime_types, "pct", "image/x-pict");
    g_hash_table_insert(mime_types, "pcx", "image/x-pcx");
    g_hash_table_insert(mime_types, "pdb", "chemical/x-pdb");
    g_hash_table_insert(mime_types, "pdf", "application/pdf");
    g_hash_table_insert(mime_types, "pfunk", "audio/make");
    g_hash_table_insert(mime_types, "pgm", "image/x-portable-graymap");
    g_hash_table_insert(mime_types, "pic", "image/pict");
    g_hash_table_insert(mime_types, "pict", "image/pict");
    g_hash_table_insert(mime_types, "pkg", "application/x-newton-compatible-pkg");
    g_hash_table_insert(mime_types, "pko", "application/vnd.ms-pki.pko");
    g_hash_table_insert(mime_types, "pl", "text/plain");
    g_hash_table_insert(mime_types, "plx", "application/x-pixclscript");
    g_hash_table_insert(mime_types, "pm", "image/x-xpixmap");
    g_hash_table_insert(mime_types, "pm4", "application/x-pagemaker");
    g_hash_table_insert(mime_types, "pm5", "application/x-pagemaker");
    g_hash_table_insert(mime_types, "png", "image/png");
    g_hash_table_insert(mime_types, "pnm", "application/x-portable-anymap");
    g_hash_table_insert(mime_types, "pot", "application/mspowerpoint");
    g_hash_table_insert(mime_types, "pov", "model/x-pov");
    g_hash_table_insert(mime_types, "ppa", "application/vnd.ms-powerpoint");
    g_hash_table_insert(mime_types, "ppm", "image/x-portable-pixmap");
    g_hash_table_insert(mime_types, "pps", "application/mspowerpoint");
    g_hash_table_insert(mime_types, "ppt", "application/mspowerpoint");
    g_hash_table_insert(mime_types, "ppz", "application/mspowerpoint");
    g_hash_table_insert(mime_types, "pre", "application/x-freelance");
    g_hash_table_insert(mime_types, "prt", "application/pro_eng");
    g_hash_table_insert(mime_types, "ps", "application/postscript");
    g_hash_table_insert(mime_types, "psd", "application/octet-stream");
    g_hash_table_insert(mime_types, "pvu", "paleovu/x-pv");
    g_hash_table_insert(mime_types, "pwz", "application/vnd.ms-powerpoint");
    g_hash_table_insert(mime_types, "py", "text/x-script.phyton");
    g_hash_table_insert(mime_types, "pyc", "applicaiton/x-bytecode.python");
    g_hash_table_insert(mime_types, "qcp", "audio/vnd.qcelp");
    g_hash_table_insert(mime_types, "qd3", "x-world/x-3dmf");
    g_hash_table_insert(mime_types, "qd3d", "x-world/x-3dmf");
    g_hash_table_insert(mime_types, "qif", "image/x-quicktime");
    g_hash_table_insert(mime_types, "qt", "video/quicktime");
    g_hash_table_insert(mime_types, "qtc", "video/x-qtc");
    g_hash_table_insert(mime_types, "qti", "image/x-quicktime");
    g_hash_table_insert(mime_types, "qtif", "image/x-quicktime");
    g_hash_table_insert(mime_types, "ra", "audio/x-pn-realaudio");
    g_hash_table_insert(mime_types, "ram", "audio/x-pn-realaudio");
    g_hash_table_insert(mime_types, "ras", "application/x-cmu-raster");
    g_hash_table_insert(mime_types, "rast", "image/cmu-raster");
    g_hash_table_insert(mime_types, "rexx", "text/x-script.rexx");
    g_hash_table_insert(mime_types, "rf", "image/vnd.rn-realflash");
    g_hash_table_insert(mime_types, "rgb", "image/x-rgb");
    g_hash_table_insert(mime_types, "rm", "application/vnd.rn-realmedia");
    g_hash_table_insert(mime_types, "rmi", "audio/mid");
    g_hash_table_insert(mime_types, "rmm", "audio/x-pn-realaudio");
    g_hash_table_insert(mime_types, "rmp", "audio/x-pn-realaudio");
    g_hash_table_insert(mime_types, "rng", "application/ringing-tones");
    g_hash_table_insert(mime_types, "rnx", "application/vnd.rn-realplayer");
    g_hash_table_insert(mime_types, "roff", "application/x-troff");
    g_hash_table_insert(mime_types, "rp", "image/vnd.rn-realpix");
    g_hash_table_insert(mime_types, "rpm", "audio/x-pn-realaudio-plugin");
    g_hash_table_insert(mime_types, "rt", "text/richtext");
    g_hash_table_insert(mime_types, "rtf", "application/rtf");
    g_hash_table_insert(mime_types, "rtx", "application/rtf");
    g_hash_table_insert(mime_types, "rv", "video/vnd.rn-realvideo");
    g_hash_table_insert(mime_types, "s", "text/x-asm");
    g_hash_table_insert(mime_types, "s3m", "audio/s3m");
    g_hash_table_insert(mime_types, "saveme", "application/octet-stream");
    g_hash_table_insert(mime_types, "sbk", "application/x-tbook");
    g_hash_table_insert(mime_types, "scm", "application/x-lotusscreencam");
    g_hash_table_insert(mime_types, "sdml", "text/plain");
    g_hash_table_insert(mime_types, "sdp", "application/sdp");
    g_hash_table_insert(mime_types, "sdr", "application/sounder");
    g_hash_table_insert(mime_types, "sea", "application/sea");
    g_hash_table_insert(mime_types, "set", "application/set");
    g_hash_table_insert(mime_types, "sgm", "text/sgml");
    g_hash_table_insert(mime_types, "sgml", "text/sgml");
    g_hash_table_insert(mime_types, "sh", "application/x-bsh");
    g_hash_table_insert(mime_types, "shar", "application/x-bsh");
    g_hash_table_insert(mime_types, "shtml", "text/html");
    g_hash_table_insert(mime_types, "sid", "audio/x-psid");
    g_hash_table_insert(mime_types, "sit", "application/x-sit");
    g_hash_table_insert(mime_types, "skd", "application/x-koan");
    g_hash_table_insert(mime_types, "skm", "application/x-koan");
    g_hash_table_insert(mime_types, "skp", "application/x-koan");
    g_hash_table_insert(mime_types, "skt", "application/x-koan");
    g_hash_table_insert(mime_types, "sl", "application/x-seelogo");
    g_hash_table_insert(mime_types, "smi", "application/smil");
    g_hash_table_insert(mime_types, "smil", "application/smil");
    g_hash_table_insert(mime_types, "snd", "audio/basic");
    g_hash_table_insert(mime_types, "sol", "application/solids");
    g_hash_table_insert(mime_types, "spc", "application/x-pkcs7-certificates");
    g_hash_table_insert(mime_types, "spl", "application/futuresplash");
    g_hash_table_insert(mime_types, "spr", "application/x-sprite");
    g_hash_table_insert(mime_types, "sprite", "application/x-sprite");
    g_hash_table_insert(mime_types, "src", "application/x-wais-source");
    g_hash_table_insert(mime_types, "ssi", "text/x-server-parsed-html");
    g_hash_table_insert(mime_types, "ssm", "application/streamingmedia");
    g_hash_table_insert(mime_types, "sst", "application/vnd.ms-pki.certstore");
    g_hash_table_insert(mime_types, "step", "application/step");
    g_hash_table_insert(mime_types, "stl", "application/sla");
    g_hash_table_insert(mime_types, "stp", "application/step");
    g_hash_table_insert(mime_types, "sv4cpio", "application/x-sv4cpio");
    g_hash_table_insert(mime_types, "sv4crc", "application/x-sv4crc");
    g_hash_table_insert(mime_types, "svf", "image/vnd.dwg");
    g_hash_table_insert(mime_types, "svr", "application/x-world");
    g_hash_table_insert(mime_types, "swf", "application/x-shockwave-flash");
    g_hash_table_insert(mime_types, "t", "application/x-troff");
    g_hash_table_insert(mime_types, "talk", "text/x-speech");
    g_hash_table_insert(mime_types, "tar", "application/x-tar");
    g_hash_table_insert(mime_types, "tbk", "application/toolbook");
    g_hash_table_insert(mime_types, "tcl", "application/x-tcl");
    g_hash_table_insert(mime_types, "tcsh", "text/x-script.tcsh");
    g_hash_table_insert(mime_types, "tex", "application/x-tex");
    g_hash_table_insert(mime_types, "texi", "application/x-texinfo");
    g_hash_table_insert(mime_types, "texinfo", "application/x-texinfo");
    g_hash_table_insert(mime_types, "text", "application/plain");
    g_hash_table_insert(mime_types, "tgz", "application/gnutar");
    g_hash_table_insert(mime_types, "tif", "image/tiff");
    g_hash_table_insert(mime_types, "tiff", "image/tiff");
    g_hash_table_insert(mime_types, "tr", "application/x-troff");
    g_hash_table_insert(mime_types, "tsi", "audio/tsp-audio");
    g_hash_table_insert(mime_types, "tsp", "application/dsptype");
    g_hash_table_insert(mime_types, "tsv", "text/tab-separated-values");
    g_hash_table_insert(mime_types, "turbot", "image/florian");
    g_hash_table_insert(mime_types, "txt", "text/plain");
    g_hash_table_insert(mime_types, "uil", "text/x-uil");
    g_hash_table_insert(mime_types, "uni", "text/uri-list");
    g_hash_table_insert(mime_types, "unis", "text/uri-list");
    g_hash_table_insert(mime_types, "unv", "application/i-deas");
    g_hash_table_insert(mime_types, "uri", "text/uri-list");
    g_hash_table_insert(mime_types, "uris", "text/uri-list");
    g_hash_table_insert(mime_types, "ustar", "application/x-ustar");
    g_hash_table_insert(mime_types, "uu", "application/octet-stream");
    g_hash_table_insert(mime_types, "uue", "text/x-uuencode");
    g_hash_table_insert(mime_types, "vcd", "application/x-cdlink");
    g_hash_table_insert(mime_types, "vcs", "text/x-vcalendar");
    g_hash_table_insert(mime_types, "vda", "application/vda");
    g_hash_table_insert(mime_types, "vdo", "video/vdo");
    g_hash_table_insert(mime_types, "vew", "application/groupwise");
    g_hash_table_insert(mime_types, "viv", "video/vivo");
    g_hash_table_insert(mime_types, "vivo", "video/vivo");
    g_hash_table_insert(mime_types, "vmd", "application/vocaltec-media-desc");
    g_hash_table_insert(mime_types, "vmf", "application/vocaltec-media-file");
    g_hash_table_insert(mime_types, "voc", "audio/voc");
    g_hash_table_insert(mime_types, "vos", "video/vosaic");
    g_hash_table_insert(mime_types, "vox", "audio/voxware");
    g_hash_table_insert(mime_types, "vqe", "audio/x-twinvq-plugin");
    g_hash_table_insert(mime_types, "vqf", "audio/x-twinvq");
    g_hash_table_insert(mime_types, "vql", "audio/x-twinvq-plugin");
    g_hash_table_insert(mime_types, "vrml", "application/x-vrml");
    g_hash_table_insert(mime_types, "vrt", "x-world/x-vrt");
    g_hash_table_insert(mime_types, "vsd", "application/x-visio");
    g_hash_table_insert(mime_types, "vst", "application/x-visio");
    g_hash_table_insert(mime_types, "vsw", "application/x-visio");
    g_hash_table_insert(mime_types, "w60", "application/wordperfect6.0");
    g_hash_table_insert(mime_types, "w61", "application/wordperfect6.1");
    g_hash_table_insert(mime_types, "w6w", "application/msword");
    g_hash_table_insert(mime_types, "wav", "audio/wav");
    g_hash_table_insert(mime_types, "wb1", "application/x-qpro");
    g_hash_table_insert(mime_types, "wbmp", "image/vnd.wap.wbmp");
    g_hash_table_insert(mime_types, "web", "application/vnd.xara");
    g_hash_table_insert(mime_types, "wiz", "application/msword");
    g_hash_table_insert(mime_types, "wk1", "application/x-123");
    g_hash_table_insert(mime_types, "wmf", "windows/metafile");
    g_hash_table_insert(mime_types, "wml", "text/vnd.wap.wml");
    g_hash_table_insert(mime_types, "wmlc", "application/vnd.wap.wmlc");
    g_hash_table_insert(mime_types, "wmls", "text/vnd.wap.wmlscript");
    g_hash_table_insert(mime_types, "wmlsc", "application/vnd.wap.wmlscriptc");
    g_hash_table_insert(mime_types, "word", "application/msword");
    g_hash_table_insert(mime_types, "wp", "application/wordperfect");
    g_hash_table_insert(mime_types, "wp5", "application/wordperfect");
    g_hash_table_insert(mime_types, "wp6", "application/wordperfect");
    g_hash_table_insert(mime_types, "wpd", "application/wordperfect");
    g_hash_table_insert(mime_types, "wq1", "application/x-lotus");
    g_hash_table_insert(mime_types, "wri", "application/mswrite");
    g_hash_table_insert(mime_types, "wrl", "application/x-world");
    g_hash_table_insert(mime_types, "wrz", "model/vrml");
    g_hash_table_insert(mime_types, "wsc", "text/scriplet");
    g_hash_table_insert(mime_types, "wsrc", "application/x-wais-source");
    g_hash_table_insert(mime_types, "wtk", "application/x-wintalk");
    g_hash_table_insert(mime_types, "xbm", "image/x-xbitmap");
    g_hash_table_insert(mime_types, "xdr", "video/x-amt-demorun");
    g_hash_table_insert(mime_types, "xgz", "xgl/drawing");
    g_hash_table_insert(mime_types, "xif", "image/vnd.xiff");
    g_hash_table_insert(mime_types, "xl", "application/excel");
    g_hash_table_insert(mime_types, "xla", "application/excel");
    g_hash_table_insert(mime_types, "xlb", "application/excel");
    g_hash_table_insert(mime_types, "xlc", "application/excel");
    g_hash_table_insert(mime_types, "xld", "application/excel");
    g_hash_table_insert(mime_types, "xlk", "application/excel");
    g_hash_table_insert(mime_types, "xll", "application/excel");
    g_hash_table_insert(mime_types, "xlm", "application/excel");
    g_hash_table_insert(mime_types, "xls", "application/excel");
    g_hash_table_insert(mime_types, "xlt", "application/excel");
    g_hash_table_insert(mime_types, "xlv", "application/excel");
    g_hash_table_insert(mime_types, "xlw", "application/excel");
    g_hash_table_insert(mime_types, "xm", "audio/xm");
    g_hash_table_insert(mime_types, "xml", "application/xml");
    g_hash_table_insert(mime_types, "xmz", "xgl/movie");
    g_hash_table_insert(mime_types, "xpix", "application/x-vnd.ls-xpix");
    g_hash_table_insert(mime_types, "xpm", "image/x-xpixmap");
    g_hash_table_insert(mime_types, "x-png", "image/png");
    g_hash_table_insert(mime_types, "xsr", "video/x-amt-showrun");
    g_hash_table_insert(mime_types, "xwd", "image/x-xwd");
    g_hash_table_insert(mime_types, "xyz", "chemical/x-pdb");
    g_hash_table_insert(mime_types, "z", "application/x-compress");
    g_hash_table_insert(mime_types, "zip", "application/x-compressed");
    g_hash_table_insert(mime_types, "zoo", "application/octet-stream");
    g_hash_table_insert(mime_types, "zsh", "text/x-script.zsh");
    return mime_types;
}
