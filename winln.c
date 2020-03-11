/**
 * GNU ln(1) workalike that creates Windows links (hard and symbolic)
 * instead of Cygwin ones.
 *
 * Revision History:
 *
 * Version 1.1 - 2001-12-04
 *
 *  - Use Cygwin functions to convert between character encodings,
 *    correctly respecting locale.
 *
 *  - Explain bugs worked around in the code.
 *
 *  - Ensure that we don't create relative symlinks to invalid
 *    filenames.
 *
 *  - Print message when user lacks SeCreateSymbolicLinkPrivilege and
 *    suggest a way to enable the privilege.
 *
 * Version 1.0 - 2011-04-06
 *
 *  - Initial release
 *
 */

#define _WIN32_WINNT 0x0600 /*Win2k*/
#define STRICT
#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <errno.h>
#include <sys/cygwin.h>
#include <sys/stat.h>
#include <libgen.h>

#define PRGNAME "winln"
#define PRGVER "1.1"
#define PRGAUTHOR "Daniel Colascione <dan.colascione@gmail.com>"
#define PRGCOPY "Copyright (C) 2011 " PRGAUTHOR
#define PRGLICENSE "GPLv2 or later <http://www.gnu.org/licenses/gpl-2.0.html>"

static BOOLEAN WINAPI
(*XCreateSymbolicLinkW)
(LPWSTR lpSymlinkFileName,
 LPWSTR lpTargetFileName,
 DWORD dwFlags);

static char*
to_mbs(const wchar_t* wc);

static wchar_t*
to_wcs(const char* mbs);

static int getRegValue() {
    HKEY hKey = HKEY_LOCAL_MACHINE;
    LPCWSTR subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock";
    DWORD options = 0;
    REGSAM samDesired = KEY_READ;
    
    HKEY OpenResult;
    
    LPCWSTR pValue = L"AllowDevelopmentWithoutDevLicense";
    DWORD flags = RRF_RT_ANY;
    
    DWORD dataType;
    
    WCHAR value[255];
    PVOID pvData = value;
    
    DWORD size = sizeof(value);
    
    LONG err = RegOpenKeyEx(hKey, subKey, options, samDesired, &OpenResult);

    if (err != ERROR_SUCCESS)
    {
        printf("The %s subkey could not be opened. Error code: %x\n", subKey, err);
    }
    else
    {
        RegGetValue(OpenResult, NULL, pValue, flags, &dataType, pvData, &size);
    }
    return *(DWORD*)pvData;
}

static void
usage()
{
    fprintf(
        stdout,
        PRGNAME " [OPTION] TARGET LINKNAME: like ln(1) for native Windows links\n"
        "\n"
        "  -s --symbolic: make symbolic links\n"
        "  -v --verbose: verbose\n"
        "  -f --force: replace existing links\n"
        "  -d --directory: always treat TARGET as a directory\n"
        "  -F --file: always treat TARGET as a file\n"
        "  -A --auto: guess type of TARGET [default]\n"
        "     if TARGET does not exist, treat as file\n"
        "\n"
        PRGNAME " -h\n"
        PRGNAME " --help\n"
        "\n"
        "  Display this help message.\n"
        "\n"
        PRGNAME " -V\n"
        PRGNAME " --version\n"
        "\n"
        "  Display version information.\n"
        );
}

static void
versinfo ()
{
    fprintf(stdout,
            PRGNAME " " PRGVER "\n"
            PRGCOPY "\n"
            PRGLICENSE "\n"
        );
}

/* Decode a Win32 error code to a localized string encoded according
   to the current locale.  Return a malloc()ed string. */
static char*
errmsg(DWORD errorcode)
{
    wchar_t* wcsmsg = NULL;
    char* msg = NULL;

    FormatMessageW(
        (FORMAT_MESSAGE_FROM_SYSTEM|
         FORMAT_MESSAGE_ALLOCATE_BUFFER),
        NULL,
        errorcode,
        0,
        (LPWSTR)&wcsmsg,
        0,
        NULL);

    if(wcsmsg != NULL) {
        msg = to_mbs(wcsmsg);
        LocalFree(wcsmsg);
        if(msg && msg[0] && msg[strlen(msg) - 1] == '\n') {
            msg[strlen(msg) - 1] = '\0';
        }
    }

    if(msg == NULL) {
        msg = strdup("[unknown error]");
    }

    return msg;
}

static const struct option longopts[] =
{
    { "verbose",   0, 0, 'v' },
    { "directory", 0, 0, 'd' },
    { "file",      0, 0, 'F' },
    { "symbolic",  0, 0, 's' },
    { "force",     0, 0, 'f' },
    { "auto",      0, 0, 'A' },
    { "help",      0, 0, 'h' },
    { "version",   0, 0, 'V' },
    { "no-target-directory", 0, 0, 'T' },
    { "target-directory", 1, 0, 't' },
    { 0 }
};

/* Output information about link on stdout */
static int verbose    = 0;

/* Overwrite existing links */
static int force      = 0;

/* Create symbolic links */
static int symbolic   = 0;

/* Never treat last argument as a directory */
static int no_tgt_dir = 0;

/* Developer mode registry key for windows 10 
https://blogs.windows.com/windowsdeveloper/2016/12/02/symlinks-windows-10/ */
static int devRegValue = 0;

enum type_mode {
    MODE_FORCE_FILE,
    MODE_FORCE_DIR,
    MODE_AUTO,
};

static enum type_mode mode = MODE_AUTO;

/* Convert the given string (which is encoded in the current locale)
   to a wide character string.  The returned string is malloced.
   Return NULL on failure. */
static wchar_t*
to_wcs(const char* mbs)
{
    size_t wcs_length = mbstowcs(NULL, mbs, 0);
    wchar_t* wcs = malloc((wcs_length + 1) * sizeof(*wcs));
    if(wcs != NULL) {
        if(mbstowcs(wcs, mbs, wcs_length) == (size_t) -1) {
            free(wcs);
            wcs = NULL;
        }
    }



    return wcs;
}

/* Convert a wide-character string to a malloced multibyte string
   encoded as specified in the current locale.  Return NULL on
   failure. */
static char*
to_mbs(const wchar_t* wcs)
{
    size_t mbs_length = wcstombs(NULL, wcs, 0) + 1;
    char* mbs = malloc(mbs_length * sizeof(*mbs));
    if(mbs != NULL) {
        if(wcstombs(mbs, wcs, mbs_length) == (size_t) -1) {
            free(mbs);
            mbs = NULL;
        }
    }

    return mbs;
}

/* Convert path to Win32.  If we're given an absolute path, use normal
   Cygwin conversion functions.  If we've given a relative path, work
   around the cygwin_conv_path deficiency described below by using a
   very simple filename transformation.

   Return NULL on failure.

   XXX: we treat relative paths specially because cygwin_create_path
   fails to actually return a relative path for a reference to the
   parent directory. Say we have this directory structure:

       dir/foo
       dir/subdir/

   With CWD in dir/subdir, we run winln -sv ../foo.
   cygwin_create_path will actually yield the _absolute_ path to foo,
   not the correct relative Windows path, ..\foo.
*/
static wchar_t*
conv_path_to_win32(const char* posix_path)
{
    wchar_t* w32_path = NULL;
    size_t posix_path_length = strlen(posix_path);

    if(posix_path_length < 1) {
        errno = EINVAL;
        return NULL;
    }

    if(posix_path[0] != '/' &&
       posix_path[posix_path_length - 1] != '.' &&
       strcspn(posix_path, "?<>\\:*|") == posix_path_length)
    {
        char* tmp = strdup(posix_path);
        char* tmp2;

        for(tmp2 = tmp; *tmp2; ++tmp2) {
            if(*tmp2 == '/') {
                *tmp2 = '\\';
            }
        }

        w32_path = to_wcs(tmp);
        free(tmp);
    }

    if(w32_path == NULL) {
        w32_path = cygwin_create_path(
            CCP_POSIX_TO_WIN_W | CCP_RELATIVE, posix_path);
    }

    return w32_path;
}

/* Make a link. Return 0 on success, something else on error. */
static int
do_link(const char* target, const char* link)
{
    /* Work around a bug that causes Cygwin to resolve the path if it
       ends in a native symbolic link.

       The bug is described on the Cygwin mailing list in message
       <AANLkTi=98+M5sAsGp4vT09UN9uisqp0M=mgJi9WcSObG@mail.gmail.com>..

       That this bug makes symlinks-to-symlinks point to the
       ultimate target, and there's no good way around that.

       XXX: The workaround is here racy. The idea here is that if
       we're going to overwrite the link anyway, we can just
       remove the link first so that cygwin_conv_path doesn't
       follow the now non-existant symlink.
    */
    struct stat lstatbuf;
    int lstat_success = 0;

    struct stat statbuf;
    int stat_success = 0;

    struct stat target_statbuf;
    int target_stat_success = 0;

    wchar_t* w32link = NULL;
    wchar_t* w32target = NULL;
    DWORD flags;

    int ret = 0;
    int devRegValue = getRegValue();

    if(lstat(link, &lstatbuf) == 0) {
        lstat_success = 1;

        if(stat(link, &statbuf) == 0) {
            stat_success = 1;
        }

        if(force) {
            if(unlink(link)) {
                fprintf(stderr,
                        PRGNAME ": cannot remove `%s': %s\n",
                        link, strerror(errno));
                ret = 5;
                goto out;
            }
        } else {
            fprintf(stderr,
                    PRGNAME ": could not create link `%s': file exists\n",
                    link);
            ret = 1;
            goto out;
        }
    }

    if(stat(target, &target_statbuf) == 0) {
        target_stat_success = 1;
    }

    w32link = conv_path_to_win32(link);
    if(w32link == NULL) {
        fprintf(stderr, PRGNAME ": could not convert `%s' to win32 path\n",
                link);
        ret = 2;
        goto out;
    }

    w32target = conv_path_to_win32(target);
    if(w32target == NULL) {
        fprintf(stderr, PRGNAME ": could not convert `%s' to win32 path\n",
                target);
        ret = 2;
        goto out;
    }


    switch(mode)
    {
        case MODE_FORCE_DIR:
            flags = SYMBOLIC_LINK_FLAG_DIRECTORY;
            break;
        case MODE_FORCE_FILE:
            flags = 0;
            break;
        default:
            flags = 0;
            if(target_stat_success && S_ISDIR(target_statbuf.st_mode)) {
                flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
            }
            break;
    }
    /*Allow creating symlink without privileges in windows 10 developer mode */
    if(devRegValue == 1) {
        flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    }
    /* Don't call link(2), even for hard links: we want to maintain
     * absolute parity between the hard and symbolic links made using
     * this tool.  We don't want link targets to change just because
     * we change the link type. */

    if(symbolic) {
        if(XCreateSymbolicLinkW(w32link, w32target, flags)) {
            if(verbose) {
                printf("`%s' -> `%s' [%s]\n", link, target,
                       flags ? "dir" : "file");
            }
        } else {
            fprintf(stderr, PRGNAME ": failed to create symbolic link `%s': %s\n",
                    link, errmsg(GetLastError()));
            ret = 2;
            goto out;
        }
    } else {
        if(CreateHardLinkW(w32link, w32target, 0)) {
            if(verbose) {
                printf("`%s' => `%s'\n", link, target);
            }
        } else {
            fprintf(stderr, PRGNAME ": failed to create hard link `%s': %s\n",
                    link, errmsg(GetLastError()));
            ret = 2;
            goto out;
        }
    }

    out:
    free(w32link);
    free(w32target);
    return ret;
}

static int
is_dir(const char* path)
{
    struct stat statbuf;
    return stat(path, &statbuf) == 0 &&
        S_ISDIR(statbuf.st_mode);
}

static BOOL
set_privilege_status (
    const wchar_t* privname,
    BOOL bEnablePrivilege)
{
    /* After the MSDN example. */

    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;
    BOOL success;

    hToken = NULL;
    success = FALSE;

    if (!OpenProcessToken (GetCurrentProcess (),
                           (TOKEN_QUERY |
                            TOKEN_ADJUST_PRIVILEGES),
                           &hToken))
    {
        goto out;
    }

    if ( !LookupPrivilegeValue (
             NULL,            // lookup privilege on local system
             privname,        // privilege to lookup
             &luid ) )        // receives LUID of privilege
    {
        goto out;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tp.Privileges[0].Attributes = 0;
    }

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges (
             hToken,
             FALSE,
             &tp,
             sizeof (TOKEN_PRIVILEGES),
             (PTOKEN_PRIVILEGES) NULL,
             (PDWORD) NULL) )
    {
        goto out;
    }

    if (GetLastError () == ERROR_NOT_ALL_ASSIGNED) {
        goto out;
    }

    success = TRUE;

  out:

    if (hToken) {
        CloseHandle (hToken);
    }

    return success;
}

int
main(int argc, char* argv[])
{
    int c;
    char* tgt_dir = NULL;
    int ret = 0;

    setlocale(LC_ALL, "");

    to_mbs(L"");
    to_wcs("");

    devRegValue = getRegValue();
    
    while ((c = getopt_long(argc, argv, "VvdfFsATt:", longopts, 0)) != -1) {
        switch(c) {
            case 'v':
                verbose = 1;
                break;
            case 'd':
                mode = MODE_FORCE_DIR;
                break;
            case 'f':
                force = 1;
                break;
            case 'F':
                mode = MODE_FORCE_FILE;
                break;
            case 's':
                symbolic = 1;
                break;
            case 'A':
                mode = MODE_AUTO;
                break;
            case 'T':
                no_tgt_dir = 1;
                break;
            case 't':
                tgt_dir = strdup(optarg);
                break;
            case 'h':
                usage();
                ret = 0;
                goto out;
            case 'V':
                versinfo ();
                ret = 0;
                goto out;
            default:
                fprintf(stderr, PRGNAME ": use --help for usage\n");
                ret = 4;
                goto out;
        }
    }

    if(symbolic) {
        HMODULE hKernel32 = LoadLibraryW(L"kernel32");
        if(hKernel32 == NULL) {
            fprintf(stderr, PRGNAME ": could not load kernel32: %s\n",
                    errmsg(GetLastError()));
            ret = 1;
            goto out;
        }

        XCreateSymbolicLinkW =
            (void*)GetProcAddress(hKernel32, "CreateSymbolicLinkW");

        if(XCreateSymbolicLinkW == NULL) {
            fprintf(stderr, PRGNAME ": symbolic links not supported on this OS\n");
            ret = 2;
            goto out;
        }
        printf("value is: %d", devRegValue);
        if(!set_privilege_status(L"SeCreateSymbolicLinkPrivilege", TRUE) && devRegValue != 1) {
            fprintf(stderr,
                    PRGNAME ": you don't permission to create symbolic links. Run,"
                    " as administrator,\n"
                    PRGNAME ":   editrights -a SeCreateSymbolicLinkPrivilege -a $YOUR_USER\n"
                );

            ret = 3;
            goto out;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc == 0) {
        fprintf(stderr, PRGNAME ": no arguments. Use --help for usage\n");
        ret = 1;
        goto out;
    }

    if(no_tgt_dir) {
        if(argc != 2) {
            fprintf(stderr, PRGNAME ": must have exactly two args with -T\n");
            ret = 1;
            goto out;
        }

        ret = do_link(argv[0], argv[1]);
        goto out;
    }

    if(tgt_dir == NULL && argc == 1) {
        tgt_dir = ".";
    }

    if(tgt_dir == NULL) {
        int last_is_dir = is_dir(argv[argc - 1]);
        if(argc == 2 && !last_is_dir) {
            ret = do_link(argv[0], argv[1]);
            goto out;
        }

        if(!last_is_dir) {
            fprintf(stderr, PRGNAME ": `%s': not a directory\n",
                    argv[argc - 1]);
            ret = 1;
            goto out;
        }

        tgt_dir = argv[--argc];
        argv[argc] = NULL;
    }

    for(; *argv; ++argv) {
        char* tgt;
        int r;

        if(asprintf(&tgt, "%s/%s", tgt_dir, basename(*argv)) == -1) {
            fprintf(stderr, PRGNAME ": asprintf: %s\n",
                    strerror(errno));
            ret = 1;
            goto out;
        }

        r = do_link(*argv, tgt);
        if(r && ret == 0) {
            ret = r;
        }

        free(tgt);
    }

    out:
    return ret;
}
