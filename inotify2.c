#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

#include <dirent.h>
#include <sys/stat.h>

#include <stddef.h>
#include <sys/queue.h>

// gcc curr_inotify.c -lpthread
// gcc inotify_full.c -lpthread

#define MAX_DIR_PATH 512

struct dir_path_s {
    char path[MAX_DIR_PATH];
    int wd;
    TAILQ_ENTRY(dir_path_s) dir_paths;
};

TAILQ_HEAD(tailhead, dir_path_s);
static struct tailhead head;

const uint32_t FULL_MASK = IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM | IN_MODIFY | IN_CREATE | IN_MOVED_TO;

void clean_up_close(int *fd)
{
    printf("Auto close(): %d\n", *fd);
    (void)close(*fd);
    return;
}

void clean_up_free(struct dir_path_s **fd)
{
    printf("Auto free(): %p\n", *fd);
    free(*fd);
    return;
}

static int try_to_watch(int fd, const char *path)
{
    int ret = -1;

    printf("\tTry to watch: %s\n", path);
    int wd = inotify_add_watch(fd, path, FULL_MASK);
    if (wd == -1) {
        printf("\t\tERROR: Cannot watch dir\n");
        return -5;
    }

    struct dir_path_s *ptr = calloc(1, sizeof(struct dir_path_s));
    if (ptr == NULL) {
        printf("\tCan't allocate memory\n");
        exit(-1);
    }
    ptr->wd = wd;
    strcpy(ptr->path, path);
    TAILQ_INSERT_TAIL(&head, ptr, dir_paths);

    return 0;
}

static int get_dir(int fd, const char *base_path)
{
    int ret = 0;
    struct dir_path_s *ptr = NULL;

    DIR *dir = opendir(base_path);
    if (dir == NULL) {
        perror("\t\tUnable to open directory");
        return -2;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[MAX_DIR_PATH] = {};
        int ret = snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);
        if (ret < 0 || ret >= sizeof(path)) {
            printf("\t\tERROR: Cannot get name of dir\n");
            return -1;
        }
        
        struct stat statbuf = {};
        if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
            int try_ret = try_to_watch(fd, path);
            if (try_ret != 0) {
                return try_ret;
            }

            ret = get_dir(fd, path);
            if (ret != 0) {
                printf("\t\tERROR: Cannot get name of dir in recursivly\n");
                return ret;
            }
        }
    }

    closedir(dir);
    return ret;
}

static void handle_inotify_events(int fd)
{
    char buf[MAX_DIR_PATH] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event = NULL;
    ssize_t size = -1;

    printf("\n\n");
    for ( ; ; ) {
        ssize_t size = read(fd, buf, sizeof(buf));
        if (size == -1 && errno != EAGAIN) {
            printf("Can't read (%d)", errno);
            return;
        }
        if (size <= 0) {
            break;
        }

        for (char *ptr = buf;
             ptr < buf + size;
             ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *)ptr;

            printf("\t\t\tevent->len = %u\n", event->len);

            if (event->mask & IN_CREATE
             && event->mask & IN_ISDIR) {
                struct dir_path_s *np = NULL;
                TAILQ_FOREACH(np, &head, dir_paths) {
                    if (np->wd == event->wd) {
                        char local_path[MAX_DIR_PATH] = {};
                        int ret = snprintf(local_path, sizeof(local_path), "%s/%s",
                                           np->path, event->name);
                        if (ret < 0 || ret >= sizeof(local_path)) {
                            printf("\t\tERROR: Cannot get name of dir\n");
                            return;
                        }

                        int try_ret = try_to_watch(fd, local_path);
                        if (try_ret != 0) {
                            return;
                        }
                        break;
                    }
                }
            }

            if (event->mask & IN_DELETE
             || event->mask & IN_DELETE_SELF
             || event->mask & IN_MOVED_FROM
             || event->mask & IN_MOVED_TO
             || event->mask & IN_MODIFY) {
                if ((event->mask & IN_DELETE || event->mask & IN_DELETE_SELF)
                 && event->mask & IN_ISDIR) {
                    struct dir_path_s *n2 = NULL;
                    TAILQ_FOREACH(n2, &head, dir_paths) {
                        if (n2->wd == event->wd) {
                            printf("\t\tTry RM: %s\n", n2->path);
                            int rm_ret = inotify_rm_watch(fd, event->wd);
                            if (rm_ret != 0) {
                                printf("\tERROR: Can't rm wd: %d\n", rm_ret);
                                return;
                            }
                            TAILQ_REMOVE(&head, n2, dir_paths);
                            free(n2);
                            break;
                        }
                    }
                }

                if (event->len != 0) {
                    printf("!!!CAN APPLY ALG HERE!!!\n");
                }
            }
        }
    }

    return;
}

static void *dir_space_notify(void *arg)
{
#define NUM_OF_DIRECTORIES 1
    const char *base_dir = "/home/user1/dev/inotify_full";
    const nfds_t nfds = 1;
    struct pollfd fds[1] = {
        { .fd = -1, .events = POLLIN }
    };
    int fd __attribute__ ((__cleanup__(clean_up_close))) = -1;
    struct dir_path_s *ptr __attribute__ ((__cleanup__(clean_up_free))) = NULL;
    (void)arg;

    TAILQ_INIT(&head);

    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        printf("Can't init inotify\n");
        return NULL;
    }

    int try_ret = try_to_watch(fd, base_dir);
    if (try_ret != 0) {
        return NULL;
    }

    int ret_dir = get_dir(fd, base_dir);
    if (ret_dir != 0) {
        printf("Cannot get recursive dirs\n");
        return NULL;
    }

    fds[0].fd = fd;
    while (1) {
        int poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR) {
                continue;
            }
            printf("Cannot polling fds\n");
            return NULL;
        }
        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {
                handle_inotify_events(fd);
            }
        }
    }

    struct dir_path_s *n1 = TAILQ_FIRST(&head);
    while (n1 != NULL) {
        struct dir_path_s *n2 = TAILQ_NEXT(n1, dir_paths);
        free(n1);
        n1 = n2;
    }
    TAILQ_INIT(&head);

    printf("Listening for events stopped.\n");
    return NULL;
}

int main()
{
    int ret;
    pthread_t tid;

    if ((ret = pthread_create(&tid, NULL, dir_space_notify, NULL)) != 0) {
        printf("Failed to start\n");
        return -1;
    }
    pthread_detach(tid);
    sleep(1000);
    return 0;
}
