#include "users.h"

#define _POSIX_C_SOURCE 200809L // fixes pthread_rwlock_t
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_USERS 100
#define MAX_UNAME 256
#define MAX_PASSWD 256

struct user
{
    char username[MAX_UNAME];
    char password[MAX_PASSWD];
    bool active;
};

static struct 
{
    struct user         users[MAX_USERS];
    size_t              count;
    pthread_rwlock_t    lock;
    bool                initialized;
} user_db = {
    .count = 0,
    .initialized = false
};


void users_init(void)
{
    if (user_db.initialized)
        return;
    
    memset(user_db.users, 0, sizeof(user_db.users));
    user_db.count = 0;
    pthread_rwlock_init(&user_db.lock, NULL);
    user_db.initialized = true;
}

void users_destroy(void)
{
    if (!user_db.initialized)
        return;

    pthread_rwlock_destroy(&user_db.lock);
    memset(user_db.users, 0, sizeof(user_db.users));
    user_db.count = 0;
    user_db.initialized = false;
}

bool users_add(const char *username, const char *password)
{
    if (username == NULL || password == NULL)
        return false;
    
    if (strlen(username) == 0 || strlen(username) >= MAX_UNAME ||
        strlen(password) == 0 || strlen(password) >= MAX_PASSWD)
        return false;

    pthread_rwlock_wrlock(&user_db.lock);

    for (size_t i = 0; i < MAX_USERS; i++)
    {
        if (user_db.users[i].active && strcmp(user_db.users[i].username, username) == 0)
        {
            strncpy(user_db.users[i].password, password, MAX_PASSWD - 1);
            user_db.users[i].password[MAX_PASSWD - 1] = '\0';
            pthread_rwlock_unlock(&user_db.lock);
            return true;
        }   
    }

    for (size_t i = 0; i < MAX_USERS; i++)
    {
        if (!user_db.users[i].active)
        {
            user_db.users[i].active = true;
            strncpy(user_db.users[i].username, username, MAX_UNAME - 1);
            user_db.users[i].username[MAX_UNAME - 1] = '\0';
            strncpy(user_db.users[i].password, password, MAX_PASSWD - 1);
            user_db.users[i].password[MAX_PASSWD - 1] = '\0';
            user_db.count++;
            pthread_rwlock_unlock(&user_db.lock);
            return true;
        }
        
    }

    pthread_rwlock_unlock(&user_db.lock);
    return false;
}

bool users_remove(const char *username) 
{
    if (username == NULL || strlen(username) == 0)
        return false;
    
    pthread_rwlock_wrlock(&user_db.lock);

    for (size_t i = 0; i < MAX_USERS; i++)
    {
        if (user_db.users[i].active && strcmp(user_db.users[i].username, username) == 0)
        {
            memset(&user_db.users[i], 0, sizeof(struct user));
            user_db.users[i].active = false;
            user_db.count--;
            pthread_rwlock_unlock(&user_db.lock);
            return true;
        }
        
    }
    pthread_rwlock_unlock(&user_db.lock);
    return false;
}

bool users_authenticate(const char *username, const char *password)
{
    if (username == NULL || password == NULL)
        return false;
    
    pthread_rwlock_rdlock(&user_db.lock);

    for (size_t i = 0; i < MAX_USERS; i++)
    {
        if (user_db.users[i].active && strcmp(user_db.users[i].username, username) == 0)
        {
            bool valid = (strcmp(user_db.users[i].password, password) == 0);
            pthread_rwlock_unlock(&user_db.lock);
            return valid;
        }
        
    }
    
    pthread_rwlock_unlock(&user_db.lock);
    return false;
    
}

size_t users_count(void)
{
    pthread_rwlock_rdlock(&user_db.lock);
    size_t count = user_db.count;
    pthread_rwlock_unlock(&user_db.lock);
    return count;
}

size_t users_list(char *buffer, size_t buffer_len)
{
    if (buffer == NULL || buffer_len == 0)
        return 0;
    
    pthread_rwlock_rdlock(&user_db.lock);
    size_t offset = 0;

    for (size_t i = 0; i < MAX_USERS && offset < buffer_len - 1; i++)
    {
        if (user_db.users[i].active)
        {
            int written = snprintf(buffer + offset, buffer_len - offset, "%s\n", user_db.users[i].username);
            if (written > 0)
            {
                offset += written;
            }
            
        }
        
    }
    
    pthread_rwlock_unlock(&user_db.lock);
    if (offset < buffer_len)
        buffer[offset] = '\0';

    return offset;
}