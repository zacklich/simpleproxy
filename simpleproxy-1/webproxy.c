//
// A very simple web proxy
// Lots of code from PA2 was used!
//


//
// Good websites for testing, they do not redirect to encrypted versions
//
// eecs.lassonde.yorku.ca
// www.mit.edu
//

#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// double link list stuff from the malloc lab
#include "queues.h"


int debug = 0;

time_t cache_timeout_seconds = 20;

// information about each connection

#define MAXBUFFER 65536

typedef struct connection_s {
    int readfd;
    int writefd;
    FILE *readfile;
    FILE *writefile;

    // this buffer holds the request from the client.  "GET http://some_server.com/somepage HTTP/1.1"
    char buffer[MAXBUFFER];

    // All of the headers from the original request.
    char headers[MAXBUFFER];

    // Info about our request that was parsed from the request.
    char *req_method;
    char *req_uri;
    char *req_version;

    char *req_full_url;
    long req_url_hash;

    // proxy info (the remote page we need to fetch).
    char *proxy_hostname;
    int proxy_portnum;
    char *proxy_uri;
} connection_t;


// linked list of host names and IP addresses for the black list

typedef struct blacklist_s {
    struct blacklist_s *next;
    char *hostname;
} blacklist_t;

blacklist_t *blacklist = NULL;


// The page cache.

typedef struct cache_entry_s {
    dqueue_t link;         
    unsigned long hash;         // hash for page
    char *url;                  // actual URL
    time_t expiration;          // time this page expires
} cache_entry_t;


// The page cache is stored as a queue to make it easy
// to remove stuff from the middle.  queue code from the malloc lab
dqueue_t page_cache;
pthread_mutex_t page_cache_mutex;


// ========================================================================

// Black List

void load_blacklist(char *filename)
{
    FILE *str;

    str = fopen(filename,"r");
    if (str == NULL) {
        printf("Warning: Blacklist file '%s' not found\n",filename);
        return;
    }

    while (!feof(str)) {
        char *x;
        char line[1000];
        blacklist_t *bl;

        if (!fgets(line,sizeof(line),str)) {
            break;
        }
        
        x = strchr(line,'\n');
        if (x != NULL) *x = 0;


        // put onto a linked list
        bl = (blacklist_t *) malloc(sizeof(blacklist_t));
        bl->hostname = strdup(line);
        bl->next = blacklist;
        blacklist = bl;

        printf("Added to blacklist: %s\n",bl->hostname);
    }

    fclose(str);
}



// is_on_blacklist - check to seee if a given host is on the black list.
int is_on_blacklist(char *hostname, int port)
{
    blacklist_t *bl = blacklist;
    struct hostent *remote_host;
    unsigned char address[32];

    // store the IP address of the host we are looking for.
    remote_host = gethostbyname(hostname);
    if (remote_host != NULL) {
        memcpy(address,remote_host->h_addr,remote_host->h_length);
    } else {
        bzero(address,sizeof(address));
    }

    while (bl) {
        // If the host name matches exactly, it's on the blacklist
        if (strcasecmp(hostname,bl->hostname) == 0) {
            return 1;
        }
        // If the IP addresses match, it is on the blacklist.
        // gethostbyname() works on IP address strings too, it seems.
        remote_host = gethostbyname(bl->hostname);
        if (remote_host != NULL) {
            if (memcmp(address, remote_host->h_addr, remote_host->h_length) == 0) {
                return 1;
            }
        }
        
        bl= bl->next;
    }

    // not on black list.
    return 0;
}

// =========================================================================

// Cache stuff


// hash function - take a string, return a 64-bit hash.
// see: http://www.cse.yorku.ca/~oz/hash.html   this is the djb2 hash 

unsigned long
djb2_hash(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

// find_page - given a page's hash find it in the cache.

cache_entry_t *find_page(unsigned long hash)
{
    dqueue_t *q;

    // get the lock so we can mess with the list
    pthread_mutex_lock(&page_cache_mutex);

    q = page_cache.next;

    while (q != &page_cache) {
        cache_entry_t *entry = (cache_entry_t *) q;

        if (entry->hash == hash) {
            pthread_mutex_unlock(&page_cache_mutex);
            return entry;
        }

        q = q->next;

    }

    pthread_mutex_unlock(&page_cache_mutex);
    return NULL;

}

// find_page_by_url - given a URL, find it in the cache
// first look up by hash then compare the URLs to be sure
cache_entry_t *find_page_by_url(char *url)
{
    unsigned long hash;
    cache_entry_t *entry;

    hash = djb2_hash((unsigned char *) url);

    entry = find_page(hash);

    // if hash is not in cache not found
    if (entry == NULL) {
        return NULL;
    }

    // if URL does not match, not found
    if (strcasecmp(url,entry->url) != 0) {
        return NULL;
    }

    // otherwise this is it
    return entry;

    
}

// remove_from_cache
// given a cache entry, remove it from the cache and free memory.
void remove_from_cache(cache_entry_t *entry)
{
    char filename[200];


    // Remove from queue
    dq_dequeue(&entry->link);

    // Delete the file
    sprintf(filename,"cache/page_%08lX",entry->hash);
    remove(filename);

    // deallocate memory
    free(entry->url);
    free(entry);    


}

// remove_from_cache_by_hash - given a hash value, remove page from cache.
// (look up page then call remove_from_cache)
void remove_from_cache_by_hash(unsigned long hash)
{
    cache_entry_t *entry;

    entry = find_page(hash);
    if (entry == NULL) {
        return;
    }

    pthread_mutex_lock(&page_cache_mutex);
    remove_from_cache(entry);
    pthread_mutex_unlock(&page_cache_mutex);


}


// add_to_cache(url,hash)
// add a page to the cache.
void add_to_cache(char *url, unsigned long hash)
{
    cache_entry_t *entry;
    time_t now;

    entry = (cache_entry_t *) malloc(sizeof(cache_entry_t));

    entry->url = strdup(url);
    time(&now);
    entry->expiration = now + cache_timeout_seconds;
    entry->hash = hash;

    pthread_mutex_lock(&page_cache_mutex);
    dq_enqueue(&page_cache,&entry->link);
    pthread_mutex_unlock(&page_cache_mutex);

}

// check_cache_timeout()
// go through all entries in the cache and remove any entries that
// are past the expiration time.
void check_cache_timeout(void)
{
    dqueue_t *q;
    dqueue_t *nextq;

    time_t now;

    // get current time
    time(&now);

    pthread_mutex_lock(&page_cache_mutex);

    q = page_cache.next;

    // go through pages and see if we are past the expiration 

    while (q != &page_cache) {
        cache_entry_t *entry = (cache_entry_t *) q;

        // we might free the current one so need to grab 'next' here.
        nextq = q->next;

        if (now >= entry->expiration) {
            printf("Removing expired cache entry for %s\n",entry->url);
            remove_from_cache(entry);
        }

        q = nextq;

    }

    pthread_mutex_unlock(&page_cache_mutex);
}

// =========================================================================

// Connection stuff

//
// Close a connection and exit its thread
//

void close_connection(connection_t *conn)
{
    if (debug > 1) {
        printf("--- Closing thread for FD %d\n",conn->readfd);
    }

    // Close the streams
    fclose(conn->readfile);
    fclose(conn->writefile);

    // Free the proxy_uri since it was allocated with strdup
    if (conn->proxy_uri != NULL) {
        free(conn->proxy_uri);
    }

    // Free the 'connection' structure
    free(conn);          

    // Cause this thread to exit
    pthread_exit(NULL);
}


//
// Send a status back to the client
//

void send_status(connection_t *conn,int statuscode, char *message)
{
    printf("[%08lx] Sending error status %s %d %s -- %s\n",(unsigned long) pthread_self(),conn->req_version,statuscode,message,conn->req_uri);
    fflush(stdout);

    fprintf(conn->writefile,"%s %d %s\r\n"
            "Server: myproxy\r\n"
            "Content-Type: text/html\r\n"
            "\r\nError %d - %s\r\n","HTTP/1.0",statuscode,message,statuscode,message);
    fflush(conn->writefile);
}


//
// do_proxy
// 
// Establish connection to proxy host, then ferry all data to the client
//

int do_proxy(connection_t *conn)
{
    int remote_readfd;
    int remote_writefd;
    FILE *remote_readfile;
    FILE *remote_writefile;
    struct sockaddr_in remote_addr;
    struct hostent *remote_host;
    int rc;

    FILE *cache_file;
    unsigned long hash;
    char cache_filename[200];

    printf("[%08lx] Proxying for '%s:%u', URI %s\n",(unsigned long) pthread_self(),conn->proxy_hostname, conn->proxy_portnum, conn->proxy_uri);

    // Look up the remote host
    remote_host = gethostbyname(conn->proxy_hostname);
    if (remote_host == NULL) {
        return -1;
    }

    // Make a socket and connect it to the real web server.
    remote_readfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote_readfd < 0) {
        return -1;
    }

    // set up the sockaddr so we can establish the connection
    bzero(&remote_addr,sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(conn->proxy_portnum);
    bcopy((char *)remote_host->h_addr, 
	  (char *)&remote_addr.sin_addr.s_addr, remote_host->h_length);

    // OK, try to make the connection.
    rc = connect(remote_readfd,(struct sockaddr *) &remote_addr,sizeof(remote_addr));
    if (rc < 0) {
        close(remote_readfd);
        return -1;
    }

    // OK sockets are connected, make the FILE things

    // Create a read and a write FILE structure 
    // https://ycpcs.github.io/cs365-spring2017/lectures/lecture15.html
    remote_writefd = dup(remote_readfd);

    // 'fdopen' lets us turn a file descriptor into a FILE *, like we get 
    // when you call fopen() on a file name.
    // Make one FILE * for reading, one for writing
    remote_readfile = fdopen(remote_readfd,"r");
    remote_writefile = fdopen(remote_writefd,"w");

    // Issue a GET for the URI for this connection to the remote server, then
    // relay everything in the response back to the client.

    printf("[%08lx] Requesting: '%s'\n",(unsigned long) pthread_self(), conn->proxy_uri);

    // commands need to end in "\r\n", not just "\n".
    // Wireshark used to figure out which headers real websites want.

    fprintf(remote_writefile,"GET %s HTTP/1.0\r\n"
            "Host: %s\r\n"
            "User-Agent: myproxy/1.0\r\n"
            "Accept: */*\r\n"
            "Upgrade-Insecure-Requests: 0\r\n"
            "\r\n", conn->proxy_uri, conn->proxy_hostname);
    fflush(remote_writefile);

    printf("[%08lx] Relaying response data\n", (unsigned long) pthread_self());

    // Remove any entry that matches this hash from the table
    hash = djb2_hash((unsigned char *) conn->req_full_url);
    remove_from_cache_by_hash(hash);

    // Open the cache file
    sprintf(cache_filename,"cache/page_%08lX",hash);
    cache_file = fopen(cache_filename,"w");

    for (;;) {
        char buffer[1024];
        int res;

        // read from one socket write to the other
        res = fread(buffer,sizeof(char),sizeof(buffer),remote_readfile);

        if (res == 0) break;

        fwrite(buffer,sizeof(char),res,conn->writefile);
        fwrite(buffer,sizeof(char),res,cache_file);
    }
    fflush(conn->writefile);

    // Close the cache file and add page to cache
    fclose(cache_file);
    add_to_cache(conn->req_full_url, hash);

    // Close the file handles and sockets

    fclose(remote_readfile);
    fclose(remote_writefile);

    printf("[%08lx] Done relaying\n", (unsigned long) pthread_self());

    return 0;
}

//
// Send a file along a connection.  Given a connection structure
// and a local file name and a file type, open the local
// file and send it to the client
//

void send_from_cache(connection_t *conn,cache_entry_t *entry)
{
    FILE *file;
    char buffer[1024];
    char name[100];
    int res;

    // open the cache entry file name
    sprintf(name,"cache/page_%08lX",entry->hash);
    file = fopen(name,"r");

    // If we could not open the file, return a 404
    if (!file) {
        send_status(conn,404,"Document not found");
        return;
    }

    printf("[%08lx] Sending %s from cache for %s\n",(unsigned long) pthread_self(),name, conn->req_full_url);

    // Now send the content of the file
    for (;;) {
        //read a chunk
        res = fread(buffer,sizeof(char),sizeof(buffer),file);

        // If we read nothing we are at the end of the file
        if (res == 0) {
            break;
        }
        // write the data we read from the file to the socket
        fwrite(buffer,sizeof(char),res,conn->writefile);
    }

    fflush(conn->writefile);
    fclose(file);

}

//
// Handle the HTTP GET request
// Returns 0 if the request looks OK
// returns -1 if the request is invalid
//
int handle_http_get(connection_t *conn,char *url)
{
    char *hostname;
    char *end_of_hostname;
    char *rest_of_uri;
    char *portstr;
    unsigned int portnum = 80;
    char buffer[4096];

    // Hack up the URL into the protocol, hostname, port, and the actual URL

    conn->req_full_url = strdup(url);   // save the original one
    conn->req_url_hash = djb2_hash((unsigned char *) url);

    // we have a string like this:      http://www.yahoo.com/logo.jpg
    // or possibly one like this:       http://www.yahoo.com:8080/logo.jpg

    // check that string starts http://
    // find the www.yahoo.com (that is the host name)
    //    Hostnames can include port numbers.
    // find the /logo.jpg (that is the URI)

    // First make sure it starts "http://".   We do not handle any other protocol like https.


    if (strncmp(url,"http://",7) != 0) {
        return -1;
    }

    // Skip past the http:// part of the URI.
    hostname = url + 7;

    // Everything from here to the next slash is the hostname.
    end_of_hostname = strchr(hostname,'/');

    // If there was nothing after the hostname, fetch "/".  Otherwise split
    // the hostname and non-hostname parts.
    if (end_of_hostname != NULL) {
        rest_of_uri = strdup(end_of_hostname);
        *end_of_hostname = '\0';
    } else {
        rest_of_uri = strdup("/");
    }

    // OK, now split out the port number.  If the host name has a ":1234" at the end,
    // find the "1234" part and store it in a variable.
    portstr = strchr(hostname,':');
    if (portstr != NULL) {
        *portstr = '\0';
        portstr++;
        portnum = atoi(portstr);
    }

    // Some sanity checks.  invalid port numbers.
    if ((portnum == 0) || (portnum > 65535)) {
        return -1;
    }

    // Save these in our connection struct.
    conn->proxy_hostname = hostname;
    conn->proxy_portnum = portnum;
    conn->proxy_uri = rest_of_uri;

    // Save all of the headers from the request.

    conn->headers[0] = '\0';
    while (fgets(buffer,sizeof(buffer),conn->readfile)) {
        if (debug > 1) {
            printf("## %s",buffer);
        }
        strcat(conn->headers,buffer);
        // Stop when we get to the blank line
        if (buffer[0] == '\r') {
            break;
        }
    }

    return 0;

}


//
// This is the pthread for the web server
//

void *webthread(void *info)
{
    connection_t *conn = (connection_t *) info;
    char *ptr;
    cache_entry_t *entry;

    if (debug > 1) {
        printf("+++ Creating new thread for FD %d\n",conn->readfd);
    }

    // Create a read and a write FILE structure 
    // https://ycpcs.github.io/cs365-spring2017/lectures/lecture15.html
    conn->writefd = dup(conn->readfd);

    // 'fdopen' lets us turn a file descriptor into a FILE *, like we get 
    // when you call fopen() on a file name.
    // Make one FILE * for reading, one for writing
    conn->readfile = fdopen(conn->readfd,"r");
    conn->writefile = fdopen(conn->writefd,"w");

    // OK read a request from the client.
    if (!fgets(conn->buffer,MAXBUFFER-1,conn->readfile)) {
        close_connection(conn);
        return NULL;
    }

    // use 'strsep' to break up the string
    // manual page for strtok says to use strsep instead.
    
    ptr = conn->buffer;

    // Store pointers to the pieces in our structure
    conn->req_method = strsep(&ptr," ");
    conn->req_uri = strsep(&ptr," ");
    conn->req_version = strsep(&ptr," \r\n");

    printf("[%08lx] REQUEST: %s %s %s\n",(unsigned long) pthread_self(),conn->req_method,conn->req_uri,conn->req_version);
   
    // we only like GET methods.
    if (strcmp(conn->req_method,"GET") != 0) {
        send_status(conn,400,"Bad Request");
        close_connection(conn);
        return NULL;
    }


    // Process the GET request.
    if (handle_http_get(conn,conn->req_uri) < 0) {
        // Could not parse request.
        send_status(conn,400,"Bad Request");
        close_connection(conn);
        return NULL;
    }

    // Check blacklist
    if (is_on_blacklist(conn->proxy_hostname, conn->proxy_portnum)) {
        send_status(conn,403,"Forbidden");
        close_connection(conn);
        return NULL;
    }

    // Check the cache
    entry = find_page_by_url(conn->req_full_url);
    if (entry != NULL) {
        send_from_cache(conn, entry);
        close_connection(conn);
        return NULL;
    }

    // Take data from remote host and feed to browser.  Store in cache too.
    if (do_proxy(conn) < 0) {
        send_status(conn,404,"Document Not Found");
    }

    // we only do one connection at a time
    close_connection(conn);

    return NULL;

}


// main loop of the web server.  Wait for a connection, accept it,
// and spawn a thread.

void webserver(int portno)
{
    struct sockaddr_in serveraddr;
    int listen_fd;
    int res;
    int set = 1;
    fd_set readset;

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(portno);

    // Create a listening socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    res = setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&set,sizeof(set));
    if (res < 0) {
        perror("setsockopt");
        close(listen_fd);
        return;
    }

    // Bind to the port we will listen on.
    res = bind(listen_fd,(struct sockaddr *) &serveraddr,sizeof(serveraddr));
    if (res < 0) {
        perror("bind");
        close(listen_fd);
        return;
    }

    // Start listening for connections.
    listen(listen_fd, 10);              // max # of connections we can accept


    printf("Waiting for connections\n");

    // Here is the main loop.

    for (;;) {

        // this sockaddr will get filled in with the IP of the client that connects to us.
        struct sockaddr_in newaddr;
        socklen_t newaddrlen  = sizeof(newaddr);
        pthread_attr_t threadattr;
        pthread_t thread;
        int nfd;
        connection_t *conn;
        struct timeval timeout;

        // instead of just calling accept, we will use select so we can have
        // a time out.  When the time out occurs we can check the page cache.
        // this way we don't need to make a special thread just for aging the cache
        for (;;) {
            int rc;

            FD_ZERO(&readset);
            FD_SET(listen_fd, &readset);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            rc = select(listen_fd+1,&readset, NULL,NULL,&timeout);

            // return less than zero is an error.
            if (rc < 0) {
                perror("select");
                break;
            }

            // more than zero means someone wants to connect
            if (rc > 0) {
                break;
            }

            // equal zero means the timeout happened.  check the cache.
            if (rc == 0) {
                // if the page cache timeout is enabled, check to see if we can delete stuff
                if (cache_timeout_seconds != 0) {
                    check_cache_timeout();
                }
            }
        }
        

        // if we get here, the select says we have some connection to accept.

        nfd = accept(listen_fd, (struct sockaddr *) &newaddr, &newaddrlen);

        if (nfd < 0) {
            perror("accept");
            continue;
        }

        if (debug > 0) {
            printf("Got a connection from %s\n",inet_ntoa(newaddr.sin_addr));
        }

        // Create a connection structure to hold information about the connection
        conn = (connection_t *) calloc(1,sizeof(connection_t));
        conn->readfd = nfd;

        // Create a new thread
        pthread_attr_init(&threadattr);
        pthread_create(&thread, &threadattr, webthread, conn);

        // The new thread is responsible for closing the connection when done.
        // Go back and wait for another one.
    }
}

//
// Main function
//

int main(int argc, char *argv[])
{
    pthread_mutexattr_t mutexattr;
    int port = 8080;

    if (argc < 2) {
        printf("Usage: webserver port-number [timeout]\n");
        exit(1);
    }

    // set up page cache.  There is a mutex to guard it.
    pthread_mutexattr_init(&mutexattr);
    pthread_mutex_init(&page_cache_mutex, &mutexattr);

    dq_init(&page_cache);
    mkdir("cache",0777);

    // Load the blacklist
    load_blacklist("blacklist.txt");

    // Grab command line parameters
    if (argc >= 3) {
        cache_timeout_seconds = atoi(argv[2]);
        printf("Page cache timeout is %ld seconds\n",cache_timeout_seconds);
    } else {
        cache_timeout_seconds = 0;
        printf("Page cache will not time out\n");
    }

    if (argc >= 2) {
        port = atoi(argv[1]);
    }

    // Start the server
    webserver(port);

    return 0;
}
