#include <sys/socket.h> 
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include "stringops.h"
#include <fcntl.h>
#include "fs.h"
#include <signal.h>
#include <pthread.h>
#define CRLF  "\r\n" // carriage return line feed
#define SP    " "
const string_view WEB_ROOT =STRING_VIEW_FROM_LITERAL("./www/"); 
const short PORT=6970;


typedef struct {
        string method;
        string uri;
        string version;
} http_req_line;

typedef enum http_status {
        HTTP_RES_OK              = 200,
        HTTP_RES_INTERNAL_SERVER_ERR = 500,
        HTTP_RES_BAD_REQUEST     = 400,
        HTTP_RES_NOT_FOUND       = 404
} http_status;

// typedef struct{
//    const char * version;
//    http_status status;
// }http_resp_status_line;

static inline string string_from_view(string_view v) {
        return (string){ .data = v.start, .len = v.len };
}
static inline string_view view_from_string(string s) {
        return (string_view){ .start = s.data, .len = s.len };
}
const char * http_status_to_string(http_status status){
        switch(status){
                case HTTP_RES_OK:
                        return "OK";
                case HTTP_RES_BAD_REQUEST:
                        return "Bad Request";
                case HTTP_RES_INTERNAL_SERVER_ERR:
                        return "Internal Servor Error";
                case HTTP_RES_NOT_FOUND:
                        return "Not Found";
                default:
                        return "Unknown";
        }
}
http_req_line http_req_line_init() {
        http_req_line line;
        memset(&line, 0, sizeof(line));
        return line;
}
const char * get_mime_type(const char * path){
        const char  * dot=strrchr(path,'.');
        if(!dot)return "application/octet-stream";
        if (strcmp(dot, ".html") == 0) return "text/html";
        if (strcmp(dot, ".css")  == 0) return "text/css";
        if (strcmp(dot, ".js")   == 0) return "application/javascript";
        if (strcmp(dot, ".png")  == 0) return "image/png";
        if(strcmp(dot,".svg")==0)return "image/svg+xml";
        if (strcmp(dot, ".jpg")  == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
        return "application/octet-stream";
}
string http_response_generate(char* buf,size_t buf_len,http_status status,size_t body_len,const char *content_type){
        int n=0;
        string response;
        response.len=0;
        memset(buf,0,buf_len);
        // Use snprintf for bounded writes to ensure safety
        response.len+=snprintf(buf, buf_len, "HTTP/1.0 %d %s" CRLF, status, http_status_to_string(status));
        // response.len+=sprintf(buf + response.len, "Content-Type: text/html" CRLF); /// wont see css without this
        response.len+=snprintf(buf+response.len, buf_len-response.len, "Access-Control-Allow-Origin: *" CRLF);
        response.len+=snprintf(buf+response.len, buf_len-response.len, "Server: Harsh Panchal's C HTTP Server" CRLF);

        response.len += snprintf(buf+response.len, buf_len-response.len, "Content-Type: %s" CRLF, content_type);
        response.len += snprintf(buf+response.len, buf_len-response.len, "Content-Length: %zu" CRLF ,body_len);
        response.len += snprintf(buf+response.len, buf_len-response.len, CRLF);
        // response.len=n;
        response.data=buf;
        return response;
}
string_view err_404 =STRING_VIEW_FROM_LITERAL("<p>Error 404 </p>");

bool ssl_write_all(SSL *ssl, const char *buf, size_t len){
        size_t sent = 0;
        while (sent < len) {
                int r = SSL_write(ssl, buf + sent, (int)(len - sent));
                if (r <= 0) {
                        int e = SSL_get_error(ssl, r);
                        ERR_print_errors_fp(stderr);
                        return false;
                }
                sent += (size_t)r;
        }
        return true;
}

bool http_send_response_ssl(SSL *ssl,string header,string body){
        if(!ssl_write_all(ssl, header.data, header.len)) return false;
        if(!ssl_write_all(ssl, body.data, body.len)) return false;
        return true;
}

bool http_serve_file_ssl(SSL *ssl,string filename){
        char buf[256];
        string hd;
        
        string header_copy = { .data = NULL, .len = 0 };
        char filename_buf[PATH_MAX];
        bool return_value=true;
        int in_fd=-1;

        snprintf(filename_buf, sizeof(filename_buf), "%.*s%.*s",
                         (int)WEB_ROOT.len - 1, WEB_ROOT.start,
                         (int)filename.len, filename.data);

        const char * mime_type=get_mime_type(filename_buf);
        fs_metadata file_metadata=fs_get_metadata(string_from_cstr(filename_buf));

        if(!file_metadata.exists){
                (void)http_send_response_ssl(ssl,http_response_generate(buf,sizeof(buf),HTTP_RES_NOT_FOUND,err_404.len,"text/html"),string_from_view(err_404));
                return false;
        }
        hd=http_response_generate(buf,sizeof(buf),HTTP_RES_OK,file_metadata.size,mime_type);

       
        header_copy.len = hd.len;
        header_copy.data = malloc(header_copy.len);
        if (!header_copy.data) {
                // Use buf for error response header
                (void)http_send_response_ssl(ssl,http_response_generate(buf,sizeof(buf),HTTP_RES_INTERNAL_SERVER_ERR,err_404.len,"text/html"),string_from_view(err_404));
                return false;
        }
        memcpy(header_copy.data, hd.data, header_copy.len);

        ///send header only for null error
        if(!ssl_write_all(ssl, header_copy.data, header_copy.len)){ // Use direct write for header
                  return_value=false;
                  goto cleanup;
        }

        in_fd=open(filename_buf,O_RDONLY);
        if(in_fd<0){
                return_value=false;
                (void)http_send_response_ssl(ssl,http_response_generate(buf,sizeof(buf),HTTP_RES_NOT_FOUND,err_404.len,"text/html"),string_from_view(err_404));
                goto cleanup;
        }

        const size_t chunk_size = 16 * 1024;
        char *read_buf = malloc(chunk_size); // revert to malloc
        if(!read_buf){
                (void)http_send_response_ssl(ssl,http_response_generate(buf,sizeof(buf),HTTP_RES_INTERNAL_SERVER_ERR,err_404.len,"text/html"),string_from_view(err_404));
                return_value=false;
                goto cleanup;
        }
        ssize_t r;
        bool first_chunk = true; 

        while ((r = read(in_fd, read_buf, chunk_size)) > 0) {
                ssize_t total_written = 0;
                size_t write_offset = 0;
                size_t write_len = (size_t)r;

                /// brute check for null
                if (first_chunk && read_buf[0] == '\0') {
                        write_offset = 1;
                        write_len -= 1;
                }
                first_chunk = false;

                while (total_written < write_len) {
                        int w = SSL_write(ssl, read_buf + write_offset + total_written, (int)(write_len - total_written));
                        if (w <= 0) {
                                int err = SSL_get_error(ssl, w);
                                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                                        continue;
                                }
                                ERR_print_errors_fp(stderr);
                                return_value = false;
                                free(read_buf);
                                goto cleanup;
                        }
                        total_written += w;
                }
        }

        if (r < 0) {
                perror("read()");
                return_value=false;
        }
        free(read_buf);
cleanup:
        if(in_fd>0){
                close(in_fd);
        }
        if (header_copy.data) free((void*)header_copy.data);
        return return_value;
}

void* handle_client(void * client_socket_ptr) {
        SSL *ssl = (SSL *)client_socket_ptr;
        int client_socket = SSL_get_fd(ssl);
        ssize_t n = 0;
        char buf[8192];
        string hello = string_from_cstr(
                "<span style=\"\n"
                "       color: red;\n"
                "       font-weight: bold;\n"
                "\">Hello Harsh Panchal</span>"
        );

        string bye = string_from_cstr(
                "<span style=\"\n"
                "       color: blue;\n"
                "       font-weight: bold;\n"
                "\">Bye Harsh Panchal</span>"
        );

        for (;;) {
                if (SSL_accept(ssl) <= 0) {
                        ERR_print_errors_fp(stderr);
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        if (client_socket >= 0) close(client_socket);
                        return (const void *) -1;
                }

                memset(buf, 0, sizeof(buf));
                n = SSL_read(ssl, buf, sizeof(buf) - 1);
                if (n < 0) {
                        ERR_print_errors_fp(stderr);
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        if (client_socket >= 0) close(client_socket);
                        return (const void *) -1;
                }
                if (n == 0) {
                        printf("Connection closed gracefully\n");
                        break;
                }
                printf("Requests:\n%s", buf);

                buf[n] = '\0';
                char *eol = strstr(buf, CRLF);
                if (!eol) {
                        fprintf(stderr, "Malformed request (no CRLF)\n");
                        free_splits(NULL); 
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(client_socket);
                        return (const void *) -1;
                }
                size_t L = eol - buf;
                char line[8192];
                if (L >= sizeof(line)) L = sizeof(line) - 1;
                memcpy(line, buf, L);
                line[L] = '\0';

                string_splits comps = split_string(line, ' ');
                if (comps.count != 3) {
                        fprintf(stderr, "Invalid request line (got %zu parts)\n", comps.count);
                        free_splits(&comps);
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(client_socket);
                        return (const void *) -1;
                }

                http_req_line req_line = http_req_line_init();
                req_line.method.data  = comps.splits[0].start;
                req_line.method.len   = comps.splits[0].len;
                req_line.uri.data     = comps.splits[1].start;
                req_line.uri.len      = comps.splits[1].len;
                req_line.version.data = comps.splits[2].start;
                req_line.version.len  = comps.splits[2].len;
                free_splits(&comps);
                /// routing logic
                string route_hello = string_from_cstr("/hello");
                string route_bye   = string_from_cstr("/bye");
                string route_index = string_from_cstr("/index");
                string route_root = string_from_cstr("/");

                const char * mime_type=get_mime_type(req_line.uri.data);


                if (strings_equal(&req_line.uri, &route_hello)) {
                        http_send_response_ssl(
                                ssl,
                                http_response_generate(buf, sizeof(buf), HTTP_RES_OK, hello.len,"text/html"),
                                hello
                        );
                        //// send mime type as text/html as without it will fallback to application/octet-stream
                        //// and prompt browser to download file
                }
                else if (strings_equal(&req_line.uri, &route_bye)) {
                        http_send_response_ssl(
                                ssl,
                                http_response_generate(buf, sizeof(buf), HTTP_RES_OK, bye.len,"text/html"),
                                bye
                        );
                }
                else if (strings_equal(&req_line.uri, &route_index)
                                 || strings_equal(&req_line.uri, &route_root)) {
                        if (!http_serve_file_ssl(ssl, string_from_cstr("index.html"))) {
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                return (const void *) -1;
                        }
                }
                else {
                        if (!http_serve_file_ssl(ssl, req_line.uri)) {
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                return (const void *) -1;
                        }
                        /// for react router handling serve index.html if serve file above fails
                }

                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_socket);
                break;
        }
        printf("-------------------\n");
        return (const void *) 0;
}



int main(void) {
        signal(SIGPIPE,SIG_IGN);/// to fix ending process if client quits on send()
        int rc = 0;
        struct sockaddr_in bind_addr;
        struct sockaddr_in client_sock;
        int tcp_socket = 0;
        int ret = 0;
        int client_socket = 0;
        int enabled = 1;
        const char * web_root="./www";
        fs_metadata web_root_meta= fs_get_metadata(string_from_view(WEB_ROOT));
        if(!web_root_meta.exists){
                ///rwxr -xr-x
                mkdir(web_root,S_IEXEC | S_IWRITE |S_IREAD |S_IRGRP | S_IXGRP | S_IROTH |S_IXOTH);
        }
        socklen_t client_len = sizeof(client_sock);

        memset(&bind_addr, 0, sizeof(bind_addr));
        tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_socket == -1) {
                perror("socket");
                return 0;
        }
        printf("Socket created\n");

        (void)setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));/// reuse port
        bind_addr.sin_port = htons(PORT); /// little endian to big endian
        bind_addr.sin_family = AF_INET;

        inet_pton(AF_INET,"0.0.0.0",&bind_addr.sin_addr); /// on 0.0.0.0 or use inet_pton()

        rc = bind(tcp_socket, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
        //  note typecasting of pointer to sockaddr and not sockaddr_in
        if (rc < 0) {
                perror("bind()");
                ret = 1;
                goto exit;
        }
        printf("bind succeeded\n");

        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        /// init ssl context
        const SSL_METHOD *method = TLS_server_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        if (!ctx) {
                ERR_print_errors_fp(stderr);
                exit(1);
        }
        //// paths of our SSL Certs 

SSL_CTX_use_certificate_chain_file(ctx, "/etc/letsencrypt/live/harshpanchal.duckdns.org/fullchain.pem");
SSL_CTX_use_PrivateKey_file(ctx, "/etc/letsencrypt/live/harshpanchal.duckdns.org/privkey.pem", SSL_FILETYPE_PEM);

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
#ifdef SSL_CTX_set_ecdh_auto
        SSL_CTX_set_ecdh_auto(ctx, 1);
#else
        {
                EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                if (ec_key) {
                        SSL_CTX_set_tmp_ecdh(ctx, ec_key);
                        EC_KEY_free(ec_key);
                }
        }
#endif
        SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!eNULL:!MD5:!RC4");

        rc = listen(tcp_socket, SOMAXCONN);///SOMAXCONN = size of our request queue
        if (rc < 0) {
                perror("listen()");
                ret = 1;
                goto exit;
        }
        printf("listen succeeded\n");


        pthread_t* threads = NULL;
        size_t threads_count=0;
        size_t threads_capacity=10;
        threads=calloc(threads_capacity,sizeof(pthread_t));
        for (;;) {
                printf("Waiting for connections...\n");
                client_socket = accept(tcp_socket,(struct sockaddr *)&client_sock,&client_len); /// pop front from queue
                if (client_socket < 0) {
                        perror("accept()");
                        continue;
                }
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client_sock.sin_addr), client_ip, INET_ADDRSTRLEN);
                printf("Got connection from %s:%d\n", client_ip, ntohs(client_sock.sin_port));
                pthread_t thread;
                //// bind thread to routine
                SSL *ssl = SSL_new(ctx);
                if (!ssl) {
                        fprintf(stderr, "SSL_new failed\n");
                        close(client_socket);
                        continue;
                }
                SSL_set_fd(ssl, client_socket);
                rc=pthread_create(&thread,NULL,handle_client,ssl);
                if(rc<0){
                        perror("pthread_create()");
                        SSL_free(ssl);
                        close(client_socket);
                        continue;
                }
                pthread_detach(thread);
                if(threads_count+1>threads_capacity){
                        threads_capacity*=2;
                        pthread_t* new_threads=realloc(threads,threads_capacity*sizeof(pthread_t));
                        if(!new_threads){
                                perror("realloc()");
                                goto exit;
                        }
                        threads=new_threads;
                }
                threads[threads_count++]=thread;

                if (client_socket < 0) {
                        perror("accept()");
                        continue;
                }



        }

exit:
        for(size_t i=0;i<threads_count;i++){
                pthread_kill(threads[i],SIGTERM);
        }
        if (threads) free(threads);
        if (ctx) SSL_CTX_free(ctx);
        close(tcp_socket);
        return ret;
}