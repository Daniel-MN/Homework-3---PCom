#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "buffer.h"
#include "Parson/parson.h"

void register_function() {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    char username[USERNAMELEN];
    char password[PASSLEN];

    printf("username=");
    scanf("%s", username);
    
    printf("password=");
    scanf("%s", password);

    JSON_Value *value = json_value_init_object();
    JSON_Object *obj = json_value_get_object(value);
    json_object_set_string(obj, "username", username);
    json_object_set_string(obj, "password", password);

    char *json = json_serialize_to_string(value);

    char *message = compute_post_request("34.241.4.235", 
                    "/api/v1/tema/auth/register", "application/json", json, 
                    NULL, 0, NULL);

    send_to_server(sockfd, message);

    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    char *code = strtok(response + 9, "\r\n");
    printf("%s -- ", code);

    if (i != -1) {
        char *mess_error = strtok(buf.data + i + 9, "\"");
        printf("%s\n\n", mess_error);
    } else {
        printf("Successful Registration!\n\n");
    }

    free(message);
    free(response);
    json_free_serialized_string(json);
    json_value_free(value);

    close_connection(sockfd);
}

void logout_function(char **JWT, char **cookies, int *cookies_count) {
    if (*cookies_count == 0) {
        printf("You are not logged in!\n");
        return;
    }



    for (int  i = 0; i < *cookies_count; i++) {
        free(cookies[i]);
        cookies[i] = NULL;
    }

    *cookies_count = 0;

    if (*JWT != NULL) {
        free(*JWT);
        *JWT = NULL;
    }

    printf("You are logged out!\n\n");
}

void login_function(char **JWT, char **cookies, int *cookies_count) {
    if (*cookies_count > 0) {
        printf("You are already logged in!\n");
        printf("Do you want to log out and log in with another account?  ");
        printf("Yes/No\n");
        char answer[4];
        while (1) {
            scanf("%s", answer);
            if (strncmp(answer, "Yes", 3) == 0) {
                logout_function(JWT, cookies, cookies_count);
                break;
            } else if (strncmp(answer, "No", 3) == 0) {
                return;
            } else {
                printf("Please, write \"Yes\" or \"No\"!\n");
            }
        }
    }

    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    char username[USERNAMELEN];
    char password[PASSLEN];

    printf("username=");
    scanf("%s", username);
    
    printf("password=");
    scanf("%s", password);

    JSON_Value *value = json_value_init_object();
    JSON_Object *obj = json_value_get_object(value);
    json_object_set_string(obj, "username", username);
    json_object_set_string(obj, "password", password);

    char *json = json_serialize_to_string(value);

    char *message = compute_post_request("34.241.4.235", 
                    "/api/v1/tema/auth/login", "application/json", json, 
                    NULL, 0, NULL);


    send_to_server(sockfd, message);

    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    if (i != -1) {
        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);
        char *mess_error = strtok(buf.data + i + 9, "\"");
        printf("%s\n\n", mess_error);
    } else {
        
        i = buffer_find(&buf, "connect.sid=", 12);

        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);
        printf("Successful Authentication!\n\n");

        if (i != -1) {
            char *connect_cookie = strtok(buf.data + i, ";");
            int len_cookie = strlen(connect_cookie);
            cookies[*cookies_count] = (char *)malloc((len_cookie + 1)
                                                            * sizeof(char));
            if (cookies[*cookies_count] == NULL) {
                printf("Memory allocation failed!\n");
                exit(1);
            }

            strncpy(cookies[*cookies_count], connect_cookie, len_cookie);

            (*cookies_count)++;
        }
    }

    free(message);
    free(response);
    json_free_serialized_string(json);
    json_value_free(value);

    close_connection(sockfd);
}

char *enter_library_function(char **cookies, int cookies_count) {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    char *JWT = (char *)malloc(JWTLEN * sizeof(char));
    if (JWT == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    
    char *message = compute_get_request("34.241.4.235", 
            "/api/v1/tema/library/access", NULL, cookies, cookies_count, NULL);

    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    if (i != -1) {
        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);
        if (strncmp(code, "401", 3) == 0) {
            printf("You did not get the authorization for library!\n");
            printf("You should try again later!\n\n");
        } else {
            char *mess_error = strtok(buf.data + i + 9, "\"");
            printf("%s\n\n", mess_error);
            free(JWT);
            JWT = NULL;
        }
    } else {

        i = buffer_find(&buf, "\"token\":\"", 9);

        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);
        printf("Access received!\n\n");

        if (i != -1) {
            char *token = strtok(buf.data + i + 9, "\"");
            int len_token = strlen(token);
            strncpy(JWT, token, len_token);
            JWT[len_token] = '\0';
        }
    }

    free(message);
    free(response);
    close_connection(sockfd);
    return JWT;
}

void get_books_function(char *JWT, char **cookies, int cookies_count) {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    char *message = compute_get_request("34.241.4.235", 
            "/api/v1/tema/library/books", NULL, cookies, cookies_count, JWT);
            

    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);

    int i = buffer_find(&buf, "[{", 2);
    JSON_Value *value;
    JSON_Object *one_json;
    JSON_Array *jsons;
    
    if (i == -1) {
        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);

        if (strncmp(code, "403", 3) == 0) {
            printf("You do not have access to the library\n\n");
        } else {
            printf("There are no books in library!\n\n");
        }

    } else {
        value = json_parse_string(response + i);

        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);
        printf("The books from library are:\n");
        if (json_value_get_type(value) != JSONArray) {
            printf("A intrat aici\n");
            return;
        }

        jsons = json_value_get_array(value);
        int nr = json_array_get_count(jsons);
        for (int i = 0; i < nr; i++) {
            one_json = json_array_get_object(jsons, i);
            printf("ID: %d --- TITLE: %s\n", 
                        (int)json_object_get_number(one_json, "id"), 
                        json_object_get_string(one_json, "title"));
        }

        json_value_free(value);

        printf("\n");
    }

    free(message);
    free(response);
    close_connection(sockfd);
}

void get_one_book_function(char *JWT, char **cookies, int cookies_count) {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    int id;
    printf("id=");
    scanf("%d", &id);

    char url[] = "/api/v1/tema/library/books/";
    char *url_send = (char *)malloc(40 * sizeof(char));
    if (url_send == NULL) {
        printf("Memeory allocation failed");
        exit(1);
    }

    sprintf(url_send, "%s%d", url, id);

    char *message = compute_get_request("34.241.4.235", url_send, NULL, 
                                                cookies, cookies_count, JWT);
            

    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    if (i != -1) {
        char *code = strtok(response + 9, "\r\n");
        printf("%s -- ", code);

        if (strncmp(code, "403", 3) == 0) {
            printf("You do not have access to the library\n\n");
        } else if (strncmp(code, "404", 3) == 0) {
            printf("No book with id %d was found!\n\n", id);
        } else {
            char *mess_error = strtok(buf.data + i + 9, "\"");
            printf("%s\n\n", mess_error);
        }
    } else {
        i = buffer_find(&buf, "{", 1);
        JSON_Value *value = json_parse_string(response + i);
        JSON_Object *obj = json_value_get_object(value);

        printf("TITLE = %s\n", json_object_get_string(obj, "title"));
        printf("AUTHOR = %s\n", json_object_get_string(obj, "author"));
        printf("PUBLISHER = %s\n", json_object_get_string(obj, "publisher"));
        printf("GENRE = %s\n", json_object_get_string(obj, "genre"));
        printf("PAGE_COUNT = %d\n", (int)json_object_get_number(obj, "page_count"));

        printf("\n");
        json_value_free(value);
    }

    free(url_send);
    free(message);
    free(response);
    close_connection(sockfd);
}

void add_book_function(char *JWT, char **cookies, int cookies_count) {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    JSON_Value *value = json_value_init_object();
    JSON_Object *obj = json_value_get_object(value);

    char *field = (char *)malloc(FIELD_BOOK_LEN * sizeof(char));
    if (field == NULL) {
        printf("Memory allocation failed\n");
        exit(1);
    }

    printf("title=");
    scanf("%s", field);
    json_object_set_string(obj, "title", field);

    printf("author=");
    scanf("%s", field);
    json_object_set_string(obj, "author", field);

    printf("genre=");
    scanf("%s", field);
    json_object_set_string(obj, "genre", field);

    printf("publisher=");
    scanf("%s", field);
    json_object_set_string(obj, "publisher", field);

    printf("page_count=");
    scanf("%s", field);
    int page_count = atoi(field);
    while (page_count == 0) {
        printf("Write a valid number pls!\n");
        printf("page_count=");
        scanf("%s", field);
        page_count = atoi(field);
    }

    json_object_set_number(obj, "page_count", page_count);

    char *json = json_serialize_to_string(value);

    char *message = compute_post_request("34.241.4.235", 
                    "/api/v1/tema/library/books", "application/json", json, 
                    cookies, cookies_count, JWT);

    send_to_server(sockfd, message);

    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    char *code = strtok(response + 9, "\r\n");
    printf("%s -- ", code);

    if (i != -1) {
        if (strncmp(code, "403", 3) == 0) {
            printf("You do not have access to the library\n\n");
        } else {
            char *mess_error = strtok(buf.data + i + 9, "\"");
            printf("%s\n\n", mess_error);
        }
    } else {
        printf("A new book was added!\n\n");        
    }

    free(message);
    free(response);
    json_free_serialized_string(json);
    json_value_free(value);

    close_connection(sockfd);
}

void delete_book_function(char *JWT, char **cookies, int cookies_count) {
    int sockfd = open_connection("34.241.4.235", 8080, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Could not connect to server!\n");
        exit(1);
    }

    int id;
    printf("id=");
    scanf("%d", &id);

    char url[] = "/api/v1/tema/library/books/";
    char *url_send = (char *)malloc(40 * sizeof(char));
    if (url_send == NULL) {
        printf("Memory allocation failed");
        exit(1);
    }

    sprintf(url_send, "%s%d", url, id);

    char *message = compute_delete_request("34.241.4.235", url_send, cookies, 
                                                                cookies_count, JWT);
            

    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    buffer buf;
    buf.data = response;
    buf.size = strlen(response);
    int i = buffer_find(&buf, "\"error\":\"", 9);

    char *code = strtok(response + 9, "\r\n");
    printf("%s -- ", code);

    if (i != -1) {
        if (strncmp(code, "403", 3) == 0) {
            printf("You do not have access to the library\n\n");
        } else if (strncmp(code, "404", 3) == 0) {
            printf("No book with id %d was found!\n\n", id);
        } else {
            char *mess_error = strtok(buf.data + i + 9, "\"");
            printf("%s\n\n", mess_error);
        }
    } else {
        printf("The book was deleted!\n\n");
    }

    free(url_send);
    free(message);
    free(response);
    close_connection(sockfd);
}

int main(int argc, char *argv[]) {
    char **cookies = (char **)malloc(NR_MAX_COOKIES * sizeof(char *));
    if (cookies == NULL) {
        printf("Memory allocation failed!\n");
        return 1;
    }

    int cookies_count = 0;

    char *JWT = NULL;

    char *command = (char *)malloc(COMMANDLEN * sizeof(char));
    if (command == NULL) {
        printf("Memory allocation failed!\n");
        return 1;
    }


    int end = 0;

    while (!end) {
        scanf("%s", command);

        if (strncmp(command, "register", 8) == 0) {
            register_function();

        } else if (strncmp(command, "login", 5) == 0) {
            login_function(&JWT, cookies, &cookies_count);

        } else if (strncmp(command, "enter_library", 13) == 0) {
            JWT = enter_library_function(cookies, cookies_count);

        } else if (strncmp(command, "get_books", 9) == 0) {
            get_books_function(JWT, cookies, cookies_count);

        } else if (strncmp(command, "get_book", 8) == 0) {
            get_one_book_function(JWT, cookies, cookies_count);

        } else if (strncmp(command, "add_book", 8) == 0) {
            add_book_function(JWT, cookies, cookies_count); 

        } else if (strncmp(command, "delete_book", 11) == 0) {
            delete_book_function(JWT, cookies, cookies_count);

        } else if (strncmp(command, "logout", 6) == 0) {
            logout_function(&JWT, cookies, &cookies_count);

        } else if (strncmp(command, "exit", 4) == 0) {
            end = 1;

        } else {
            printf("Invalid command! Try:\n");
            printf("register, login, enter_library, get_books, get_book, ");
            printf("add_book, delete_book, logout, exit\n\n");
        }
    }

    
    free(command);
    if (JWT != NULL) {
        free(JWT);
    }

    for (int i = 0; i < cookies_count; i++) {
        free(cookies[i]);
    }
    free(cookies);
    return 0;
}
