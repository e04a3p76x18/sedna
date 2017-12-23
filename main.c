/*
    Sedna
    Copyright (C) 2017 e04a3p76x18
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <dirent.h>
#include <strings.h>
#include <stdbool.h>
#include <gtk/gtk.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

struct app
{
    struct node * root;
    GtkWidget * grid;
    struct dnscache * cache;
};

struct dnscache
{
    unsigned int count;
    struct dns * dns;
};

struct dns
{
    unsigned char * name;
    char ip[INET_ADDRSTRLEN];
};

#define DNS_CACHE_SIZE 250

struct rule
{
    char * process;
    char * domain;
    short authorize;
    char ip[INET_ADDRSTRLEN];
    char port[6];
    char protocol[6];
    unsigned short src;
    int row;
    bool data;
    u_int8_t hook;
    char hash[129];
};

void destructor(struct rule * _this)
{
    if (_this) {
        if (_this->domain) {
            free(_this->domain);
        }
        if (_this->process) {
            free(_this->process);
        }
        free(_this);
        _this = NULL;
    }
}

void set_process(struct rule * _this, char * pid)
{
    if (_this && pid) {
        for (int i = 0; i < strlen(pid); i++) {
            if (pid[i] == '\\') {
                return;
            }
        }
        if (!_this->process) {
            _this->process = (char *) calloc(strlen(pid) + 1, sizeof (char));
        } else {
            _this->process = (char *) realloc(_this->process, (strlen(pid) + 1) * sizeof (char));
        }
        if (_this->process) {
            snprintf(_this->process, strlen(pid) + 1, "%s", pid);
        }
    }
}

void set_port(struct rule * _this, char * port)
{
    if (_this && port) {
        for (int i = 0; i < strlen(port); i++) {
            if (!isdigit(port[i]) && port[i] != '*') {
                return;
            }
        }
        snprintf(_this->port, 6, "%s", port);
    }
}

enum
{
    INCOMING = 1, OUTGOING = 3
};

void set_hash(struct rule * _this, char * hash)
{
    if (_this) {
        snprintf(_this->hash, 129, "%s", hash);
    }
}

void set_hook(struct rule * _this, u_int8_t hook)
{
    if (_this) {
        if (hook == INCOMING || hook == OUTGOING) {
            _this->hook = hook;
        }
    }
}

void set_domain(struct rule * _this, char * domain)
{
    if (_this && domain) {
        for (int i = 0; i < strlen(domain); i++) {
            if ((!(domain[i] >= 'a' && domain[i] <= 'z')) && (!(domain[i] >= 'A' && domain[i] <= 'Z'))
                    && domain[i] != '/' && domain[i] != '-' && domain[i] != '*'
                    && (!isdigit(domain[i])) && domain[i] != '.' && domain[i] != '_') {
                return;
            }
        }
        if (!_this->domain) {
            _this->domain = (char *) calloc(strlen(domain) + 1, sizeof (char));
        } else {
            _this->domain = (char *) realloc(_this->domain, (strlen(domain) + 1) * sizeof (char));
        }
        if (_this->domain) {
            snprintf(_this->domain, strlen(domain) + 1, "%s", domain);
        }
    }
}

enum
{
    DEFAULT = 0, ALLOW = 1, BLOCK = 2, SESSION = 3, BLOCKSESN = 4, SELECT = 5, DATA = 6
};

void set_authorization(struct rule * _this, short authorize)
{
    if (_this) {
        if (authorize >= DEFAULT && authorize <= BLOCKSESN) {
            _this->authorize = authorize;
        }
    }
}

void set_protocol(struct rule * _this, char * protocol)
{
    if (_this && protocol) {
        for (int i = 0; i < strlen(protocol); i++) {
            if ((!(protocol[i] >= 'a' && protocol[i] <= 'z')) && (!(protocol[i] >= 'A' && protocol[i] <= 'Z')) && protocol[i] != '*'
                    && (!isdigit(protocol[i]))) {
                return;
            }
        }
        snprintf(_this->protocol, 6, "%s", protocol);
    }
}

void set_ip(struct rule * _this, char * ip)
{
    if (_this && ip) {
        for (int x = 0; x < strlen(ip); x++) {
            if (ip[x] != '*' && (!isdigit(ip[x])) && ip[x] != '.' && ip[x] != '*') {
                return;
            }
        }
        snprintf(_this->ip, INET_ADDRSTRLEN, "%s", ip);
    }
}

void set_src(struct rule * _this, int src)
{
    if (_this && src) {
        _this->src = src;
    }
}

void set_row(struct rule * _this, int row)
{
    if (_this) {
        _this->row = row;
    }
}

struct rule * constructor(u_int8_t hook, char * hash, char * pid, char * domain, short authorize, unsigned short port, unsigned short sp, const char * protocol, char * ip)
{
    struct rule * object = (struct rule *) calloc(1, sizeof (struct rule));
    set_hook(object, hook);
    set_hash(object, hash);
    set_process(object, pid);
    set_domain(object, domain);
    set_authorization(object, authorize);
    char p[5 + 1];
    snprintf(p, 5 + 1, "%hu", port);
    set_port(object, p);
    set_src(object, sp);
    set_protocol(object, protocol);
    set_ip(object, ip);
    return object;
}

enum
{
    HOOK = 0, PID = 1, DOMAIN = 2, PORT = 3, PROTOCOL = 4, AUTHORIZE = 5, DELETE = 6, IP = 7, HASH = 8, SRC = 9
};

void set_property(struct rule * _this, int i, char * x)
{
    switch (i) {
        case HOOK:
            set_hook(_this, x ? x[0] - '0' : 0);
            break;
        case PID:
            set_process(_this, x);
            break;
        case DOMAIN:
            set_domain(_this, x);
            break;
        case IP:
            set_ip(_this, x);
            break;
        case PORT:
            set_port(_this, x);
            break;
        case PROTOCOL:
            set_protocol(_this, x);
            break;
        case AUTHORIZE:
            set_authorization(_this, x ? (short) x[0] - '0' : 0);
            break;
        case HASH:
            set_hash(_this, x);
            break;
    }
}

char * get_property(struct rule * _this, int i, int serialize)
{
    switch (i) {
        case HOOK:
            return serialize ? _this->hook == OUTGOING ? "3" : "1" : _this->hook == INCOMING ? "━" : "▁";
        case PID:
            return _this->process && _this->process[0] != '\0' ? _this->process : "*";
        case DOMAIN:
            return _this->domain ? _this->domain : _this->ip[0] != '\0' ? _this->ip : "*";
        case PORT:
            return _this->port && _this->port[0] == '\0' ? "*" : _this->port;
        case HASH:
            return _this->hash && _this->hash[0] == '\0' ? '\0' : _this->hash;
        case PROTOCOL:
            return _this->protocol && _this->protocol[0] != '\0' ? _this->protocol : "*";
        case AUTHORIZE:
            return serialize ? _this->authorize == ALLOW ? "1" : _this->authorize == BLOCK ? "2" : _this->authorize == DEFAULT ? "0" : "\0" : "▁";
        case DELETE:
            return "⬭";
        case IP:
            return _this->ip && _this->ip[0] != '\0' ? _this->ip : "*";
        default:
            return NULL;
    }
}

char * enum_to_str(int i)
{
    switch (i) {
        case HOOK: return "hook";
        case PID: return "pid";
        case DOMAIN: return "domain";
        case PORT: return "port";
        case PROTOCOL: return "protocol";
        case SRC: return "src";
        case AUTHORIZE: return "authorize";
        case DELETE: return "x";
        case IP: return "ip";
        case HASH: return "hash";
        default: return NULL;
    }
}

int str_to_enum(const char * i)
{
    if (strcmp("hook", i) == 0) {
        return HOOK;
    } else if (strcmp("pid", i) == 0) {
        return PID;
    } else if (strcmp("domain", i) == 0) {
        return DOMAIN;
    } else if (strcmp("port", i) == 0) {
        return PORT;
    } else if (strcmp("protocol", i) == 0) {
        return PROTOCOL;
    } else if (strcmp("src", i) == 0) {
        return SRC;
    } else if (strcmp("authorize", i) == 0) {
        return AUTHORIZE;
    } else if (strcmp("x", i) == 0) {
        return DELETE;
    } else if (strcmp("ip", i) == 0) {
        return IP;
    } else {
        return -1;
    }
}

const char * get_class_name(int x)
{
    switch (x) {
        case SESSION: return "session";
        case BLOCKSESN: return "block-session";
        case ALLOW: return "allow";
        case BLOCK: return "block";
        case SELECT: return "select";
        case DATA: return "data";
        default: return "default";
    }
}

struct node
{
    struct rule * rule;
    struct node * next;
    struct node * root;
};

void set_row_class(GtkWidget * grid, struct rule * object)
{
    if (object) {
        const char * name = get_class_name(object->authorize);
        for (int i = 0; i < 8; i++) {
            GtkWidget * widget = gtk_grid_get_child_at(GTK_GRID(grid), i, object->row);
            if (widget) {
                gtk_widget_set_name(widget, name);
            }
        }
    }
}

void update_row(struct node * root, int row, int add)
{
    struct node * ptr = root;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        if (ptr->rule->row > row) {
            ptr->rule->row = ptr->rule->row + add;
        }
    }
}

static void authorize_click(GtkWidget * button, gpointer data)
{
    struct node * ptr = (struct node *) data;
    if (data && ptr->rule) {
        short authorize = (ptr->rule->authorize % 4) + 1;
        set_authorization(ptr->rule, authorize);
        GtkWidget * grid = gtk_widget_get_ancestor(button, GTK_TYPE_GRID);
        const char * class = get_class_name(SELECT);
        if (grid && strcmp(gtk_widget_get_name(button), class) != 0) {
            set_row_class(grid, ptr->rule);
        }
    }
}

static void direction_click(GtkWidget * button, gpointer data)
{
    struct node * ptr = (struct node *) data;
    if (data && ptr->rule) {
        u_int8_t hook = ptr->rule->hook == INCOMING ? OUTGOING : INCOMING;
        set_hook(ptr->rule, hook);
        char * str = get_property(ptr->rule, HOOK, 0);
        if (str) {
            gtk_button_set_label(GTK_BUTTON(button), str);
        }
    }
}

void delete_node(struct node * key, struct node * root)
{
    struct node * ptr = root;
    struct node * prv = ptr;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        if (ptr->rule == key->rule) {
            prv->next = ptr->next;
            break;
        }
        prv = ptr;
    }
    destructor(ptr->rule);
    free(ptr);
}

static void delete_click(GtkWidget * button, gpointer data)
{
    struct node * ptr = (struct node *) data;
    GtkWidget * grid = gtk_widget_get_ancestor(button, GTK_TYPE_GRID);
    if (data && ptr->rule && grid) {
        if (ptr->rule->data) {
            gtk_grid_remove_row(GTK_GRID(grid), ptr->rule->row + 1);
        }
        gtk_grid_remove_row(GTK_GRID(grid), ptr->rule->row);
        int row = ptr->rule->row;
        bool _data = ptr->rule->data;
        delete_node(ptr, ptr->root);
        update_row(ptr->root, row, _data ? -2 : -1);
    }
}

struct node * insert(struct rule * object, struct node * root)
{
    if (object && root) {
        struct node * ptr = root;
        while (ptr->next != NULL) {
            ptr = ptr->next;
        }
        object->row = (!ptr->rule ? -1 : ptr->rule->data ? ptr->rule->row + 1 : ptr->rule->row) + 1;
        ptr->next = calloc(1, sizeof (struct node));
        if (ptr->next) {
            ptr->next->rule = object;
            ptr->next->root = root;
            return ptr->next;
        }
    }
    return NULL;
}

struct node * find_row_class(struct node * root, GtkWidget * grid, const char * class)
{
    struct node * ptr = root;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        GtkWidget * widget = gtk_grid_get_child_at(GTK_GRID(grid), PID, ptr->rule->row);
        if (widget) {
            if (strcmp(gtk_widget_get_name(widget), class) == 0) {
                return ptr;
            }
        }
    }
    return NULL;
}

static void buton_click(GtkWidget * button, gpointer data)
{
    struct node * ptr = (struct node *) data;
    GtkWidget * grid = gtk_widget_get_ancestor(button, GTK_TYPE_GRID);
    if (data && grid && ptr->rule) {
        const char * class = get_class_name(SELECT);
        struct node * object = find_row_class(ptr->root, grid, class);
        if (object) {
            gtk_grid_remove_row(GTK_GRID(grid), object->rule->row);
            gtk_grid_insert_row(GTK_GRID(grid), object->rule->row);
            print_rule(object, false, grid);
        }
        gtk_grid_remove_row(GTK_GRID(grid), ptr->rule->row);
        gtk_grid_insert_row(GTK_GRID(grid), ptr->rule->row);
        print_rule(ptr, true, grid);
    }
}

void display(struct node * ptr, struct rule * object, struct app * view)
{
    gtk_grid_insert_row(GTK_GRID(view->grid), object->row);
    print_rule(ptr, false, view->grid);
}

struct node * add_object(u_int8_t hook, char * hash, char * pid, char * domain, short authorize, unsigned short port, unsigned short sp, const char * protocol, char * ip, struct app * view)
{ 
    struct rule * object = constructor(hook, &hash[0], pid, domain, authorize, port, sp, protocol, ip);
    struct node * ptr = insert(object, view->root);
    if (ptr) {
        return ptr;
    }
    if (object) { 
        free(object);
    }
    return NULL;
}

static void add_click(GtkWidget * button, gpointer data)
{
    struct app * view = (struct app *) data;
    const char * class = get_class_name(DEFAULT);
    if (data && view->root && view->grid && !find_row_class(view->root, view->grid, class)) {
        struct node * ptr = add_object(OUTGOING, NULL, NULL, NULL, DEFAULT, 0, 0, "*", NULL, view);
        if (ptr) {
            display(ptr, ptr->rule, view);
        }
    }
}

void set_row_visible(struct app * view, struct node * ptr, bool display)
{
    for (int x = 0; x < 9; x++) {
        GtkWidget * widget = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(view->grid), x, ptr->rule->row));
        if (widget) {
            display ? gtk_widget_show(widget) : gtk_widget_hide(widget);
        }
        if (x == 0 && ptr->rule->data) {
            GtkWidget * label = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(view->grid), 1, ptr->rule->row + 1));
            if (label) {
                display ? gtk_widget_show(label) : gtk_widget_hide(label);
            }
        }
    }
}

bool find_str(const char * search, struct node * ptr)
{
    for (int i = 0; i < 8; i++) {
        char * str = get_property(ptr->rule, i, 0);
        if (str) {
            if (strcasestr(str, search) != NULL) {
                return true;
            }
        }
    }
    return false;
}

static void search_click(GtkWidget * entry, gpointer data)
{
    struct app * view = (struct app *) data;
    struct node * ptr = view->root;
    const char * search = gtk_entry_get_text(GTK_ENTRY(entry));
    if (ptr && view->grid && data) {
        while (ptr->next != NULL) {
            ptr = ptr->next;
            bool x = find_str(search, ptr);
            set_row_visible(view, ptr, x);
        }
    }
}

static void set_property_callback(GtkWidget * entry, gpointer data)
{
    const char * attribute = gtk_entry_get_placeholder_text(entry);
    char * input = gtk_entry_get_text(entry);
    if (data && attribute && input) {
        struct rule * ptr = (struct rule *) data;
        int x = str_to_enum(attribute);
        set_property(ptr, x, input);
    }
}

void set_label_property(int i, GtkWidget * label)
{
    gtk_label_set_width_chars(GTK_LABEL(label), (i == HOOK || i == DELETE) ? 1 : i == AUTHORIZE ? 1 : (i == PID || i == 10) ? 26 : i == DOMAIN ? 28 : i == PROTOCOL ? 4 : 5);
    if (i == PID || i == DOMAIN || i == 10) {
        gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
        gtk_label_set_line_wrap_mode(GTK_LABEL(label), GTK_WRAP_CHAR);
    }
    if (i != 10) {
        gtk_widget_set_halign(label, (i == AUTHORIZE || i == HOOK || i == DELETE) ? GTK_ALIGN_FILL : GTK_ALIGN_START);
        gtk_label_set_xalign(GTK_LABEL(label), (i == AUTHORIZE || i == HOOK || i == DELETE) ? 0.5 : 0);
        gtk_widget_set_valign(label, i == DELETE ? 1 : 0);
    }
}

void print_rule(struct node * ptr, bool selected, GtkWidget * grid)
{
    const char * name = get_class_name(selected ? SELECT : ptr->rule->authorize);
    for (int i = 0; i < 7; i++) {
        char * str = get_property(ptr->rule, i, 0);
        int input = selected && (i == PID || i == DOMAIN || i == PORT || i == PROTOCOL) ? 1 : 0;
        GtkWidget * widget = input ? gtk_entry_new() : gtk_button_new_with_label(str);
        if (widget) {
            if (input) {
                if (i != PID && i != DOMAIN) {
                    gtk_entry_set_max_width_chars(GTK_ENTRY(widget), 5);
                }
                gtk_entry_set_width_chars(GTK_ENTRY(widget), i == PID ? 26 : i == DOMAIN ? 28 : i == PROTOCOL ? 4 : 5);
                gtk_entry_set_text(GTK_ENTRY(widget), str);
                char * attribute = enum_to_str(i);
                gtk_entry_set_placeholder_text(GTK_ENTRY(widget), attribute);
                g_signal_connect(widget, "changed", G_CALLBACK(set_property_callback), ptr->rule);
            } else {
                GtkWidget * label = gtk_bin_get_child(GTK_BIN(widget));
                set_label_property(i, label);
                gtk_widget_set_hexpand(widget, TRUE);
                g_signal_connect(widget, "clicked", G_CALLBACK(i == DELETE ? delete_click : i == HOOK ? direction_click : i == AUTHORIZE ? authorize_click : buton_click), ptr);
            }
            gtk_widget_set_name(GTK_WIDGET(widget), name);
            gtk_grid_attach(GTK_GRID(grid), widget, i, ptr->rule->row, 1, 1);
            gtk_widget_show(widget);
        }
    }
}

static void toogle_click(GtkToggleButton * togglebutton, gpointer data)
{
    int * x = (int *) data;
    gboolean active = gtk_toggle_button_get_active(togglebutton);
    *x = active ? 1 : 0;
    gtk_button_set_label(GTK_BUTTON(togglebutton), active ? "always" : "session only");
}

gboolean cabk(GIOChannel *source, GIOCondition condition, gpointer data)
{
    char buf[4096] __attribute__((aligned));
    struct nfq_handle * h = (struct nfq_handle *) data;
    int rv = recv(g_io_channel_unix_get_fd(source), buf, sizeof (buf), 0);
    if (rv > 0 && condition && G_IO_IN) {
        nfq_handle_packet(h, buf, rv);
    }
    return TRUE;
}

struct dnshdr
{
    unsigned short id;
    unsigned char qr : 1;
    unsigned char opcode : 4;
    unsigned char aa : 1;
    unsigned char trc : 1;
    unsigned char rd : 1;
    unsigned char ra : 1;
    unsigned char z : 3;
    unsigned char rc : 4;
    unsigned short qcount;
    unsigned short anscount;
    unsigned short authcount;
    unsigned short addcount;
};

struct question
{
    unsigned short qtype;
    unsigned short qclass;
};

#pragma pack(push, 1)

struct resdata
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rdlen;
};
#pragma pack(pop)

struct resource
{
    unsigned char * name;
    struct resdata * resource;
    unsigned char * rdata;
};

void domain_to_str(char * domain)
{
    unsigned int x = 0;
    int i = 0;
    for (; i < strlen(domain); i++) {
        x = domain[i];
        for (int j = 0; x < strlen(domain) && j < x && x < 255; j++) {
            domain[i] = domain[i + 1];
            i = i + 1;
        }
        domain[i] = '.';
    }
    domain[i == 0 ? 0 : i - 1] = '\0';
}

unsigned char * get_domain(unsigned char * reply, unsigned char * buf, int * index, uint16_t len, int data)
{
    unsigned char * domain = calloc(256, sizeof (unsigned char *));
    if (domain) {
        domain[0] = '\0';
        unsigned int x = 0;
        unsigned int offset = 0;
        *index = 1;
        while (*reply != 0 && x < 255 && (data + *index <= len)) {
            if (*reply >= 192) {
                reply = buf + ((*reply)*256 + *(reply + 1) - 49152) - 1;
                offset = 1;
            } else {
                domain[x++] = *reply;
            }
            reply = reply + 1;
            if (!offset) {
                *index = *index + 1;
            }
        }
        domain[x] = '\0';
        if (offset) {
            *index = *index + 1;
        }
        domain_to_str(domain);
    }
    return domain;
}

const char * get_proc_filename(int p)
{
    switch (p) {
        case IPPROTO_TCP: return "/proc/net/tcp";
        case IPPROTO_UDP: return "/proc/net/udp";
        default: NULL;
    }
    return NULL;
}

const char * protocol_to_str(int x)
{
    switch (x) {
        case IPPROTO_TCP: return "tcp";
        case IPPROTO_UDP: return "udp";
        default: NULL;
    }
    return NULL;
}

void add(struct app * view, unsigned char * domain, long * ip)
{
    unsigned int x = view->cache->count >= DNS_CACHE_SIZE ? view->cache->count % DNS_CACHE_SIZE : view->cache->count;
    if (x < DNS_CACHE_SIZE) {
        if (view->cache->count < DNS_CACHE_SIZE) {
            view->cache->dns[x].name = (unsigned char *) calloc(strlen(domain) + 1, sizeof (char));
        } else {
            view->cache->dns[x].name = (unsigned char *) realloc(view->cache->dns[x].name, (strlen(domain) + 1) * sizeof (char));
        }
        snprintf(view->cache->dns[x].name, strlen(domain) + 1, "%s", domain);
        struct in_addr ia;
        ia.s_addr = (*ip);
        snprintf(view->cache->dns[x].ip, INET_ADDRSTRLEN, "%s", inet_ntoa(ia));
        view->cache->count++;
        if (view->cache->count < DNS_CACHE_SIZE) {
            view->cache->dns = (struct dns *) realloc(view->cache->dns, (view->cache->count + 1) * sizeof (struct dns));
        }
    }
}

void parse_dns_reply(unsigned int ipd, unsigned int tcpd, unsigned char * packet, struct udphdr * udph, struct app * view)
{
    struct dnshdr * dhdr = (struct dnshdr *) &packet[ipd + tcpd];
    int x = 0;
    unsigned char * dns = tcpd + sizeof (struct dnshdr) < ntohs(udph->len) ? (unsigned char *) &packet[ipd + tcpd + sizeof (struct dnshdr)] : 0;
    while (dns && dns[x] != 0 && (tcpd + sizeof (struct dnshdr)+x < ntohs(udph->len))) {
        x++;
    }
    x = x + 1 + tcpd + sizeof (struct dnshdr);
    unsigned char * reply = x + sizeof (struct question) < ntohs(udph->len) ? (unsigned char *) &packet[ipd + x + sizeof (struct question)] : 0;
    int index = 0;
    x = x + sizeof (struct question);
    struct resource rr;
    for (int i = 0; i < ntohs(dhdr->anscount) && reply; i++) {
        rr.name = get_domain(reply, packet + ipd + tcpd, &index, ntohs(udph->len), x);
        if (!rr.name) {
            break;
        }
        reply = reply + index;
        x = x + index;
        rr.resource = (struct resdata *) reply;
        reply = x + sizeof (struct resdata) < ntohs(udph->len) ? reply + sizeof (struct resdata) : NULL;
        x = x + sizeof (struct resdata);
        rr.rdata = x + ntohs(rr.resource->rdlen) <= ntohs(udph->len) ? calloc(ntohs(rr.resource->rdlen), sizeof (unsigned char *)) : NULL;
        x = x + ntohs(rr.resource->rdlen);
        if (reply && rr.rdata) {
            for (int j = 0; j < ntohs(rr.resource->rdlen); j++) {
                rr.rdata[j] = reply[j];
            }
            rr.rdata[ntohs(rr.resource->rdlen)] = '\0';
            reply = reply + ntohs(rr.resource->rdlen);
            if (ntohs(rr.resource->type) == 1) {
                add(view, rr.name, (long*) rr.rdata);
            }
            free(rr.rdata);
        }
        free(rr.name);
    }
}

void get_file_hash(char * file, char * hash)
{
    struct stat st;
    if (stat(file, &st) != 0) {
        return;
    }
    FILE * fd = fopen(file, "rb");
    if (fd == NULL) {
        return;
    }
    char * buf = calloc(st.st_size, sizeof (char));
    if (buf) {
        int len = fread(buf, st.st_size, 1, fd);
        gchar * sha = g_compute_checksum_for_data(G_CHECKSUM_SHA512, buf, st.st_size);
        if (sha) {
            snprintf(hash, 129, "%s", sha);
            g_free(sha);
        }
        free(buf);
    }
    fclose(fd);
}

char * get_pid_name(char * search)
{
    char * pid = NULL;
    struct dirent * dir;
    DIR * pd = opendir("/proc/");
    if (!pd) {
        return NULL;
    }
    while (((dir = readdir(pd)) != NULL)) {
        if (isdigit((unsigned char) *dir->d_name) && dir->d_type == 4) {
            char * fp = dir->d_name;
            struct dirent * dsp = NULL;
            char name[6 + strlen(fp) + 5];
            snprintf(name, sizeof (name), "/proc/%s/fd/", fp); 
            DIR * spd = opendir(name);
            if (spd) {
                while (((dsp = readdir(spd)) != NULL)) {
                    if (dsp->d_name[0] != ".") {
                        char pth[strlen(name) + strlen(dsp->d_name) + 1];
                        snprintf(pth, sizeof (pth), "%s%s", name, dsp->d_name);
                        char buf[4096];
                        ssize_t len;
                        if ((len = readlink(pth, buf, sizeof (buf) - 1)) != -1) {
                            buf[len] = '\0';
                            if (strcmp(buf, search) == 0) {
                                char pro[strlen(fp) + 11];
                                snprintf(pro, sizeof (pro), "/proc/%s/exe", fp);
                                ssize_t read;
                                char buf_[4096];
                                if ((read = readlink(pro, buf_, sizeof (buf_) - 1)) != -1) {
                                    buf_[read] = '\0';
                                    pid = calloc(read + 1, sizeof (char));
                                    if (pid) {
                                        snprintf(pid, read + 1, "%s", buf_);
                                    }
                                }
                                closedir(spd);
                                closedir(pd);
                                return pid;
                            }
                        }
                    }
                }
            }
            closedir(spd);
        }
    }
    closedir(pd);
    return pid;
}

void save(struct node * root)
{
    FILE * fd = fopen("rules", "w");
    if (fd == NULL) {
        return;
    }
    struct node * ptr = root;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        if (ptr->rule->authorize == ALLOW || ptr->rule->authorize == BLOCK || ptr->rule->authorize == DEFAULT) {
            fprintf(fd, "(");
            for (int i = 0; i < 9; i++) {
                char * data = get_property(ptr->rule, i, 1);
                char * attribute = enum_to_str(i);
                if (i != DELETE && i != SRC && data != NULL && attribute != NULL) {
                    fprintf(fd, " (%s \"%s\") ", attribute, data);
                }
            }
            fprintf(fd, ")");
            fprintf(fd, "\n");
        }
    }
    fclose(fd);
}

void load(struct app * view)
{
    FILE * fd = fopen("rules", "r");
    if (fd == NULL) {
        return;
    }
    char * lne = NULL;
    size_t len = 0;
    ssize_t read;
    struct rule * object = (struct rule *) calloc(1, sizeof (struct rule));
    while ((read = getline(&lne, &len, fd)) != -1) {
        for (int i = 0; i < 9 && object; i++) {
            char buf[strlen(lne) + 1];
            const char * attribute = enum_to_str(i);
            if (attribute) {
                char str[strlen(attribute) + 5];
                snprintf(str, strlen(attribute) + 5, "(%s ", attribute);
                char * index = strstr(lne, str);
                char regex[strlen(attribute) + 10];
                snprintf(regex, strlen(attribute) + 10, "(%s %c%c%c%c%c%c)", attribute, '"', '%', '[', '^', '\"', ']');
                if (index) {
                    int x = sscanf(index, regex, buf);
                    if (x == 1) {
                        set_property(object, i, buf);
                    }
                }
            }
        }
        struct node * ptr = insert(object, view->root);
        if (ptr) {
            print_rule(ptr, false, view->grid);
            object = (struct rule *) calloc(1, sizeof (struct rule));
            if (!object) {
                break;
            }
        }
    }
    if (lne) {
        free(lne);
    }
    fclose(fd);
}

struct rule * find_rule(struct app * app, char * pro, int x, char * ip, u_int8_t hook, unsigned short sp, unsigned short port, char * hash, int * sha)
{
    struct node * ptr = app->root;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        if (ptr->rule->process && ((strcmp(pro, ptr->rule->process) == 0) || strcmp("*", ptr->rule->process) == 0)) {
            if (((ptr->rule->domain && ((x != -1 && (strcmp(app->cache->dns[x].name, ptr->rule->domain) == 0)) || (strcmp("*", ptr->rule->domain)) == 0))
                    || (ptr->rule->ip[0] != '\0' && (strcmp(ptr->rule->ip, ip) == 0 || (strcmp("*", ptr->rule->ip)) == 0)))
                    && ptr->rule->hook == hook && ptr->rule->authorize != DEFAULT) {
                char p[5 + 1];
                snprintf(p, 5 + 1, "%u", hook == INCOMING ? sp : port);
                if (strcmp("*", ptr->rule->port) == 0 || strcmp(p, ptr->rule->port) == 0) {
                    set_src(ptr->rule, hook == INCOMING ? port : sp);
                    set_port(ptr->rule, p);
                    if (strcmp(hash, ptr->rule->hash) == 0 || strcmp("*", ptr->rule->process) == 0) {
                        *sha = 0;
                    } else {
                        *sha = 1;
                    }
                    return ptr->rule;
                }
            }
        }
    }
    return NULL;
}

int find_domain(struct dnscache * cache, char * ip)
{
    for (int x = 0; x < (cache->count > DNS_CACHE_SIZE ? DNS_CACHE_SIZE : cache->count); x++) {
        if (strcmp(ip, cache->dns[x].ip) == 0) {
            return x;
        }
    }
    return -1;
}

int show_message_dialog(char * pid, char * domain, int hook, char * ip, const char * protocol, int sp, int port, int * sha)
{
    int response = BLOCKSESN;
    char str[512];
    snprintf(str, 510, "process %s is trying to open %s %s connection to %s %s %u %s", pid ? pid : "*", hook == INCOMING ? "incoming" : "outgoing", protocol ? protocol : "*", domain, ip, hook == 1 ? sp : port, *sha ? "\n warning application binary has been modified" : "");
    GtkBuilder * builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, "dialog.ui", NULL);
    GObject * dialog = gtk_builder_get_object(builder, "dialog");
    if (dialog) {
        int select = 1;
        GtkWidget * toggle = GTK_WIDGET(gtk_builder_get_object(builder, "togglebutton"));
        if (toggle) {
            g_signal_connect(toggle, "toggled", G_CALLBACK(toogle_click), &select);
        }
        GtkWidget * label = GTK_WIDGET(gtk_builder_get_object(builder, "message"));
        if (label) {
            gtk_label_set_text(GTK_LABEL(label), str);
        }
        response = gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(GTK_WIDGET(dialog));
        if (response == -4) {
            response = BLOCKSESN;
        }
        if (!select) {
            response = response == ALLOW ? SESSION : BLOCKSESN;
        }
    }
    g_object_unref(builder);
    return response;
}

void print_packet_data(unsigned short sp, unsigned char * pdata, const char * protocol, struct node * root, GtkWidget * grid)
{
    struct node * ptr = root;
    while (ptr->next != NULL) {
        ptr = ptr->next;
        if (ptr->rule->src == sp && strcmp(ptr->rule->protocol, protocol) == 0) {
            GtkWidget * widget = ptr->rule->data ? gtk_grid_get_child_at(GTK_GRID(grid), 1, ptr->rule->row + 1) : gtk_label_new(NULL);
            if (widget) {
                gtk_label_set_text(GTK_LABEL(widget), pdata);
                if (!ptr->rule->data) {
                    gtk_widget_set_name(GTK_WIDGET(widget), get_class_name(DATA));
                    set_label_property(10, widget);
                    gtk_grid_insert_row(GTK_GRID(grid), ptr->rule->row + 1);
                    gtk_grid_attach(GTK_GRID(grid), widget, 1, ptr->rule->row + 1, 5, 1);
                    gtk_widget_show(widget);
                    ptr->rule->data = true;
                    update_row(root, ptr->rule->row, 1);
                }
            }
            break;
        }
    }
}

int get_inode(char * search, const char * file)
{
    FILE * fd = fopen(file, "r");
    if (fd == NULL) {
        return 0;
    }
    __u32 inode = 0;
    char * lne = NULL;
    size_t len = 0;
    ssize_t read;
    int i = 0;
    while ((read = getline(&lne, &len, fd)) != -1) {
        if (i) {
            char buf[14];
            int ret = sscanf(lne, "%*d: %13[0-9A-Fa-f:0-9A-Fa-f] %*8x:%*hx %*x %*x:%*x %*x:%*x %*x %*lu %*d %lu", buf, &inode);
            if (ret == 2) {
                if (strcasecmp(buf, search) == 0) {
                    break;
                }
            }
        }
        i++;
        inode = 0;
    }
    if (lne) {
        free(lne);
    }
    fclose(fd);
    return inode;
}

char * get_application(u_int8_t hook, struct iphdr * iph, unsigned short port, unsigned short sp)
{
    char addr[14];
    snprintf(addr, 14, "%08x:%x", hook == INCOMING ? iph->daddr : iph->saddr, hook == INCOMING ? port : sp);
    const char * file = get_proc_filename(iph->protocol);
    int inode = get_inode(addr, file);
    if (inode) {
        int len = snprintf(NULL, 0, "%u", inode);
        char sock[len + 10];
        snprintf(sock, len + 10, "socket:[%u]", inode);
        return get_pid_name(sock);
    }
    return NULL;
}

bool get_packet(unsigned short * port, unsigned int *ipd, unsigned short * sp, unsigned int * prctl, unsigned int * ipdlen, struct iphdr * iph, unsigned char * packet)
{
    bool connection = false;
    switch (iph->protocol) {
        case IPPROTO_TCP:
        {
            struct tcphdr * tcph = (struct tcphdr *) (packet + (iph->ihl * 4));
            *port = ntohs(tcph->dest);
            *sp = ntohs(tcph->source);
            *prctl = tcph->doff * 4;
            if ((tcph->syn == 1) && (tcph->ack == 0)) {
                connection = true;
            }
            *ipdlen = (ntohs(iph->tot_len)) - (*ipd + *prctl);
            break;
        }
        case IPPROTO_UDP:
        {
            struct udphdr * udph = (struct udphdr *) (packet + (iph->ihl * 4));
            *port = ntohs(udph->dest);
            *sp = ntohs(udph->source);
            *prctl = sizeof (struct udphdr);
            *ipdlen = ntohs(udph->len) - *prctl;
            connection = true;
            break;
        }
    }
    return connection;
}

int get_response(struct app * view, char * program, int x, char * ip, u_int8_t hook, unsigned short port, unsigned short sp, char * hash, const char * protocol)
{
    int response = -4;
    int sha = 0;
    struct rule * object = find_rule(view, program, x, ip, hook, sp, port, &hash[0], &sha);
    if (!object || sha) {
        response = show_message_dialog(program, x != -1 ? view->cache->dns[x].name : "\0", hook, ip, protocol, sp, port, &sha);
        if (sha) {
            set_hash(object, &hash[0]);
            set_authorization(object, response);
            set_row_class(view->grid, object);
        } else {
            struct node * ptr = add_object(hook, &hash[0], program, x == -1 ? NULL : view->cache->dns[x].name, response, hook == 1 ? sp : port, hook == 1 ? port : sp, !protocol ? "*" : protocol, ip, view); 
            if (ptr) {
                display(ptr, ptr->rule, view);
            }
        }
    } else {
        response = object->authorize;
    }
    return response;
}

int parse_packet(u_int8_t hook, unsigned char * packet, struct app * view)
{
    int response=-4;
    struct iphdr * iph = (struct iphdr *) packet;
    unsigned short port = 0;
    unsigned short sp = 0;
    const char * protocol = protocol_to_str(iph->protocol);
    unsigned int ipd = iph->ihl * 4;
    unsigned int prctl;
    unsigned int ipdlen;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, hook == INCOMING ? &iph->saddr : &iph->daddr, ip, INET_ADDRSTRLEN);

    bool connection = get_packet(&port, &ipd, &sp, &prctl, &ipdlen, iph, packet);

    if (iph->protocol == IPPROTO_UDP) {
        if (sp == 53 && iph->version == 4) {
            parse_dns_reply(ipd, prctl, packet, (struct udphdr *) (packet + (iph->ihl * 4)), view);
        }
    }

    if (connection) {
        char * program = get_application(hook, iph, port, sp);
        if (program) {
            char hash[129];
            get_file_hash(program, hash);
            int x = find_domain(view->cache, ip); 
            response = get_response(view,program, x, &ip[0], hook, port, sp, hash, protocol);
            free(program);
        }
    } else {
        response = SESSION;
    }

    if ((iph->protocol == IPPROTO_TCP && ((ntohs(iph->tot_len)) - (ipd + prctl)) > 0) || (iph->protocol == IPPROTO_UDP)) {
        int x = 0;
        unsigned char content[ipdlen];
        while (*(packet + (ipd + prctl) + x) != 0 && x < ipdlen) {
            content[x] = *(packet + (ipd + prctl) + x);
            x++;
        }
        content[x] = '\0';
        print_packet_data(hook == 1 ? port : sp, content, protocol, view->root, view->grid);
    }
    return response;
}

static int callback(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg, struct nfq_data * nfa, void * data)
{
    struct nfqnl_msg_packet_hdr * ph = nfq_get_msg_packet_hdr(nfa);
    u_int8_t hook = ph->hook;
    u_int32_t id = ntohl(ph->packet_id);
    unsigned char * packet;
    int _data = nfq_get_payload(nfa, &packet);
    struct app * view = (struct app *) data;
    int response = -4;

    if (_data > 0) {
        response = parse_packet(hook, packet, view);
    }

    if (response == ALLOW || response == SESSION) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        return nfq_set_verdict2(qh, id, NF_DROP, 0xff, 0, NULL);
    }
}

void free_node(struct node * root)
{
    struct node * ptr = root->next;
    while (ptr != NULL) {
        struct node * object = ptr->next;
        destructor(ptr->rule);
        free(ptr);
        ptr = object;
    }
    free(root);
}

int main(int argc, char **argv)
{
    struct nfnl_handle * nh;
    struct node * root = calloc(1, sizeof (struct node));
    if (!root) {
        return -1;
    }
    root->root = root;

    struct dns * dns = calloc(1, sizeof (struct dns));
    if (!dns) {
        return -1;
    }
    struct dnscache dnsche = {.dns = dns, .count = 0};

    gtk_init(&argc, &argv);

    GtkBuilder * builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, "main.ui", NULL);

    GtkWidget * close = GTK_WIDGET(gtk_builder_get_object(builder, "close"));
    g_signal_connect(close, "clicked", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget * settings = GTK_WIDGET(gtk_builder_get_object(builder, "setting"));
    GtkWidget * menu = GTK_WIDGET(gtk_builder_get_object(builder, "menu"));
    gtk_menu_button_set_popover(GTK_MENU_BUTTON(settings), menu);

    GtkWidget * grid = GTK_WIDGET(gtk_builder_get_object(builder, "grid"));

    struct app view = {.root = root, .grid = grid, .cache = &dnsche};

    GtkWidget * add = GTK_WIDGET(gtk_builder_get_object(builder, "add"));
    g_signal_connect(add, "clicked", G_CALLBACK(add_click), &view);
    GtkWidget * search = GTK_WIDGET(gtk_builder_get_object(builder, "search"));
    g_signal_connect(search, "changed", G_CALLBACK(search_click), &view);

    g_object_unref(builder);

    GtkCssProvider * provider = gtk_css_provider_new();
    GdkDisplay * display = gdk_display_get_default();
    GdkScreen * screen = gdk_display_get_default_screen(display);
    gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);
    gtk_css_provider_load_from_path(provider, "style.css", NULL);
    g_object_unref(provider);

    struct nfq_handle * nfq = nfq_open();
    if (!nfq) {
        printf("\n error setting nfq_open()\n");
        return -1;
    }

    if (nfq_unbind_pf(nfq, AF_INET) < 0) {
        printf("\n error setting nfq_unbind_pf()");
        return -1;
    }

    if (nfq_bind_pf(nfq, AF_INET) < 0) {
        return -1;
    }

    struct nfq_q_handle * qh = nfq_create_queue(nfq, 0, &callback, &view);
    if (!qh) {
        return -1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("\n error setting copy_packet mode");
        return -1;
    }

    int fd = nfq_fd(nfq);
    GIOChannel * chn = g_io_channel_unix_new(fd);
    g_io_add_watch(chn, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL, (GIOFunc) cabk, nfq);

    load(&view);
    gtk_main();
    save(root);
    printf("\n unbinding from queue 0");
    nfq_destroy_queue(qh);

    printf("\n closing handle\n");
    nfq_close(nfq);

    free_node(root);
    return 0;
}

