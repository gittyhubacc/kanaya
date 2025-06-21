#include <mf/array.h>
#include <mf/list.h>
#include <mf/memory.h>
#include <mf/string.h>
#include <stdio.h>

typedef enum token_type {
        TOK_BROKEN,
        TOK_GROUP_BEGIN, // (
        TOK_GROUP_END,   // )
        TOK_STAR,        // *
        TOK_CONCAT,      // .
        TOK_UNION,       // +
        TOK_SYMBOL,      // a
        TOK_EPSILON,     // ~
        TOK_START,
        TOK_OVER,

        NT_PRIMARY = 'P',
        NT_SECONDARY = 'S',
        NT_TERTIARY = 'T',
        NT_QUATERNARY = 'A',
} token_type;

typedef struct token {
        token_type type;
        char data;
} token;
#define T(t) ((token){.type = t, .data = 0})

typedef struct tstring {
        int len;
        token *addr;
} tstring;
#define TS(ta) ((tstring){.len = sizeof(ta) / sizeof(*ta), .addr = ta})

typedef struct trule {
        token head;
        tstring body;
} trule;

typedef struct grammar {
        int rule_cnt;
        trule *rules;
        trule *start;
} grammar;

typedef struct pid {
        int i;
        token head;
        tstring body;
        tstring look_ahead;
} pid;

typedef struct ptree {
        token label;
        int child_cnt;
        struct ptree *parent;
        struct ptree *children;
} ptree;

#define PARSER_SZ (0x10)
typedef struct parser {
        int s;
        int n;
        list *sym[PARSER_SZ];
        ptree *nodes[PARSER_SZ];
} parser;

#define PART_SZ (kibibyte / 2)
static string read_source(arena *a, int argc, char **argv)
{
        char c = 0;
        int parts_read = 0;
        int bytes_read = 0;
        char *buffer = make(a, char, 512);

        // eventually, optionally read from other places
        while ((c = fgetc(stdin)) != EOF) {
                buffer[(parts_read * PART_SZ) + bytes_read++] = c;
                if (bytes_read >= PART_SZ) {
                        steal(a, char, PART_SZ);
                        bytes_read = 0;
                        parts_read++;
                }
        }

        return (string){buffer, parts_read * PART_SZ + bytes_read};
}
#define IS_SYMBOL(c) ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
static token emit_token(string source, int *i)
{
        token tok;
        tok.type = TOK_BROKEN;
        tok.data = source.addr[(*i)++];
        switch (tok.data) {
        case '~':
                tok.type = TOK_EPSILON;
                return tok;
        case '*':
                tok.type = TOK_STAR;
                return tok;
        case '.':
                tok.type = TOK_CONCAT;
                return tok;
        case '+':
                tok.type = TOK_UNION;
                return tok;
        case '(':
                tok.type = TOK_GROUP_BEGIN;
                return tok;
        case ')':
                tok.type = TOK_GROUP_END;
                return tok;
        }
        if (IS_SYMBOL(tok.data)) {
                tok.type = TOK_SYMBOL;
                return tok;
        }
        printf("found broken: %c\n", tok.data);
        // broken token
        return tok;
}

#define IS_WHITESPACE(c) (c == ' ' || c == '\n' || c == '\t')
static tstring lex(arena *a, string source)
{
        int i = 0;
        tstring res;

        res.len = 0;
        res.addr = make(a, token, 0);

        while (i < source.len) {
                if (IS_WHITESPACE(source.addr[i])) {
                        while (IS_WHITESPACE(source.addr[++i])) {
                        }
                        continue;
                }
                steal(a, token, 1);
                res.addr[res.len++] = emit_token(source, &i);
        }

        steal(a, token, 1);
        res.addr[res.len++] = (token){.type = TOK_OVER, .data = '$'};

        return res;
}

static void debug_tokens(tstring tokens)
{
        int type;
        char c;
        for (int i = 0; i < tokens.len; i++) {
                type = tokens.addr[i].type;
                c = tokens.addr[i].data;
                printf("%c %i\n", c >= ' ' ? c : ' ', c);
        }
}

static int tstreq(tstring left, tstring right)
{
        if (left.len != right.len) {
                return 0;
        }
        if (left.addr == right.addr) {
                return 1;
        }
        for (int i = 0; i < left.len; i++) {
                if (left.addr[i].type != right.addr[i].type) {
                        return 0;
                }
        }
        return 1;
}

static char hitmap[0xFF];
static tstring strunion(arena *a, tstring left, tstring right)
{
        mfmemset(hitmap, 0, 0xFF);

        tstring res;
        res.len = 0;
        res.addr = make(a, token, left.len + right.len);
        for (int i = 0; i < left.len; i++) {
                if (!hitmap[left.addr[i].type]) {
                        res.addr[res.len++] = left.addr[i];
                        hitmap[left.addr[i].type] = 1;
                }
        }
        for (int i = 0; i < right.len; i++) {
                if (!hitmap[right.addr[i].type]) {
                        res.addr[res.len++] = right.addr[i];
                }
        }
        return res;
}

static int tstrmember(tstring s, token t)
{
        for (int i = 0; i < s.len; i++) {
                if (s.addr[i].type == t.type) {
                        return 1;
                }
        }
        return 0;
}

static int append_if_absent(arena *a, list **head, pid *p)
{
        pid *data;
        list *cursor = *head;
        while (cursor) {
                data = cursor->data;
                if (data->head.type == p->head.type && data->i == p->i &&
                    tstreq(data->body, p->body)) {
                        if (!tstreq(data->look_ahead, p->look_ahead)) {
                                data->look_ahead = strunion(a, data->look_ahead,
                                                            p->look_ahead);
                        }
                        return 0;
                }
                cursor = cursor->next;
        }

        list *node = make(a, list, 1);
        node->data = make(a, pid, 1);
        *(pid *)node->data = *p;
        list_append(head, node);

        return 1;
}

static int append_pid_closure(arena *a, list **head, grammar *g, pid *p)
{
        pid *new;
        int updated = 0;
        for (int i = 0; i < g->rule_cnt; i++) {
                if (g->rules[i].head.type == p->body.addr[p->i].type) {
                        new = make(a, pid, 1);
                        new->i = 0;
                        new->head = g->rules[i].head;
                        new->body = g->rules[i].body;
                        if (p->i + 1 >= p->body.len) {
                                new->look_ahead = p->look_ahead;
                        } else {
                                new->look_ahead.len = 1;
                                new->look_ahead.addr = make(a, token, 1);
                                new->look_ahead.addr[0] =
                                    p->body.addr[p->i + 1];
                        }
                        updated |= append_if_absent(a, head, new);
                }
        }
        return updated;
}

static list *close_pid_list(arena *a, grammar *g, list *pids)
{
        pid *p;
        pid *new;
        list *cursor;
        int updated = 1;
        list *res = NULL;

        // copy what's present
        cursor = pids;
        while (cursor) {
                p = cursor->data;
                append_if_absent(a, &res, p);
                cursor = cursor->next;
        }

        // then close
        while (updated) {
                updated = 0;
                cursor = res;
                while (cursor) {
                        p = cursor->data;
                        updated |= append_pid_closure(a, &res, g, p);
                        cursor = cursor->next;
                }
        }
        return res;
}

static const tstring tepsilon = {.len = 0, .addr = 0};
static list *create_start_state(arena *a, grammar *g)
{
        pid start_pid = {
            .i = 0,
            .head = g->start->head,
            .body = g->start->body,
            .look_ahead = tepsilon,
        };
        list basis_state = {
            .data = &start_pid,
            .next = NULL,
            .last = NULL,
        };
        return close_pid_list(a, g, &basis_state);
}

static int is_terminal(grammar *g, token t)
{
        for (int i = 0; i < g->rule_cnt; i++) {
                if (g->rules[i].head.type == t.type) {
                        return 0;
                }
        }
        return 1;
}

static void shift(arena *a, parser *p, grammar *g, token t)
{
        pid *new;
        pid *data;
        list *cursor;
        list *new_state = NULL;

        cursor = p->sym[p->s - 1];
        while (cursor) {
                data = cursor->data;
                if (data->body.addr[data->i].type != t.type) {
                        cursor = cursor->next;
                        continue;
                }
                new = make(a, pid, 1);
                new->i = data->i + 1;
                new->head = data->head;
                new->body = data->body;
                if (data->i < new->body.len) {
                        new->body.addr[data->i].data = t.data;
                }
                new->look_ahead = data->look_ahead;
                append_if_absent(a, &new_state, new);
                cursor = cursor->next;
        }

        p->sym[p->s++] = close_pid_list(a, g, new_state);
}

static pid *reduce(arena *a, parser *p, grammar *g, token next_t)
{
        // printf("next char: '%c'\n", next_ch);
        pid *data;
        list *state;
        tstring *body;
        list *cursor = p->sym[p->s - 1];

        while (cursor) {
                data = cursor->data;
                body = &data->body;
                if (data->i < body->len ||
                    !tstrmember(data->look_ahead, next_t)) {
                        cursor = cursor->next;
                        continue;
                }

                p->s -= data->body.len;
                state = p->sym[p->s - 1];

                // printf("reduction: %.*s -> %c\n", data->body.len,
                // data->body.addr, data->head);
                shift(a, p, g, data->head);

                return data;
        }
        return 0;
}

static void print_state(list *state)
{
        pid *data;
        list *cursor = state;
        printf("-----\n");
        while (cursor) {
                data = cursor->data;
                printf("%c -> [%i] ", data->head.type, data->i);
                for (int i = 0; i < data->body.len; i++) {
                        printf("%c", data->body.addr[i].type);
                }
                printf(" [");
                for (int i = 0; i < data->look_ahead.len; i++) {
                        printf("%c", data->look_ahead.addr[i].type);
                }
                printf("]\n");
                cursor = cursor->next;
        }
}

static token primary_sym[] = {T(TOK_SYMBOL)};
static token primary_group[] = {
    T(TOK_GROUP_BEGIN),
    T(NT_QUATERNARY),
    T(TOK_GROUP_END),
};
static token secondary_unit[] = {T(NT_PRIMARY)};
static token secondary_star[] = {
    T(NT_SECONDARY),
    T(TOK_STAR),
};
static token tertiary_unit[] = {T(NT_SECONDARY)};
static token tertiary_dot[] = {
    T(NT_TERTIARY),
    T(TOK_CONCAT),
    T(NT_SECONDARY),
};
static token quaternary_unit[] = {T(NT_TERTIARY)};
static token quaternary_union[] = {
    T(NT_QUATERNARY),
    T(TOK_UNION),
    T(NT_TERTIARY),
};
static token augmented_start[] = {
    T(NT_QUATERNARY),
    T(TOK_OVER),
};
static trule rules[] = {
    {
        .head = T(NT_PRIMARY),
        .body = TS(primary_sym),
    },
    {
        .head = T(NT_PRIMARY),
        .body = TS(primary_group),
    },
    {
        .head = T(NT_SECONDARY),
        .body = TS(secondary_unit),
    },
    {
        .head = T(NT_SECONDARY),
        .body = TS(secondary_star),
    },

    {
        .head = T(NT_TERTIARY),
        .body = TS(tertiary_unit),
    },
    {
        .head = T(NT_TERTIARY),
        .body = TS(tertiary_dot),
    },

    {
        .head = T(NT_QUATERNARY),
        .body = TS(quaternary_unit),
    },
    {
        .head = T(NT_QUATERNARY),
        .body = TS(quaternary_union),
    },

    {
        .head = T(TOK_START),
        .body = TS(augmented_start),
    },
};
static const int rule_cnt = sizeof(rules) / sizeof(*rules);
static grammar kanaya_grammar = {
    .rules = rules,
    .rule_cnt = rule_cnt,
    .start = rules + (rule_cnt - 1),
};
static ptree *parse(arena *a, grammar *g, tstring tokens)
{
        parser prsr;
        prsr.n = 0;
        prsr.s = 0;
        prsr.sym[prsr.s++] = create_start_state(a, g);

        pid *p;
        ptree *n;
        int i = 0;
        list *state = prsr.sym[prsr.s - 1];
        while (state) {
                state = prsr.sym[prsr.s - 1];
                if (state == NULL) {
                        printf("dead\n");
                        return NULL;
                }

                // print_state(state);
                if (i >= tokens.len) {
                        printf("accepted\n");
                        return prsr.nodes[prsr.n - 1];
                }

                while ((p = reduce(a, &prsr, g, tokens.addr[i]))) {
                        state = prsr.sym[prsr.s - 1];
                        // print_state(state);
                        n = make(a, ptree, 1);
                        n->parent = NULL;
                        n->label = p->head;
                        n->child_cnt = p->body.len;
                        n->children = make(a, ptree, n->child_cnt);
                        for (int i = 0; i < n->child_cnt; i++) {
                                if (is_terminal(g, p->body.addr[i])) {
                                        n->children[i].parent = n;
                                        n->children[i].label = p->body.addr[i];
                                        n->children[i].child_cnt = 0;
                                        n->children[i].children = 0;
                                } else {
                                        n->children[i] = *prsr.nodes[--prsr.n];
                                }
                        }
                        prsr.nodes[prsr.n++] = n;
                }
                shift(a, &prsr, g, tokens.addr[i++]);
        }
        printf("how did we get here?\n");
        return NULL;
}

static void debug_ptree(ptree *pt, int generation)
{
        // char c = pt->label.type;
        char c = pt->label.data >= ' ' ? pt->label.data : ' ';
        printf("%i: %c (%i)\n", generation, c, pt->label.data);
        for (int i = 0; i < pt->child_cnt; i++) {
                debug_ptree(pt->children + i, generation + 1);
        }
}

int main(int argc, char **argv)
{
        char mem[256 * kibibyte];
        arena root = make_arena(mem);
        string source = read_source(&root, argc, argv);
        tstring tokens = lex(&root, source);
        debug_tokens(tokens);
        ptree *tree = parse(&root, &kanaya_grammar, tokens);
        debug_ptree(tree, 0);
        printf("used: %lu, %lukib\n", bytes_used(root),
               bytes_used(root) / kibibyte);
        return 0;
}
