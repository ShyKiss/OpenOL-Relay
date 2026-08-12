/*=============================================================================
    cli.c - minimal cross-platform TUI: scrolling log + command input line
=============================================================================*/
#include "cli.h"
#include "db.h"
#include <stdarg.h>

// ---------------------------------------------------------------------------
// Platform-specific terminal control
// ---------------------------------------------------------------------------

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <conio.h>
#  include <io.h>
   static HANDLE g_hout = INVALID_HANDLE_VALUE;
   static HANDLE g_hin  = INVALID_HANDLE_VALUE;
   static DWORD  g_orig_out_mode = 0;
   static DWORD  g_orig_in_mode  = 0;
#else
#  include <termios.h>
#  include <sys/ioctl.h>
#  include <unistd.h>
#  include <fcntl.h>
   static struct termios g_orig_termios;
#endif

// ---------------------------------------------------------------------------
// Log ring buffer
// ---------------------------------------------------------------------------

#define LOG_LINES_MAX   4000
#define LOG_LINE_WIDTH  512

static char  g_log[LOG_LINES_MAX][LOG_LINE_WIDTH];
static int   g_log_head = 0;   // index of oldest line
static int   g_log_count = 0;  // number of lines stored
static int   g_log_scroll = 0; // lines scrolled up from bottom (0 = bottom)

// ---------------------------------------------------------------------------
// Input line
// ---------------------------------------------------------------------------

#define INPUT_MAX 4095

static char g_input[INPUT_MAX + 1];
static int  g_input_len = 0;
static int  g_input_cur = 0;   // cursor position (0..g_input_len)

char cli_last_cmd[4096];
gui_log_hook_t g_gui_log_hook = NULL;

// ---------------------------------------------------------------------------
// Terminal size
// ---------------------------------------------------------------------------

static int g_cols = 80;
static int g_rows = 24;
static int g_is_tty = 0;

static void update_term_size(void) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hout, &csbi)) {
        g_cols = csbi.srWindow.Right  - csbi.srWindow.Left + 1;
        g_rows = csbi.srWindow.Bottom - csbi.srWindow.Top  + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        g_cols = ws.ws_col;
        g_rows = ws.ws_row;
    }
#endif
    if (g_cols < 20) g_cols = 20;
    if (g_rows < 4)  g_rows = 4;
}

// ---------------------------------------------------------------------------
// Raw terminal mode
// ---------------------------------------------------------------------------

static void enter_raw(void) {
#ifdef _WIN32
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hin  = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(g_hout, &g_orig_out_mode);
    GetConsoleMode(g_hin,  &g_orig_in_mode);
    SetConsoleMode(g_hout, g_orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleMode(g_hin,  ENABLE_VIRTUAL_TERMINAL_INPUT);
#else
    struct termios raw;
    tcgetattr(STDIN_FILENO, &g_orig_termios);
    raw = g_orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON); // keep ISIG so Ctrl+C sends SIGINT
    raw.c_iflag &= ~(IXON | ICRNL);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    // O_NONBLOCK so read() returns immediately when no data available
    int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, fl | O_NONBLOCK);
#endif
}

static void leave_raw(void) {
#ifdef _WIN32
    if (g_hout != INVALID_HANDLE_VALUE) {
        SetConsoleMode(g_hout, g_orig_out_mode);
        SetConsoleMode(g_hin,  g_orig_in_mode);
    }
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
#endif
}

// ---------------------------------------------------------------------------
// ANSI helpers (work on both POSIX and modern Windows)
// ---------------------------------------------------------------------------

#define ANSI_CLEAR_SCREEN  "\x1b[2J"
#define ANSI_MOVE(r,c)     "\x1b[" #r ";" #c "H"
#define ANSI_MOVE_FMT      "\x1b[%d;%dH"
#define ANSI_ERASE_LINE    "\x1b[2K"
#define ANSI_RESET         "\x1b[0m"
#define ANSI_BOLD          "\x1b[1m"
#define ANSI_DIM           "\x1b[2m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"

static void term_write(const char *s) {
    fputs(s, stdout);
}

static void term_writef(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

// ---------------------------------------------------------------------------
// Log append
// ---------------------------------------------------------------------------

static void log_append(const char *line) {
    // Word-wrap into g_log ring buffer
    int w = g_cols > LOG_LINE_WIDTH - 1 ? LOG_LINE_WIDTH - 1 : g_cols;
    int len = (int)strlen(line);
    int pos = 0;
    do {
        int chunk = len - pos;
        if (chunk > w) chunk = w;
        int idx = (g_log_head + g_log_count) % LOG_LINES_MAX;
        memset(g_log[idx], ' ', w);
        memcpy(g_log[idx], line + pos, chunk);
        g_log[idx][w] = '\0';
        if (g_log_count < LOG_LINES_MAX)
            g_log_count++;
        else
            g_log_head = (g_log_head + 1) % LOG_LINES_MAX;
        pos += chunk;
    } while (pos < len);
}

// ---------------------------------------------------------------------------
// Redraw
// ---------------------------------------------------------------------------

void cli_redraw(void) {
    if (!g_is_tty) return;

    update_term_size();
    int log_rows = g_rows - 2; // top area: log lines; -2 for separator + input

    // Move to top-left without clearing (avoids flicker)
    term_write("\x1b[H");

    // Compute which log lines to display
    // Bottom of view = g_log_count - 1 - g_log_scroll
    int bottom = g_log_count - 1 - g_log_scroll;
    int top    = bottom - log_rows + 1;

    for (int row = 0; row < log_rows; row++) {
        int li = top + row;
        term_writef(ANSI_MOVE_FMT ANSI_ERASE_LINE, row + 1, 1);
        if (li >= 0 && li < g_log_count) {
            int idx = (g_log_head + li) % LOG_LINES_MAX;
            // Truncate to terminal width
            char buf[LOG_LINE_WIDTH];
            strncpy(buf, g_log[idx], g_cols);
            buf[g_cols] = '\0';
            fputs(buf, stdout);
        }
    }

    // Separator line
    term_writef(ANSI_MOVE_FMT ANSI_COLOR_CYAN, log_rows + 1, 1);
    for (int i = 0; i < g_cols; i++) fputc('-', stdout);
    term_write(ANSI_RESET);

    // Input line
    term_writef(ANSI_MOVE_FMT ANSI_ERASE_LINE ANSI_BOLD "> " ANSI_RESET, g_rows, 1);
    // Print input buf, truncated to fit after "> "
    int avail = g_cols - 2;
    int start = 0;
    if (g_input_cur >= avail) start = g_input_cur - avail + 1;
    for (int i = start; i < g_input_len && i - start < avail; i++)
        fputc(g_input[i], stdout);

    // Move cursor to correct column
    int cur_col = 2 + (g_input_cur - start) + 1; // 1-indexed
    if (cur_col > g_cols) cur_col = g_cols;
    term_writef(ANSI_MOVE_FMT, g_rows, cur_col);

    fflush(stdout);
}

// ---------------------------------------------------------------------------
// cli_log — write timestamped log line (replaces server_log)
// ---------------------------------------------------------------------------

void cli_log(const char *fmt, ...) {
    char buf[LOG_LINE_WIDTH];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);

    // GUI hook takes priority
    if (g_gui_log_hook) {
        g_gui_log_hook(buf);
        return;
    }

    if (!g_is_tty) {
        fprintf(stdout, "%s\n", buf);
        fflush(stdout);
        return;
    }

    log_append(buf);
    if (g_log_scroll == 0)
        cli_redraw();
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

// Returns 1 if complete line ready in cli_last_cmd
static int process_key(int ch) {
    if (ch == '\n' || ch == '\r') {
        g_input[g_input_len] = '\0';
        memcpy(cli_last_cmd, g_input, g_input_len + 1);
        g_input_len = 0;
        g_input_cur = 0;
        return 1;
    }
    if (ch == 127 || ch == '\b') { // Backspace
        if (g_input_cur > 0) {
            memmove(g_input + g_input_cur - 1,
                    g_input + g_input_cur,
                    g_input_len - g_input_cur);
            g_input_cur--;
            g_input_len--;
        }
        return 0;
    }
    if (ch >= 0x20 && ch < 0x7F && g_input_len < INPUT_MAX) {
        memmove(g_input + g_input_cur + 1,
                g_input + g_input_cur,
                g_input_len - g_input_cur);
        g_input[g_input_cur] = (char)ch;
        g_input_cur++;
        g_input_len++;
    }
    return 0;
}

#ifndef _WIN32
// Parse ANSI escape sequences for arrow keys / Home / End / Del
static int process_escape(void) {
    // Peek for CSI sequence: ESC [ ...
    char    buf[8] = {0};
    int     n = 0;
    unsigned char c;
    // stdin is O_NONBLOCK here (set by caller in cli_poll)
    while (n < 7) {
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        buf[n++] = (char)c;
        if (c >= 0x40 && c <= 0x7E) break; // final byte of CSI sequence
    }
    if (n == 0) return 0; // bare ESC — ignore
    if (buf[0] == '[') {
        char final = buf[n - 1];
        if (final == 'A') { // Up — scroll log up
            int log_rows = g_rows - 2;
            if (g_log_scroll < g_log_count - log_rows)
                g_log_scroll++;
        } else if (final == 'B') { // Down — scroll log down
            if (g_log_scroll > 0) g_log_scroll--;
        } else if (final == 'C') { // Right
            if (g_input_cur < g_input_len) g_input_cur++;
        } else if (final == 'D') { // Left
            if (g_input_cur > 0) g_input_cur--;
        } else if (final == 'H') { // Home
            g_input_cur = 0;
        } else if (final == 'F') { // End
            g_input_cur = g_input_len;
        } else if (final == '~') {
            int code = atoi(buf + 1);
            if (code == 1 || code == 7) g_input_cur = 0;              // Home
            if (code == 4 || code == 8) g_input_cur = g_input_len;    // End
            if (code == 3) { // Delete
                if (g_input_cur < g_input_len) {
                    memmove(g_input + g_input_cur,
                            g_input + g_input_cur + 1,
                            g_input_len - g_input_cur - 1);
                    g_input_len--;
                }
            }
        }
    }
    return 0;
}
#endif /* !_WIN32 */

int cli_poll(void) {
    if (!g_is_tty) return 0;
    int complete = 0;

#ifdef _WIN32
    INPUT_RECORD ir;
    DWORD n;
    while (PeekConsoleInput(g_hin, &ir, 1, &n) && n > 0) {
        ReadConsoleInput(g_hin, &ir, 1, &n);
        if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
            WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;
            if (vk == VK_RETURN) {
                complete = process_key('\n');
            } else if (vk == VK_BACK) {
                process_key(127);
            } else if (vk == VK_DELETE) {
                if (g_input_cur < g_input_len) {
                    memmove(g_input + g_input_cur, g_input + g_input_cur + 1,
                            g_input_len - g_input_cur - 1);
                    g_input_len--;
                }
            } else if (vk == VK_LEFT)  { if (g_input_cur > 0) g_input_cur--; }
            else if (vk == VK_RIGHT)   { if (g_input_cur < g_input_len) g_input_cur++; }
            else if (vk == VK_HOME)    { g_input_cur = 0; }
            else if (vk == VK_END)     { g_input_cur = g_input_len; }
            else if (vk == VK_UP) {
                int log_rows = g_rows - 2;
                if (g_log_scroll < g_log_count - log_rows) g_log_scroll++;
            } else if (vk == VK_DOWN) {
                if (g_log_scroll > 0) g_log_scroll--;
            } else {
                char c = ir.Event.KeyEvent.uChar.AsciiChar;
                if (c >= 0x20 && c < 0x7F) complete = process_key((unsigned char)c);
            }
            cli_redraw();
        } else if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT) {
            update_term_size();
            cli_redraw();
        }
    }
#else
    // POSIX: drain all available bytes (stdin is O_NONBLOCK from enter_raw)
    {
        unsigned char byte;
        while (read(STDIN_FILENO, &byte, 1) == 1) {
            if (byte == '\x1b') {
                process_escape();
            } else {
                if (process_key((int)byte)) complete = 1;
            }
        }
        cli_redraw();
    }
#endif

    return complete;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

static Server *g_server_ref = NULL;

// Print a message to the log (used inside dispatch for command output)
static void cmd_print(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    cli_log("%s", buf);
}

static void print_help(void) {
    cmd_print("  Commands:");
    cmd_print("    list                          - list players per room");
    cmd_print("    rooms                         - list active rooms");
    cmd_print("    kick <id>                     - kick player");
    cmd_print("    ban <id> [reason]             - globally ban player IP");
    cmd_print("    ban room <code> <id> [reason] - ban player from room");
    cmd_print("    unban <ip>                    - remove global ban");
    cmd_print("    unban room <code> <ip>        - remove room ban");
    cmd_print("    bans                          - list all bans");
    cmd_print("    trust add <room> <ip>         - manually trust IP in room");
    cmd_print("    trust remove <room> <ip>      - revoke room trust");
    cmd_print("    trust list [room]             - list trusted IPs");
    cmd_print("    room create <code> [password] - create room");
    cmd_print("    setpw <code> <password>       - change room password");
    cmd_print("    log on|off                    - toggle packet logging");
    cmd_print("    quit                          - shutdown server");
}

// Split line into tokens (max n), returns count
static int split(const char *s, char toks[][256], int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s == ' ') s++;
        if (!*s) break;
        int i = 0;
        while (*s && *s != ' ' && i < 255) toks[n][i++] = *s++;
        toks[n][i] = '\0';
        n++;
    }
    return n;
}

// Return rest of string after skipping `skip` space-separated tokens
static const char *rest_after(const char *s, int skip) {
    for (int i = 0; i < skip; i++) {
        while (*s == ' ') s++;
        while (*s && *s != ' ') s++;
    }
    while (*s == ' ') s++;
    return s;
}

void cli_dispatch(Server *s, const char *line) {
    g_server_ref = s;

    // Trim leading spaces
    while (*line == ' ') line++;
    if (!*line) return;

    char toks[16][256];
    int  ntok = split(line, toks, 16);
    if (ntok == 0) return;

    // help
    if (strcmp(toks[0], "help") == 0) {
        print_help();
        return;
    }

    // list
    if (strcmp(line, "list") == 0) {
        int found = 0;
        for (int ri = 0; ri < s->n_rooms; ri++) {
            Room *r = &s->rooms[ri];
            if (!r->active) continue;
            int any = 0;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                Player *p = &s->players[i];
                if (p->used && p->room_idx == ri) {
                    if (!any) {
                        cmd_print("  Room '%s':", r->code);
                        any = 1; found = 1;
                    }
                    cmd_print("    ID=%-7d  nick='%s'  ip=%s",
                              p->id, p->nick, p->ip);
                }
            }
        }
        if (!found) cmd_print("  (no players connected)");
        return;
    }

    // rooms
    if (strcmp(line, "rooms") == 0) {
        int any = 0;
        for (int ri = 0; ri < s->n_rooms; ri++) {
            Room *r = &s->rooms[ri];
            if (!r->active) continue;
            any = 1;
            int count   = server_room_player_count(s, ri);
            DBRoom *dr  = db_find_room(&s->db, r->code);
            int n_trust = dr ? dr->n_trusted : 0;
            int n_bans  = dr ? dr->n_bans    : 0;
            const char *pw = r->password[0] ? r->password : "(no password)";
            cmd_print("  '%s': %d player(s)  password=%s  trusted=%d  bans=%d",
                      r->code, count, pw, n_trust, n_bans);
        }
        if (!any) cmd_print("  (no rooms)");
        return;
    }

    // kick <id>
    if (strcmp(toks[0], "kick") == 0) {
        if (ntok < 2) { cmd_print("  Usage: kick <id>"); return; }
        int id = atoi(toks[1]);
        Player *p = server_find_player_by_id(s, id);
        if (!p) { cmd_print("  Unknown player ID %d", id); return; }
        cli_log("Admin: kicked ID=%d ('%s')", id, p->nick);
        server_disconnect(s, p);
        return;
    }

    // ban room <code> <id> [reason]
    if (strcmp(toks[0], "ban") == 0 && ntok >= 2 && strcmp(toks[1], "room") == 0) {
        if (ntok < 4) { cmd_print("  Usage: ban room <code> <id> [reason]"); return; }
        const char *code   = toks[2];
        int         id     = atoi(toks[3]);
        const char *reason = ntok >= 5 ? rest_after(line, 4) : "";
        Player *p = server_find_player_by_id(s, id);
        if (!p) { cmd_print("  Unknown player ID %d", id); return; }
        DBRoom *dr = db_find_room(&s->db, code);
        if (!dr) { cmd_print("  Unknown room '%s'", code); return; }
        db_add_room_ban(dr, p->ip, p->nick, reason);
        db_save(&s->db);
        cli_log("Admin: room-banned %s ('%s') from '%s'  reason: %s",
                p->ip, p->nick, code, reason[0] ? reason : "(none)");
        server_disconnect(s, p);
        return;
    }

    // ban <id> [reason]
    if (strcmp(toks[0], "ban") == 0) {
        if (ntok < 2) { cmd_print("  Usage: ban <id> [reason]"); return; }
        int         id     = atoi(toks[1]);
        const char *reason = ntok >= 3 ? rest_after(line, 2) : "";
        Player *p = server_find_player_by_id(s, id);
        if (!p) { cmd_print("  Unknown player ID %d", id); return; }
        db_add_ban(&s->db, p->ip, p->nick, reason);
        db_save(&s->db);
        cli_log("Admin: globally banned %s ('%s')  reason: %s",
                p->ip, p->nick, reason[0] ? reason : "(none)");
        server_disconnect(s, p);
        return;
    }

    // unban room <code> <ip>
    if (strcmp(toks[0], "unban") == 0 && ntok >= 2 && strcmp(toks[1], "room") == 0) {
        if (ntok < 4) { cmd_print("  Usage: unban room <code> <ip>"); return; }
        const char *code = toks[2];
        const char *ip   = toks[3];
        DBRoom *dr = db_find_room(&s->db, code);
        if (!dr || !db_remove_room_ban(dr, ip)) {
            cmd_print("  No room ban for %s in '%s'", ip, code);
            return;
        }
        db_save(&s->db);
        cli_log("Admin: removed room ban for %s in '%s'", ip, code);
        return;
    }

    // unban <ip>
    if (strcmp(toks[0], "unban") == 0) {
        if (ntok < 2) { cmd_print("  Usage: unban <ip>"); return; }
        const char *ip = toks[1];
        if (!db_remove_ban(&s->db, ip)) {
            cmd_print("  No global ban for %s", ip);
            return;
        }
        db_save(&s->db);
        cli_log("Admin: removed global ban for %s", ip);
        return;
    }

    // bans
    if (strcmp(line, "bans") == 0) {
        int any = 0;
        if (s->db.n_bans > 0) {
            cmd_print("  Global bans:");
            for (int i = 0; i < s->db.n_bans; i++) {
                DBBan *b = &s->db.bans[i];
                cmd_print("    %s  nick='%s'  reason='%s'  at=%s",
                          b->ip, b->nick, b->reason, b->banned_at);
            }
            any = 1;
        }
        for (int ri = 0; ri < s->db.n_rooms; ri++) {
            DBRoom *dr = &s->db.rooms[ri];
            if (dr->n_bans == 0) continue;
            cmd_print("  Room '%s' bans:", dr->code);
            for (int i = 0; i < dr->n_bans; i++) {
                DBBan *b = &dr->bans[i];
                cmd_print("    %s  nick='%s'  reason='%s'  at=%s",
                          b->ip, b->nick, b->reason, b->banned_at);
            }
            any = 1;
        }
        if (!any) cmd_print("  (no bans)");
        return;
    }

    // trust add <room> <ip>
    if (strcmp(toks[0], "trust") == 0 && ntok >= 2 && strcmp(toks[1], "add") == 0) {
        if (ntok < 4) { cmd_print("  Usage: trust add <room> <ip>"); return; }
        const char *code = toks[2];
        const char *ip   = toks[3];
        DBRoom *dr = db_find_room(&s->db, code);
        if (!dr) { cmd_print("  Unknown room '%s'", code); return; }
        if (db_is_trusted(dr, ip)) {
            cmd_print("  %s is already trusted in '%s'", ip, code);
            return;
        }
        db_add_trusted(dr, ip);
        db_save(&s->db);
        cli_log("Admin: trusted %s in room '%s'", ip, code);
        return;
    }

    // trust remove <room> <ip>
    if (strcmp(toks[0], "trust") == 0 && ntok >= 2 && strcmp(toks[1], "remove") == 0) {
        if (ntok < 4) { cmd_print("  Usage: trust remove <room> <ip>"); return; }
        const char *code = toks[2];
        const char *ip   = toks[3];
        DBRoom *dr = db_find_room(&s->db, code);
        if (!dr || !db_remove_trusted(dr, ip)) {
            cmd_print("  No trust record for %s in '%s'", ip, code);
            return;
        }
        db_save(&s->db);
        cli_log("Admin: removed trust for %s in room '%s'", ip, code);
        return;
    }

    // trust list [room]
    if (strcmp(toks[0], "trust") == 0 && ntok >= 2 && strcmp(toks[1], "list") == 0) {
        const char *filter = ntok >= 3 ? toks[2] : NULL;
        int any = 0;
        for (int i = 0; i < s->db.n_rooms; i++) {
            DBRoom *dr = &s->db.rooms[i];
            if (filter && strcmp(dr->code, filter) != 0) continue;
            if (dr->n_trusted == 0) continue;
            any = 1;
            cmd_print("  Room '%s':", dr->code);
            for (int t = 0; t < dr->n_trusted; t++)
                cmd_print("    %s", dr->trusted[t]);
        }
        if (!any) cmd_print("  (no trusted IPs%s)", filter ? " for that room" : "");
        return;
    }

    // room create <code> [password]
    if (strcmp(toks[0], "room") == 0 && ntok >= 2 && strcmp(toks[1], "create") == 0) {
        if (ntok < 3) { cmd_print("  Usage: room create <code> [password]"); return; }
        const char *code = toks[2];
        const char *pw   = ntok >= 4 ? toks[3] : "";
        if (server_find_room(s, code)) {
            cmd_print("  Room '%s' already exists.", code);
            return;
        }
        Room *r = server_add_room(s, code, pw);
        if (!r) { cmd_print("  Failed: too many rooms."); return; }
        db_add_room(&s->db, code, pw);
        db_save(&s->db);
        cli_log("Admin: created room '%s'%s", code, pw[0] ? " (with password)" : "");
        return;
    }

    // setpw <code> <password>
    if (strcmp(toks[0], "setpw") == 0) {
        if (ntok < 3) { cmd_print("  Usage: setpw <code> <password>"); return; }
        const char *code = toks[1];
        const char *pw   = rest_after(line, 2);
        Room *r = server_find_room(s, code);
        if (!r) { cmd_print("  Unknown room '%s'", code); return; }
        server_set_room_password(s, r, pw);
        db_save(&s->db);
        cli_log("Admin: password changed for room '%s' (trusted IPs cleared)", code);
        return;
    }

    // quit
    if (strcmp(line, "quit") == 0) {
        cli_log("Admin: shutting down.");
        cli_shutdown();
        server_shutdown(s);
        exit(0);
    }

    cmd_print("  Unknown command: %s", line);
    print_help();
}

// ---------------------------------------------------------------------------
// Init / shutdown
// ---------------------------------------------------------------------------

void cli_init(Server *s) {
    (void)s;
#ifdef _WIN32
    g_is_tty = (_isatty(_fileno(stdout)) && _isatty(_fileno(stdin)));
#else
    g_is_tty = (isatty(STDOUT_FILENO) && isatty(STDIN_FILENO));
#endif
    if (!g_is_tty) return;
    update_term_size();
    enter_raw();
    // Clear screen and hide cursor position artifacts
    term_write(ANSI_CLEAR_SCREEN "\x1b[H");
    fflush(stdout);
}

void cli_shutdown(void) {
    if (!g_is_tty) return;
    // Move cursor past log area before restoring terminal
    term_writef(ANSI_MOVE_FMT "\n", g_rows, 1);
    fflush(stdout);
    leave_raw();
    g_is_tty = 0;
}
