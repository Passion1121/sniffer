#ifndef PARSE_CMD_H
#define PARSE_CMD_H

struct cmd_params_data{
    int is_help;
    char interface[10];
};

void parse_cmd(int, char **, struct cmd_params_data *);

#endif // PARSE_CMD_H
