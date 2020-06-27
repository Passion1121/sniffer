#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "parse_cmd.h"

void parse_cmd(int argc, char **argv, struct cmd_params_data *params_data)
{
    int opt = 0;
    struct option long_params_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
    };

    while ((opt = getopt_long(argc, argv, "hi:", long_params_options, NULL)) != -1)
    {
        switch (opt) {
        case 'h':
            params_data->is_help = 1;
            break;
        case '?':
            params_data->is_help = 1;
            break;
        case 'i':
            if (strlen(optarg) > 10)
            {
               params_data->is_help = 1;
            }
            else
            {
                strcpy(params_data->interface, optarg);
            }
            break;
        default:
            params_data->is_help = 1;
        }
    }
}
