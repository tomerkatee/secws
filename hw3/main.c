#include "fw.h"
#include <string.h>
#include<stdio.h>
#include <sys/stat.h>
#include <errno.h>


#define PATH_TO_RULES_ATTR "/sys/class/fw/rules/rules"
#define PATH_TO_RESET_ATTR "/sys/class/fw/fw_log/reset"
#define PATH_TO_LOG_DEV "/dev/fw_log"

/*
void print_error(char* custom_error_message)
{

    fprintf(stderr, )
}

*/

int file_isreg(const char *path) {
    struct stat st;

    if (stat(path, &st) < 0)
        return -1;

    return S_ISREG(st.st_mode);
}

int load_rules(char* path)
{
    if(file_isreg(path) != 1)
    {
        perror("invalid file path");
        return -1;
    }

    
}

int show_rules(void)
{
    FILE *file;
    char buffer[MAX_RULES*sizeof(rule_t)];
    rule_t rule;
    const char* format = "%s %hhu %u %hhu %u %hhu %hu %hu %hhu %hhu %hhu\n";
    file = fopen(PATH_TO_RULES_ATTR, "r");

    if(!file){
        perror("Error opening rules file");
        return -1;
    }

    while(fread(&rule, sizeof(rule_t), sizeof(rule_t), file))
    {
        //TODO: beautify the print format
        printf(format, rule.rule_name, rule.direction, rule.src_ip, rule.src_prefix_size, rule.dst_ip, rule.dst_prefix_size, rule.src_port, rule.dst_port, rule.protocol, rule.ack, rule.action);	
    }

    return 0;
}

int main(int argc, char* argv[])
{

    if(argc < 2)
    {
        printf("error: not enough arguments\n");
        return -1;
    }

    if(strcmp(argv[1], "load_rules\n"))
    {
        if(argc != 3)
        {
            printf("error: there should be exactly 2 arguments given\n");
            return -1;
        }
        return load_rules(argv[1]);      
    }
    else if(argc != 2)
    {
        printf("error: too much arguments\n");
        return -1;
    }

    if(strcmp(argv[1], "show_rules"))
    {
        return show_rules();
    }
    else if(strcmp(argv[1], "show_log"))
    {
        
    }
    else if(strcmp(argv[1], "clear_log"))
    {
        
    }
    else
    {
        printf("error: bad arguments");
    }


}