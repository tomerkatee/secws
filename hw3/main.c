#include <string.h>
#include<stdio.h>
#include <sys/stat.h>
#include <errno.h>


typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	unsigned int direction;
	unsigned int	src_ip;
	unsigned int	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	unsigned char    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	unsigned int	dst_ip;
	unsigned int	dst_prefix_mask; 	// as above
	unsigned char   dst_prefix_size; 	// as above	
	unsigned short	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	unsigned int	protocol; 			// values from: prot_t
	unsigned int	ack; 				// values from: ack_t
	unsigned char	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

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
    //char buffer[MAX_RULES*sizeof(rule_t)];
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

    if(strcmp(argv[1], "load_rules\n") == 0)
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

    if(strcmp(argv[1], "show_rules") == 0)
    {
        return show_rules();
    }
    else if(strcmp(argv[1], "show_log") == 0)
    {
        
    }
    else if(strcmp(argv[1], "clear_log") == 0)
    {
        
    }
    else
    {
        printf("error: bad arguments");
    }


}