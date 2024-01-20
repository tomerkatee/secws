#include "fw.h"
#include <linux/uaccess.h>
#include <linux/klist.h>
#include <stdarg.h>




MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Katee");

static struct nf_hook_ops nfho_fwd;
/////////////////////////////////////////////////////////

#define CHRDEV_NAME "firewall"



static int major_number;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;

#define MAX_FORMAT_SIZE 40
#define LOGS_CHUNK_SIZE
#define NUM_RULE_CATEGORIES 9

typedef struct {
    log_row_t* data;
    struct klist_node node;
} log_node;

static struct klist logs;
static rule_t rules[MAX_RULES];
static int num_rules = 0;

static int fwd_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	
}



static int create_log(log_row_t* log)
{
	
}

static create_rule()

ssize_t read_logs(struct file *filp, char *buff, size_t length, loff_t *offp) {
	
	
	ssize_t num_of_bytes;

	

	///////////////////////////////////

	num_of_bytes = (str_len < length) ? str_len : length;
    
    if (num_of_bytes == 0) { // We check to see if there's anything to write to the user
    	return 0;
	}
    
    if (copy_to_user(buff, buffer_index, num_of_bytes)) { // Send the data to the user through 'copy_to_user'
        return -EFAULT;
    } else { // fuction succeed, we just sent the user 'num_of_bytes' bytes, so we updating the counter and the string pointer index
        str_len -= num_of_bytes;
        buffer_index += num_of_bytes;
        return num_of_bytes;
    }
	return -EFAULT; // Should never reach here
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = read_logs
};

ssize_t display_accepted(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", accepted);
}

static int custom_sscanf(char** str, const char* format, ...)
{
	int num_chars_scanned, num_matches;
	va_list args;

	va_start(args, format);
	char format_with_num[MAX_FORMAT_SIZE];
	// used to append a "%n" to the format
	scnprintf(format_with_num, MAX_FORMAT_SIZE, "%s%%n", format);

	num_matches = sscanf(*str, format_with_num, args, &num_chars_scanned);

	*str += num_chars_scanned;
	va_end(args);
	return num_matches;
}


static int is_prot_t(unsigned char number) {
	switch (number) {
		case PROT_ICMP:
		case PROT_TCP:
		case PROT_UDP:
		case PROT_OTHER:
		case PROT_ANY:
			return 1;
		default:
			return 0;
	}
}

static int is_direction_t(unsigned char number) {
	switch (number) {
		case DIRECTION_IN:
		case DIRECTION_OUT:
		case DIRECTION_ANY:
			return 1;
		default:
			return 0;
	}
}

static int is_ack_t(unsigned char number) {
	switch (number) {
		case ACK_NO:
		case ACK_YES:
		case ACK_ANY:
			return 1;
		default:
			return 0;
	}
}

static int is_action(unsigned char number) {
	switch (number) {
		case NF_ACCEPT:
		case NF_DROP:
			return 1;
		default:
			return 0;
	}
}

static __be32 subnet_mask(unsigned char prefix_len)
{
    return prefix_len ? ~0 << (32 - prefix_len) : 0;
}


ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	rule_t temp[MAX_RULES];
	char* curr = buf;
	rule_t rule;
	unsigned char direction, ack, protocol, action;

	int num_matches, num_chars_scanned;
	int i, j;
	for(i = 0 ;; i++, curr+=num_chars_scanned)
	{
		rule = temp[i];

		num_matches = sscanf(curr, "%19s %hhu %u %hhu %u %hhu %hu %hu %hhu %hhu %hhu%n", rule.rule_name, &direction, &rule.src_ip, &rule.src_prefix_size, &rule.dst_ip, &rule.dst_prefix_size, &rule.src_port, &rule.dst_port, &protocol, &ack, &action, &num_chars_scanned);

		if(num_matches == 0)
			break;
		
		if(num_matches != NUM_RULE_CATEGORIES)
			return -1;

		
		if (!(rule.src_prefix_size <= 32
			&& rule.dst_prefix_size <= 32
			&& rule.src_port <= PORT_ABOVE_1023
			&& rule.dst_port <= PORT_ABOVE_1023
			&& is_prot_t(protocol)
			&& is_ack_t(ack)
			&& is_action(action)
			&& is_direction_t(direction)))
			return -1;

		rule.src_prefix_mask = subnet_mask(rule.src_prefix_size);
		rule.dst_prefix_mask = subnet_mask(rule.dst_prefix_size);
		rule.direction = direction;
		rule.protocol = protocol;
		rule.ack = ack;
		rule.action = action;
	}

	for (j = 0; j < i; j++) 
		rules[j] = temp[j];
	
	num_rules = i;

	return count;	
}

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	char *curr = buf;
	char* format = "%s %hhu %u %hhu %u %hhu %hu %hu %hhu %hhu %hhu\n";
	rule_t rule;
	int i;
	for (i = 0; i < num_rules; i++)
	{
		rule = rules[i];
		
		curr += scnprintf(curr, PAGE_SIZE-(curr-buf), format, rule.rule_name, rule.direction, rule.src_ip, rule.src_prefix_size, rule.dst_ip, rule.dst_prefix_size, rule.src_port, rule.dst_port, rule.protocol, rule.ack, rule.action);
		
	}
	return curr - buf;
}



ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	// TODO: clear logs
	return count;
}

static DEVICE_ATTR(rules_attr, S_IWUSR | S_IRUGO, display_rules, modify_rules);
static DEVICE_ATTR(reset_attr, S_IWUSR, NULL, modify_reset);

static int register_sysfs_chrdev(void)
{
	
	major_number = register_chrdev(0, CHRDEV_NAME, &fops);
	if (major_number < 0)
		goto register_chrdev_failed;
		
	sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sysfs_class))
		goto class_create_failed;
	
	rules_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);
	if (IS_ERR(rules_device))
		goto rules_device_create_failed;
	
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules_attr.attr))
		goto rules_attr_create_failed;
	
	log_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, DEVICE_NAME_LOG);
	if (IS_ERR(log_device))
		goto log_device_create_failed;

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_reset_attr.attr))
		goto rules_attr_create_failed;
	

	return 0;

	// error handling
reset_attr_create_failed:
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));
log_device_create_failed:
rules_attr_create_failed:
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));
rules_device_create_failed:
	class_destroy(sysfs_class);
class_create_failed:
	unregister_chrdev(major_number, CHRDEV_NAME);
register_chrdev_failed:
	return -1;

}


static int __init my_module_init_function(void) {
	nfho_fwd.hook = (nf_hookfn*)fwd_hook_function;
    nfho_fwd.hooknum = NF_INET_FORWARD;
    nfho_fwd.pf = PF_INET;
    nfho_fwd.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_fwd);

    if(register_sysfs_chrdev())
	{
		printk(KERN_ERR "hw3secws module failed to load\n");
		return -1;
	}
	printk(KERN_INFO "hw3secws module loaded\n");
	return 0; 
}

static void __exit my_module_exit_function(void) {
    nf_unregister_net_hook(&init_net, &nfho_fwd);

	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset_attr.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));

    device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules_attr.attr);	
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));

	class_destroy(sysfs_class);
	unregister_chrdev(major_number, CHRDEV_NAME);

	printk(KERN_INFO "hw3secws module unloaded\n");
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);