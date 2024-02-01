#include "fw.h"
#include <linux/uaccess.h>
#include <linux/klist.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/string.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Katee");



typedef __be32 ip_t;
typedef __be16 port_t;


#define CHRDEV_NAME "firewall"
#define MAX_FORMAT_SIZE 40
#define LOG_CHUNK_SIZE 8
#define NUM_RULE_CATEGORIES 9
#define IP_ANY 0
#define LOG_ROW_BUFFER_SIZE 64

//TODO: fix!
//#define subnet_prefix_size_to_mask(size) ((size) ? ~0 << (32 - (size)) : 0)
#define subnet_prefix_size_to_mask(size) ((size) ? (1 << (size))-1 : 0)


typedef struct {
	int rows_count;
    log_row_t* data;
    struct klist_node node;
} log_node;


typedef struct {
	struct klist_iter nodes_iter;
	int i;
} log_iter;


static struct nf_hook_ops nfho_fwd;
static struct klist log_klist;
static log_node* tail = NULL;
static rule_t custom_rules[MAX_RULES];
static int num_custom_rules = 0;
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;
static log_iter read_log_iter;

static rule_t loopback_rule = {
	.rule_name = "loopback",
	.direction = DIRECTION_ANY,
	.src_ip = htonl(INADDR_LOOPBACK),
	.src_prefix_mask = subnet_prefix_size_to_mask(8),
	.src_prefix_size = 8,
	.dst_ip = htonl(INADDR_LOOPBACK),
	.dst_prefix_mask = subnet_prefix_size_to_mask(8),
	.dst_prefix_size = 8,
	.src_port = PORT_ANY,
	.dst_port = PORT_ANY,
	.protocol = PROT_ANY,
	.ack = ACK_ANY,
	.action = NF_ACCEPT
};

static rule_t default_rule = {
	.rule_name = "default",
	.direction = DIRECTION_ANY,
	.src_ip = IP_ANY,
	.src_prefix_mask = 0,
	.src_prefix_size = 0,
	.dst_ip = IP_ANY,
	.dst_prefix_mask = 0,
	.dst_prefix_size = 0,
	.src_port = PORT_ANY,
	.dst_port = PORT_ANY,
	.protocol = PROT_ANY,
	.ack = ACK_ANY,
	.action = NF_DROP
};


// gets log_node reference from its klist_node
static log_node* cast_to_log_node(struct klist_node* knode)
{
	return knode ? container_of(knode, log_node, node) : NULL;
}

static void log_iter_init(log_iter* iter)
{
	klist_iter_init(&log_klist, &iter->nodes_iter);
	klist_next(&iter->nodes_iter);
	iter->i = 0;
}


static log_row_t* log_iter_next(log_iter* iter)
{
	log_node* curr_log_node = cast_to_log_node(iter->nodes_iter.i_cur);

	if(!curr_log_node)
		return NULL;

	if(iter->i < curr_log_node->rows_count)
		return &curr_log_node->data[iter->i++];

	iter->i = 0;
	if(klist_next(&iter->nodes_iter))
		return log_iter_next(iter);

	klist_iter_exit(&iter->nodes_iter);
	return NULL;
}


static ip_t is_addr_in_subnet(ip_t addr, ip_t subnet_addr, ip_t subnet_mask)
{
	return (addr & subnet_mask) == (subnet_addr & subnet_mask);
}

static int is_port_in_range(port_t port, port_t range)
{
	return range ? (range == 1023 ? port > 1023 : port==range) : 1;	
}

static int is_protocol_in_range(u_int8_t prot, prot_t range)
{
	return range==PORT_ANY ? 1 : (prot==range ? 1 : range==PORT_OTHER);
}

static int is_ack_in_range(unsigned short ack, ack_t range)
{
	return range == ACK_ANY ? 1 : (range == ACK_YES ? ack : !ack);
}

static int rule_match(rule_t *rule, struct sk_buff *skb)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header;
	struct udphdr* udp_header;
	char* nic_name = skb->dev->name;
	u_int8_t packet_prot = ip_header->protocol;

	if(rule->src_ip != IP_ANY && !is_addr_in_subnet(ip_header->saddr, rule->src_ip, rule->src_prefix_mask))
		return 0;
	
	if(rule->dst_ip != IP_ANY && !is_addr_in_subnet(ip_header->daddr, rule->dst_ip, rule->dst_prefix_mask))
		return 0;

	if(rule->direction==DIRECTION_IN && !strcmp(IN_NET_DEVICE_NAME, nic_name))
		return 0;
	
	if(rule->direction==DIRECTION_OUT && !strcmp(OUT_NET_DEVICE_NAME, nic_name))
		return 0;


	if(!is_protocol_in_range(packet_prot, rule->protocol))
		return 0;

	if(packet_prot == PROT_TCP)
	{
		tcp_header = tcp_hdr(skb);
		if(!is_port_in_range(tcp_header->source, rule->src_port))
			return 0;
		if(!is_port_in_range(tcp_header->dest, rule->dst_port))
			return 0;
		if(!is_ack_in_range(tcp_header->ack, rule->ack))
			return 0;
	}

	if(packet_prot == PROT_UDP)
	{
		udp_header = udp_hdr(skb);
		if(!is_port_in_range(udp_header->source, rule->src_port))
			return 0;
	
		if(!is_port_in_range(udp_header->dest, rule->dst_port))
			return 0;
	}

	return 1;
}

//TODO: check xmas
static int is_xmas_packet(struct sk_buff *skb)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header;
	if(ip_header->protocol != PROT_TCP)
		return 0;

	tcp_header = tcp_hdr(skb);
	return tcp_header->fin && tcp_header->urg && tcp_header->psh;
}


// this function will be called only for IPV4 TCP/UDP/ICMP packets
static log_row_t create_log(struct sk_buff *skb, __u8 action, reason_t reason)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header;
	struct udphdr* udp_header;
	struct timespec ts;
	log_row_t log_row;

	getnstimeofday(&ts);
	log_row.timestamp = ts.tv_sec;
	log_row.protocol = ip_header->protocol;
	log_row.action = action;
	log_row.src_ip = ip_header->saddr;
	log_row.dst_ip = ip_header->daddr;
	
	if(ip_header->protocol == PROT_TCP)
	{
		tcp_header = tcp_hdr(skb);
		log_row.src_port = tcp_header->source;
		log_row.dst_port = tcp_header->dest;
	}

	if(ip_header->protocol == PROT_UDP)
	{
		udp_header = udp_hdr(skb);
		log_row.src_port = udp_header->source;
		log_row.dst_port = udp_header->dest;
	}

	log_row.reason = reason;
	log_row.count = 1;

	return log_row;
}

// adds a chunk of empty log rows to the log list as a node
static void add_log_node(void)
{
	log_node* log_node_p;
	if(!(log_node_p = (log_node*)kmalloc(sizeof(log_node), GFP_KERNEL)))
		printk(KERN_ERR "kmalloc failed\n");
	if(!(log_node_p->data = (log_row_t*)kmalloc(sizeof(log_row_t) * LOG_CHUNK_SIZE, GFP_KERNEL)))
		printk(KERN_ERR "kmalloc failed\n");
	log_node_p->rows_count = 0;
	klist_add_tail(&log_node_p->node, &log_klist);
	tail = log_node_p;
}

static int compare_log_rows(log_row_t *r1, log_row_t *r2)
{
	return r1->protocol == r2->protocol &&
		r1->action == r2->action &&
		r1->src_ip == r2->src_ip &&
		r1->dst_ip == r2->dst_ip &&
		r1->src_port == r2->src_port &&
		r1->dst_port == r2->dst_port &&
		r1->reason == r2->reason;
}

// add a single log row to the log and add a log rows chunck if needed
static void add_log(log_row_t log_row)
{
	log_iter iter;
	log_row_t *curr;
	
	log_iter_init(&iter);

	while((curr = log_iter_next(&iter)))
	{
		if(compare_log_rows(&log_row, curr))
		{
			curr->timestamp = log_row.timestamp;
			curr->count++;
			return;
		}
	}

	if(!tail || tail->rows_count == LOG_CHUNK_SIZE)
		add_log_node();

	// tail is now updated to the new log_node
	tail->data[tail->rows_count++] = log_row;
}

static int fwd_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int i;
	rule_t* rule;
	struct iphdr* ip_header = ip_hdr(skb);
	u_int8_t packet_prot = ip_header->protocol;
	reason_t reason;

	if((ip_header->version != 4) || (packet_prot != PROT_UDP && packet_prot != PROT_ICMP && packet_prot != PROT_TCP) || rule_match(&loopback_rule, skb))
		return NF_ACCEPT;

	if(is_xmas_packet(skb))
	{
		add_log(create_log(skb, NF_DROP, REASON_XMAS_PACKET));
		return NF_DROP;
	}

	for (i = 0; i < num_custom_rules; i++)
	{
		rule = custom_rules+i;
		if (rule_match(rule, skb))
		{
			// TODO: add reasons
			reason = i;
			add_log(create_log(skb, rule->action, reason));
			return rule->action;
		}
	}
	add_log(create_log(skb, default_rule.action, REASON_NO_MATCHING_RULE));
	return default_rule.action;
}


int open_log(struct inode *_inode, struct file *_file) {
	log_iter_init(&read_log_iter);
	return 0;
}

char* copy_log_row_to_buffer(char *buff, log_row_t *log)
{
	char *curr = buff;

	memcpy(curr, &log->timestamp, sizeof(log->timestamp));
	curr += sizeof(log->timestamp);

	memcpy(curr, &log->protocol, sizeof(log->protocol));
	curr += sizeof(log->protocol);

	memcpy(curr, &log->action, sizeof(log->action));
	curr += sizeof(log->action);

	memcpy(curr, &log->src_ip, sizeof(log->src_ip));
	curr += sizeof(log->src_ip);

	memcpy(curr, &log->dst_ip, sizeof(log->dst_ip));
	curr += sizeof(log->dst_ip);

	memcpy(curr, &log->src_port, sizeof(log->src_port));
	curr += sizeof(log->src_port);

	memcpy(curr, &log->dst_port, sizeof(log->dst_port));
	curr += sizeof(log->dst_port);

	memcpy(curr, &log->reason, sizeof(log->reason));
	curr += sizeof(log->reason);

	memcpy(curr, &log->count, sizeof(log->count));
	curr += sizeof(log->count);

	return curr;
}
ssize_t read_log(struct file *filp, char *buff, size_t length, loff_t *offp) {	
	log_row_t *row;
	char *curr = buff;

	if(length < sizeof(log_row_t))
		return -ENOSPC;

	while((length-(curr-buff)) > sizeof(log_row_t) && (row = log_iter_next(&read_log_iter)))
	{
		curr = copy_log_row_to_buffer(curr, row);
	}
	
	return curr-buff;
	
}


static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = read_log,
	.open = open_log
};


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

const char* set_rule_from_buffer(const char* buff, rule_t *rule)
{
	const char *curr = buff;

	memcpy(&rule->rule_name, curr, sizeof(rule->rule_name));
	curr += sizeof(rule->rule_name);

	memcpy(&rule->direction, curr, sizeof(rule->direction));
	curr += sizeof(rule->direction);

	memcpy(&rule->src_ip, curr, sizeof(rule->src_ip));
	curr += sizeof(rule->src_ip);

	memcpy(&rule->src_prefix_size, curr, sizeof(rule->src_prefix_size));
	curr += sizeof(rule->src_prefix_size);

	memcpy(&rule->dst_ip, curr, sizeof(rule->dst_ip));
	curr += sizeof(rule->dst_ip);

	memcpy(&rule->dst_prefix_size, curr, sizeof(rule->dst_prefix_size));
	curr += sizeof(rule->dst_prefix_size);

	memcpy(&rule->src_port, curr, sizeof(rule->src_port));
	curr += sizeof(rule->src_port);

	memcpy(&rule->dst_port, curr, sizeof(rule->dst_port));
	curr += sizeof(rule->dst_port);

	memcpy(&rule->protocol, curr, sizeof(rule->protocol));
	curr += sizeof(rule->protocol);

	memcpy(&rule->ack, curr, sizeof(rule->ack));
	curr += sizeof(rule->ack);

	memcpy(&rule->action, curr, sizeof(rule->action));
	curr += sizeof(rule->action);

	if (!(rule->src_prefix_size <= 32
		&& rule->dst_prefix_size <= 32
		&& rule->src_port <= PORT_ABOVE_1023
		&& rule->dst_port <= PORT_ABOVE_1023
		&& is_prot_t(rule->protocol)
		&& is_ack_t(rule->ack)
		&& is_action(rule->action)
		&& is_direction_t(rule->direction)))
		return NULL;

	rule->src_prefix_mask = subnet_prefix_size_to_mask(rule->src_prefix_size);
	rule->dst_prefix_mask = subnet_prefix_size_to_mask(rule->dst_prefix_size);
	
	return curr;
}

ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int i;
	rule_t *temp;
	const char* curr = buf;
	temp = (rule_t*)kmalloc(sizeof(rule_t)*MAX_RULES, GFP_KERNEL);
	
	for(i = 0; i < MAX_RULES && curr-buf < count; i++)
	{
		if(!(curr = set_rule_from_buffer(curr, temp+i)))
			return -1;
		if(curr-buf > count)
			return -1;
	}

	num_custom_rules = i;

	for (i = 0; i < num_custom_rules; i++) 
		custom_rules[i] = temp[i];
	
	kfree(temp);

	return count;	
}


char* copy_rule_to_buffer(char *buff, rule_t *rule)
{
	char *curr = buff;

	memcpy(curr, rule->rule_name, sizeof(rule->rule_name));
	curr += sizeof(rule->rule_name);

	memcpy(curr, &rule->direction, sizeof(rule->direction));
	curr += sizeof(rule->direction);

	memcpy(curr, &rule->src_ip, sizeof(rule->src_ip));
	curr += sizeof(rule->src_ip);

	memcpy(curr, &rule->src_prefix_size, sizeof(rule->src_prefix_size));
	curr += sizeof(rule->src_prefix_size);

	memcpy(curr, &rule->dst_ip, sizeof(rule->dst_ip));
	curr += sizeof(rule->dst_ip);

	memcpy(curr, &rule->dst_prefix_size, sizeof(rule->dst_prefix_size));
	curr += sizeof(rule->dst_prefix_size);

	memcpy(curr, &rule->src_port, sizeof(rule->src_port));
	curr += sizeof(rule->src_port);

	memcpy(curr, &rule->dst_port, sizeof(rule->dst_port));
	curr += sizeof(rule->dst_port);

	memcpy(curr, &rule->protocol, sizeof(rule->protocol));
	curr += sizeof(rule->protocol);

	memcpy(curr, &rule->ack, sizeof(rule->ack));
	curr += sizeof(rule->ack);

	memcpy(curr, &rule->action, sizeof(rule->action));
	curr += sizeof(rule->action);

	return curr;
}

ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	char *curr = buf;
	rule_t* rule;
	int i;
	for (i = -1; i <= num_custom_rules; i++)
	{
		rule = i == -1 ? &loopback_rule : (i == num_custom_rules ? &default_rule : custom_rules+i);

		curr = copy_rule_to_buffer(curr, rule);
	}
	return curr - buf;
}

// deletes all nodes from klist and refreshes it, frees all kmalloc-ed memory
ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{

	struct klist_iter iter;
	log_node *curr_log_node;
	struct klist_node *prev;
	struct klist_node *curr;

	if(!tail)
		return count;

	klist_iter_init_node(&log_klist, &iter, &tail->node);

	do 
	{
		curr = iter.i_cur;
		curr_log_node = cast_to_log_node(curr);
		kfree(curr_log_node->data);
		prev = klist_prev(&iter);
		klist_del(curr);
		kfree(curr_log_node);
	} while(prev);

	klist_iter_exit(&iter);
	klist_init(&log_klist, NULL, NULL);
	tail = NULL;
	return count;
}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR, NULL, modify_reset);

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
	
	if (device_create_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
		goto rules_attr_create_failed;
	
	log_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);
	if (IS_ERR(log_device))
		goto log_device_create_failed;

	if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr))
		goto reset_attr_create_failed;
	

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
	klist_init(&log_klist, NULL, NULL);

	nfho_fwd.hook = (nf_hookfn*)fwd_hook_function;
    nfho_fwd.hooknum = NF_INET_FORWARD;
    nfho_fwd.pf = PF_INET;
    nfho_fwd.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_fwd);

    if(register_sysfs_chrdev())
	{
		printk(KERN_ERR "firewall module failed to load\n");
		return -1;
	}
	printk(KERN_INFO "firewall module loaded\n");
	return 0; 
}

static void __exit my_module_exit_function(void) {
    nf_unregister_net_hook(&init_net, &nfho_fwd);

	device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_LOG));

    device_remove_file(rules_device, (const struct device_attribute *)&dev_attr_rules.attr);	
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_RULES));

	class_destroy(sysfs_class);
	unregister_chrdev(major_number, CHRDEV_NAME);

	printk(KERN_INFO "firewall module unloaded\n");
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);