#include "fw.h"
#include <linux/uaccess.h>
#include <linux/klist.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <net/tcp_states.h>


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
#define MINOR_CONNS 2
#define CONN_HASHTABLE_SIZE_BITS 8
#define NO_DECISION 99
#define REASON_EXISTING_TCP_CONNECTION -7
#define PORT_HTTP_SERVER 80
#define PORT_FTP_SERVER 21

#define DEVICE_NAME_CONNS "conns"

#define subnet_prefix_size_to_mask(size) ((size)==sizeof(ip_t)*8 ? -1 : (1 << (size))-1)

#define COPY_AND_ADVANCE(buf, st_p, field_id) do {\
						memcpy((buf), &(st_p)->field_id, sizeof((st_p)->field_id));\
						(buf) += sizeof((st_p)->field_id);\
						} while(0)


typedef struct {
	int rows_count;
    log_row_t* data;
    struct klist_node node;
} log_node;


typedef struct {
	struct klist_iter nodes_iter;
	int i;
} log_iter;


typedef struct{
	ip_t src_ip;
	ip_t dst_ip;
	port_t src_port;
	port_t dst_port;
} conn_t;

typedef struct {
	conn_t conn;	
	int state;
	int mitm_src_port;
	struct klist_node node;
} conn_row_node;

typedef struct {
	conn_row_node* conn_row;
	struct hlist_node hnode;
} conn_row_p_node;


static struct nf_hook_ops nfho_prert;
static struct nf_hook_ops nfho_localout;
static struct klist log_klist;
static struct klist conn_klist;
static log_node* tail_log = NULL;
static conn_row_node* tail_conn = NULL;
static rule_t custom_rules[MAX_RULES];
static int num_custom_rules = 0;
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* rules_device = NULL;
static struct device* log_device = NULL;
static struct device* conns_device = NULL;
static log_iter read_log_iter;
static port_t curr_mitm_port;

// the hashtable will contain 2^(CONN_HASHTABLE_SIZE_BITS) buckets, each containing linked list of conn_rows
DEFINE_HASHTABLE(conn_hashtable, CONN_HASHTABLE_SIZE_BITS);


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

// gets conn_row_node reference from its klist_node
static log_node* cast_to_conn_row_node(struct klist_node* knode)
{
	return knode ? container_of(knode, conn_row_node, node) : NULL;
}

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
	return ntohs(range)==PORT_ANY ? 1 : (ntohs(range) == PORT_ABOVE_1023 ? ntohs(port) > 1023 : port==range);	
}

static int is_protocol_in_range(u_int8_t prot, prot_t range)
{
	return range==PROT_ANY ? 1 : (prot==range ? 1 : range==PORT_OTHER);
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

	if(rule->direction==DIRECTION_IN && strcmp(OUT_NET_DEVICE_NAME, nic_name))
		return 0;

	if(rule->direction==DIRECTION_OUT && strcmp(IN_NET_DEVICE_NAME, nic_name))
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
	else if(packet_prot == PROT_UDP)
	{
		udp_header = udp_hdr(skb);
		if(!is_port_in_range(udp_header->source, rule->src_port))
			return 0;
	
		if(!is_port_in_range(udp_header->dest, rule->dst_port))
			return 0;
	}

	return 1;
}


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
	else if(ip_header->protocol == PROT_UDP)
	{
		udp_header = udp_hdr(skb);
		log_row.src_port = udp_header->source;
		log_row.dst_port = udp_header->dest;
	}
	else 
	{
		log_row.src_port = 0;
		log_row.dst_port = 0;
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
	tail_log = log_node_p;
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

	if(!tail_log || tail_log->rows_count == LOG_CHUNK_SIZE)
		add_log_node();

	// tail_log is now updated to the new log_node
	tail_log->data[tail_log->rows_count++] = log_row;
}

static int conn_eq(conn_t *conn1, conn_t *conn2)
{
	return conn1->src_ip == conn2->src_ip &&
		   conn1->dst_ip == conn2->dst_ip &&
		   conn1->src_port == conn2->src_port &&
		   conn1->dst_port == conn2->dst_port;
}

static int hash_conn(conn_t *conn)
{
	return conn->src_ip + conn->dst_ip + conn->src_port + conn->dst_port;
}

static conn_row_node* search_conn_table_by_conn(conn_t *conn)
{
	conn_row_p_node* curr;

	hash_for_each_possible(conn_hashtable, curr, hnode, hash_conn(conn))
	{
		if(conn_eq(&curr->conn_row->conn, conn))
			return curr->conn_row;
	}

	return NULL;
}


static conn_row_node* search_conn_table_by_mitm_port(port_t mitm_port)
{
	conn_row_p_node* curr;

	hash_for_each_possible(conn_hashtable, curr, hnode, mitm_port)
	{
		if(curr->conn_row->mitm_src_port, mitm_port)
			return curr->conn_row;
	}

	return NULL;
}

static int hash_src(ip_t src_ip, port_t src_port)
{
	return src_ip + src_port;
}

static conn_row_node* search_conn_table_by_src(ip_t src_ip, port_t src_port)
{
	conn_row_p_node* curr;

	hash_for_each_possible(conn_hashtable, curr, hnode, hash_src(src_ip, src_port))
	{
		if(curr->conn_row->conn.src_ip == src_ip && curr->conn_row->conn.src_port == src_port)
			return curr;
	}

	return NULL;
}




static conn_row_node* add_conn_row(conn_t *conn, int initialState)
{
	conn_row_node* conn_row = kmalloc(sizeof(conn_row_node), GFP_KERNEL);
	if(!conn_row){
		printk(KERN_ERR "Failed to allocate memory\n");
		return NULL;
	}

	conn_row->conn = *conn;
	conn_row->state = initialState;
	klist_add_tail(&conn_row->node, &conn_klist);
	tail_conn = conn_row;
	return conn_row;
}

static conn_row_p_node* add_conn_row_to_conn_hash(conn_row_node* conn_row, int hash)
{
	conn_row_p_node* conn_row_p = kmalloc(sizeof(conn_row_p_node), GFP_KERNEL);
	if(!conn_row_p){
		printk(KERN_ERR "Failed to allocate memory\n");
		return NULL;
	}

	conn_row_p->conn_row = conn_row;
	hash_add(conn_hashtable, &conn_row_p->hnode, hash);

	return conn_row_p;
}


//TODO: think about acks are they mandatory to write here?

// decides what to do with the packet by the connection row in the table, and also updates if needed
static int handle_packet_by_conn_row(struct sk_buff *skb, conn_row_node* conn_row)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header = tcp_hdr(skb);

	if(ip_header->daddr == conn_row->conn.src_ip)
		return NF_ACCEPT;

	switch (conn_row->state)
	{
		case TCP_CLOSE:
			if(tcp_header->syn && !tcp_header->ack)
				conn_row->state = TCP_SYN_SENT;

			else if(tcp_header->syn && tcp_header->ack)
				conn_row->state = TCP_SYN_RECV;
			
			else
				return NF_DROP;
			
			break;

		case TCP_SYN_SENT:
			if(tcp_header->ack)
				conn_row->state = TCP_ESTABLISHED;
			else if(tcp_header->syn && !tcp_header->ack) // syn retransmission
				conn_row->state = TCP_SYN_SENT;
			else
				return NF_DROP;

			break;

		case TCP_SYN_RECV:
			if(tcp_header->ack)
				conn_row->state = tcp_header->syn ? TCP_SYN_RECV : TCP_ESTABLISHED;
			else
				return NF_DROP;

		case TCP_ESTABLISHED:
			if(tcp_header->ack)
				conn_row->state = tcp_header->fin ? TCP_CLOSE : TCP_ESTABLISHED;
			else
				return NF_DROP;
			break;	
	}
	return NF_ACCEPT;

}

static int handle_by_conn_tab(struct sk_buff *skb)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header = tcp_hdr(skb);
	conn_t skb_conn = { .src_ip = ip_header->saddr, .src_port = tcp_header->source, .dst_ip = ip_header->daddr, .dst_port = tcp_header->dest };
	conn_t skb_conn_inv = { .src_ip = ip_header->daddr, .src_port = tcp_header->dest, .dst_ip = ip_header->saddr, .dst_port = tcp_header->source };
	conn_row_node *conn_row, *conn_inv_row;
	conn_row = search_conn_table_by_conn(&skb_conn);
	conn_inv_row = search_conn_table_by_conn(&skb_conn_inv);

	if(tcp_header->ack)
	{
		if(conn_row || conn_inv_row)
			return handle_packet_by_conn_row(skb, conn_row) && handle_packet_by_conn_row(skb, conn_inv_row);
		else 
			return NF_DROP;
	}
		
	// ACK = 0
	if(tcp_header->syn)
	{
		if(!conn_row && !conn_inv_row)
		{
			conn_row = add_conn_row(&skb_conn, TCP_CLOSE);
			conn_inv_row = add_conn_row(&skb_conn_inv, TCP_CLOSE);
			add_conn_row_to_conn_hash(conn_row, hash_conn(&conn_row->conn));
			add_conn_row_to_conn_hash(conn_inv_row, hash_conn(&conn_inv_row->conn));
		}	
		return handle_packet_by_conn_row(skb, conn_row) && handle_packet_by_conn_row(skb, conn_inv_row);
	}

	return NF_DROP;
}

static void set_packet_fields(struct sk_buff *skb, ip_t src_ip, port_t src_port, ip_t dst_ip, port_t dst_port)
{
	struct iphdr* iph = ip_hdr(skb);
	struct tcphdr* tcph = tcp_hdr(skb);
	int tcp_len;

	iph->saddr = src_ip;
	tcph->source = src_port;
	iph->daddr = dst_ip;	
	tcph->dest = dst_port;
	
	tcp_len = skb->len - (iph->ihl<<2);
	tcph->check = 0; // critical for checksum correctness
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, iph->protocol, csum_partial((char *)tcph, tcp_len, 0));

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	iph->check = 0; // critical for checksum correctness
	iph->check = ip_fast_csum(iph, iph->ihl);
}

static int prert_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int i;
	rule_t* rule;
	struct iphdr* iph = ip_hdr(skb);
	struct tcphdr* tcph;
	u_int8_t packet_prot = iph->protocol;
	reason_t reason;
	u_int8_t action = NO_DECISION;
	int dest_port;

	if((iph->version != 4) || (packet_prot != PROT_UDP && packet_prot != PROT_ICMP && packet_prot != PROT_TCP) || rule_match(&loopback_rule, skb))
		return NF_ACCEPT;

	if(packet_prot == PROT_TCP)
	{
		if(tcp_hdr(skb)->ack || tcp_hdr(skb)->source == htons(20)) // src_port = 20 represents an ftp data connection from the server
		{
			action = handle_by_conn_tab(skb);
			reason = action == NF_DROP ? REASON_ILLEGAL_VALUE : REASON_EXISTING_TCP_CONNECTION;
			goto post_decision;
		}
	}


	if(is_xmas_packet(skb))
	{
		action = NF_DROP;
		reason = REASON_XMAS_PACKET;
		goto post_decision;
	}

	for (i = 0; i < num_custom_rules; i++)
	{
		rule = custom_rules+i;
		if (rule_match(rule, skb))
		{
			action = rule->action;
			reason = i;
			break;
		}
	}
	if(action == NO_DECISION)
	{
		action = default_rule.action;
		reason = REASON_NO_MATCHING_RULE;
		goto post_decision;
	}
	if(packet_prot == PROT_TCP && action == NF_ACCEPT)
	{
		action = handle_by_conn_tab(skb);
		reason = action == NF_DROP ? REASON_ILLEGAL_VALUE : reason;
		goto post_decision;
	}


post_decision:
	add_log(create_log(skb, action, reason));

	if(packet_prot == PROT_TCP)
	{
		tcph = tcp_hdr(skb);
		dest_port = tcph->dest;
		if(dest_port == PORT_HTTP_SERVER || dest_port == PORT_FTP_SERVER)
		{
			set_packet_fields(skb, iph->saddr, tcph->source, htonl(INADDR_LOOPBACK), htons(ntohs(dest_port)*10));
		}
		
	}

	return action;
}


static int localout_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	conn_row_p_node* curr;
	conn_t *correct_conn;
	struct tcphdr* tcph;
	struct iphdr* iph = ip_hdr(skb);

	if((iph->version != 4) || (iph->protocol != PROT_TCP) || rule_match(&loopback_rule, skb))
		return NF_ACCEPT;


	hash_for_each_possible(conn_hashtable, curr, hnode, tcph->source)
	{
		if(curr->conn_row->mitm_src_port == tcph->source)
		{
			correct_conn = &curr->conn_row->conn;
			set_packet_fields(skb, correct_conn->src_ip, correct_conn->src_port, correct_conn->dst_ip, correct_conn->dst_port);
		}
	}

	return NF_ACCEPT;
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
		&& rule->src_port <= htons(PORT_ABOVE_1023)
		&& rule->dst_port <= htons(PORT_ABOVE_1023)
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
	int i;
	for (i = 0; i < num_custom_rules; i++)
		curr = copy_rule_to_buffer(curr, custom_rules+i);

	return curr - buf;
}

// deletes all nodes from klist and frees all kmalloc-ed memory
void free_log_klist(struct klist* list)
{
	struct klist_iter iter;
	void* curr_node;
	struct klist_node *prev;
	struct klist_node *curr;
	void* tail = list == &log_klist ? tail_log : tail_conn;
	struct klist_node *tail_knode; 

	if(!tail)
		return;
	
	tail_knode = list == &log_klist ? &((log_node*)tail)->node : &((conn_row_node*)tail)->node;


	klist_iter_init_node(list, &iter, tail_knode);

	do 
	{
		curr = iter.i_cur;
		if(list == &log_klist)
			kfree(cast_to_log_node(curr)->data);
		prev = klist_prev(&iter);
		klist_del(curr);
		kfree(curr_node);
	} while(prev);

	klist_iter_exit(&iter);

}

ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	free_klist(&log_klist);
	klist_init(&log_klist, NULL, NULL);
	tail_log = NULL;
	return count;
}

ssize_t modify_mitm(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	ip_t client_ip;
	port_t client_port;
	const char *curr = buf;

	memcpy(&client_ip, curr, sizeof(client_ip));
	curr += sizeof(client_ip);

	memcpy(&client_port, curr, sizeof(client_ip));
	curr += sizeof(client_port);

	memcpy(&curr_mitm_port, curr, sizeof(client_ip));
	curr += sizeof(client_ip);
	
	search

	return count;
}

ssize_t display_mitm(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	char *curr = buf;


	memcpy(curr, )

	return curr - buf;
}

// deletes all entries from hashtable and frees all kmalloc-ed memory
void free_conn_hashtable(void)
{
    conn_row_p_node *conn_row_p;
	struct hlist_node *tmp;
    int bucket;

    // Free memory for elements in the old hashtable
    hash_for_each_safe(conn_hashtable, bucket, tmp, conn_row_p, hnode) {
        hash_del(&conn_row_p->hnode);
        kfree(conn_row_p);
    }
}

char* copy_conn_row_to_buffer(char *buff, conn_row_node *conn_row)
{
	char *curr = buff;

	COPY_AND_ADVANCE(curr, conn_row, conn.src_ip);
	COPY_AND_ADVANCE(curr, conn_row, conn.dst_ip);
	COPY_AND_ADVANCE(curr, conn_row, conn.src_port);
	COPY_AND_ADVANCE(curr, conn_row, conn.dst_port);
	COPY_AND_ADVANCE(curr, conn_row, state);

	return curr;
}

// ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
// {
// 	char *curr = buf;
// 	conn_row_node *conn_row;
// 	int bucket;
// 	hash_for_each(conn_hashtable, bucket, conn_row, hnode)
// 	{
// 		curr = copy_conn_row_to_buffer(curr, conn_row);
// 	}

// 	return curr - buf;
// }


ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	conn_row_node *conn_row;
	char *curr = buf;
	struct klist_iter iter;

	klist_iter_init(&conn_klist, &iter);
	while(klist_next(&iter))
	{
		conn_row = cast_to_conn_row_node(iter.i_cur);
		curr = copy_conn_row_to_buffer(curr, conn_row);
	}
	klist_iter_exit(&iter);

	return curr-buf;
}


static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO, display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR, NULL, modify_reset);
static DEVICE_ATTR(conns, S_IRUSR, display_conns, NULL);
static DEVICE_ATTR(mitm, S_IWUSR | S_IRUGO, display_mitm, modify_mitm);

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

	conns_device = device_create(sysfs_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONNS);
	if (IS_ERR(conns_device))
		goto conns_device_create_failed;

	if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
		goto conns_attr_create_failed;
	
	if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_mitm.attr))
		goto mitm_attr_create_failed;

	return 0;

	// error handling
mitm_attr_create_failed:
conns_attr_create_failed:
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));
conns_device_create_failed:
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
	klist_init(&conn_klist, NULL, NULL);
	hash_init(conn_hashtable);

	nfho_prert.hook = (nf_hookfn*)prert_hook_function;
    nfho_prert.hooknum = NF_INET_PRE_ROUTING;
    nfho_prert.pf = PF_INET;
    nfho_prert.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_prert);

	nfho_localout.hook = (nf_hookfn*)localout_hook_function;
    nfho_localout.hooknum = NF_INET_LOCAL_OUT;
    nfho_localout.pf = PF_INET;
    nfho_localout.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_localout);


    if(register_sysfs_chrdev())
	{
		printk(KERN_ERR "firewall module failed to load\n");
		return -1;
	}
	printk(KERN_INFO "firewall module loaded\n");
	return 0; 
}

static void __exit my_module_exit_function(void) {
	free_klist(&log_klist);
	free_klist(&conn_klist);
	free_conn_hashtable();

    nf_unregister_net_hook(&init_net, &nfho_prert);
    nf_unregister_net_hook(&init_net, &nfho_localout);

	device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_destroy(sysfs_class, MKDEV(major_number, MINOR_CONNS));

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