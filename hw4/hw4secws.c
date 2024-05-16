#include "fw.h"
#include <linux/uaccess.h>
#include <linux/klist.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <net/tcp_states.h>
#include <net/tcp.h>
#include <linux/timer.h>



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
#define PORT_FTP_DATA_CONNECTION_SERVER 20
#define IN_NET_IP_ADDR 50397450
#define OUT_NET_IP_ADDR 50462986
#define TIMEOUT_TIMERS_COUNT 100
#define TIMEOUT_MILISECONDS 10000
#define DEVICE_NAME_CONNS "conns"


#define subnet_prefix_size_to_mask(size) ((size)==sizeof(ip_t)*8 ? -1 : (1 << (size))-1)

#define COPY_FROM_VAR_AND_ADVANCE(buf, var) do {\
						memcpy((buf), &(var), sizeof(var));\
						(buf) += sizeof(var);\
						} while(0)

#define COPY_TO_VAR_AND_ADVANCE(buf, var) do {\
						memcpy(&(var), (buf), sizeof(var));\
						(buf) += sizeof(var);\
						} while(0)


// represents a chunck of log rows that is kept in a klist
typedef struct {
	int rows_count;
    log_row_t* data;
    struct klist_node node;
} log_node;

// custom iterator that goes over log rows
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

// connection row that is kept in a klist
typedef struct {
	conn_t conn;	
	int state;
	port_t mitm_src_port;
	struct klist_node node;
} conn_row_node;

// pointer to a connection row that is kept in the hash table
typedef struct {
	conn_row_node* conn_row;
	struct hlist_node hnode;
} conn_row_p_node;

// timer for deleting connection row, set when a fin is sent
typedef struct {
	struct timer_list timer;
	conn_row_node* conn_row;
} timeout_timer;


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
static timeout_timer timeout_timers[TIMEOUT_TIMERS_COUNT];

// the hashtable will contain 2^(CONN_HASHTABLE_SIZE_BITS) buckets, each containing linked list of conn_row_p_node's
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
static conn_row_node* cast_to_conn_row_node(struct klist_node* knode)
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

// given a packet and a rule, compares between them and decides if the packet matches the rule
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


// creates a log row struct. this function will be called only for IPV4 TCP/UDP/ICMP packets
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

// converts a connection into a hash for hash table access
static int hash_conn(conn_t *conn)
{
	return conn->src_ip + conn->dst_ip + conn->src_port + conn->dst_port;
}

// searches hash table for a connection row by hash-value = hash_conn(conn)
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

// searches hash table for a connection row by hash-value = mitm_port
static conn_row_node* search_conn_table_by_mitm_port(port_t mitm_port)
{
	conn_row_p_node* curr;

	hash_for_each_possible(conn_hashtable, curr, hnode, mitm_port)
	{
		if(curr->conn_row->mitm_src_port == mitm_port)
			return curr->conn_row;
	}

	return NULL;
}

// searches hash table for a connection row by hash-value = dst_ip + dst_port
static conn_row_node* search_conn_table_by_dst(ip_t dst_ip, port_t dst_port)
{
	conn_row_p_node* curr;

	hash_for_each_possible(conn_hashtable, curr, hnode, dst_ip + dst_port)
	{
		if(curr->conn_row->conn.dst_ip == dst_ip && curr->conn_row->conn.dst_port == dst_port)
			return curr->conn_row;
	}

	return NULL;
}

// deletes a connection row from the hash-table and then from the linked list
static void del_conn_row(conn_row_node *conn_row_del)
{
	conn_row_p_node* curr;
	struct klist_iter iter;
	conn_row_node *conn_row;
	conn_row_node *prev = NULL;


	hash_for_each_possible(conn_hashtable, curr, hnode, hash_conn(&conn_row_del->conn))
	{
		if(conn_eq(&curr->conn_row->conn, &conn_row_del->conn))
			hash_del(&curr->hnode);
	}


	hash_for_each_possible(conn_hashtable, curr, hnode, conn_row_del->mitm_src_port)
	{
		if(curr->conn_row->mitm_src_port == conn_row_del->mitm_src_port)
			hash_del(&curr->hnode);
	}

	hash_for_each_possible(conn_hashtable, curr, hnode, conn_row_del->conn.dst_ip + conn_row_del->conn.dst_port)
	{
		if(curr->conn_row->conn.dst_ip == conn_row_del->conn.dst_ip && curr->conn_row->conn.dst_port == conn_row_del->conn.dst_port)
			hash_del(&curr->hnode);
	}


	klist_iter_init(&conn_klist, &iter);
	while(klist_next(&iter))
	{
		conn_row = cast_to_conn_row_node(iter.i_cur);
		if(conn_eq(&conn_row->conn, &conn_row_del->conn))
		{
			if(tail_conn == conn_row)
			{
				tail_conn = prev;
			}
			klist_del(iter.i_cur);
			kfree(conn_row);
			break;
		}
		prev = conn_row;
	}
	klist_iter_exit(&iter);
}

// adds a connection row to the linked list
static conn_row_node* add_conn_row(conn_t *conn, int initialState)
{
	conn_row_node* conn_row = kmalloc(sizeof(conn_row_node), GFP_KERNEL);
	if(!conn_row){
		printk(KERN_ERR "Failed to allocate memory\n");
		return NULL;
	}

	conn_row->conn = *conn;
	conn_row->state = initialState;
	conn_row->mitm_src_port = 0;
	klist_add_tail(&conn_row->node, &conn_klist);
	tail_conn = conn_row;
	return conn_row;
}

// adds a connection row pointer to the hash table by the given hash value
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

// called after the connection row deletion timer expires. The fact that the timer has expired is enough for later deletion
void timeout_handler(struct timer_list *timer)
{
	// do nothing.
	return;
}


// decides what to do with the packet by the connection row in the table, and also updates if needed
// only called for the sender of the packet
static int handle_packet_by_conn_row(struct sk_buff *skb, conn_row_node* conn_row)
{
	struct tcphdr* tcp_header = tcp_hdr(skb);
	int i;
	timeout_timer *curr;

	if(tcp_header->rst)
	{
		conn_row->state = TCP_CLOSE;
		return NF_ACCEPT;
	}

	switch (conn_row->state)
	{
		case TCP_CLOSE:
			if(tcp_header->syn && !tcp_header->ack)
				conn_row->state = TCP_SYN_SENT;

			else
				return NF_DROP;
			
			break;

		case TCP_LISTEN:
			if(tcp_header->syn && tcp_header->ack)
			{
				conn_row->state = TCP_SYN_RECV;
			}
			else
			{
				return NF_DROP;
			}
			
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
			{
				if(tcp_header->fin)
				{
					conn_row->state = TCP_FIN_WAIT1;
					// try finding an available timeout timer, and cleanup finished timers
					for (i = 0; i < TIMEOUT_TIMERS_COUNT; i++)
					{
						curr = &timeout_timers[i];
						if(!timer_pending(&curr->timer))
						{
							if(curr->conn_row)
							{
								// found an expired timer of a connection row to be deleted
								del_conn_row(curr->conn_row);
							}
							curr->conn_row = conn_row;
							// set the timeout timer and after TIMEOUT_MILISECONDS, conn_row will be ready for deletion
							mod_timer(&timeout_timers[i].timer, jiffies + msecs_to_jiffies(TIMEOUT_MILISECONDS));
							break;	
						}
					}
					// if we didn't find an available timer, just close the connection row right now, don't wait for proper termination
					if(i == TIMEOUT_TIMERS_COUNT)		
						conn_row->state = TCP_CLOSE;
				}	
				else
				{
					conn_row->state = TCP_ESTABLISHED;
				}
			}
			else
				return NF_DROP;
			break;	

		case TCP_FIN_WAIT1:
		case TCP_TIME_WAIT:
			if(tcp_header->ack)
				conn_row->state = TCP_TIME_WAIT;
			else
				return NF_DROP;
			break;

	}
	return NF_ACCEPT;

}

// decides whether to drop or accept the packet by reading the connection table and updates the connection table by the packet.
static int handle_by_conn_tab(struct sk_buff *skb)
{
	struct iphdr* ip_header = ip_hdr(skb);
	struct tcphdr* tcp_header = tcp_hdr(skb);
	conn_t skb_conn_sender = { .src_ip = ip_header->saddr, .src_port = tcp_header->source, .dst_ip = ip_header->daddr, .dst_port = tcp_header->dest };
	conn_t skb_conn_receiver = { .src_ip = ip_header->daddr, .src_port = tcp_header->dest, .dst_ip = ip_header->saddr, .dst_port = tcp_header->source };
	conn_row_node *conn_row_sender, *conn_row_receiver;
	int result = NF_DROP;
	int i;
	timeout_timer *curr;


	conn_row_sender = search_conn_table_by_conn(&skb_conn_sender);

	// means that this packet is of an existing TCP connection
	if(tcp_header->ack || tcp_header->rst)
	{
		if(conn_row_sender)
		{
			// we only update the sender's connection row because we cannot assume something changed for the receiver (we didn't get any new data from him)
			result = handle_packet_by_conn_row(skb, conn_row_sender);
			goto post_result;
		}
	}
		
	// ACK = 0
	if(tcp_header->syn)
	{
		// if it's an ftp data connection, the sender's row must have been already in the connection table thanks to the userspace program
		if(tcp_header->source == htons(PORT_FTP_DATA_CONNECTION_SERVER) && !conn_row_sender)
		{
			result = NF_DROP;
			goto post_result;
		}

		if(!conn_row_sender)
		{
			// adding connection row for two directions: both for sender and receiver
			conn_row_sender = add_conn_row(&skb_conn_sender, TCP_CLOSE);
			conn_row_receiver = add_conn_row(&skb_conn_receiver, TCP_LISTEN);
			// adding connection rows pointers into the hash table
			add_conn_row_to_conn_hash(conn_row_sender, hash_conn(&conn_row_sender->conn));
			add_conn_row_to_conn_hash(conn_row_receiver, hash_conn(&conn_row_receiver->conn));
			// if it's a packet destined for a server then also add to hash table by hash-value = dst_ip + dst_port (for MITM purposes)
			if(tcp_header->dest == htons(PORT_HTTP_SERVER) || tcp_header->dest == htons(PORT_FTP_SERVER))
			{
				add_conn_row_to_conn_hash(conn_row_sender, conn_row_sender->conn.dst_ip + conn_row_sender->conn.dst_port);
				add_conn_row_to_conn_hash(conn_row_receiver, conn_row_receiver->conn.dst_ip + conn_row_receiver->conn.dst_port);
			}

		}	
		result = handle_packet_by_conn_row(skb, conn_row_sender);
		goto post_result;
	}

post_result:
	// if something caused the state to be TCP_CLOSE, just delete the connection row
	if(conn_row_sender && conn_row_sender->state == TCP_CLOSE)
	{
		del_conn_row(conn_row_sender);
	}

	// timeout timers that just expired, their connection rows are deleted here, and the timers can be reused
 	for (i = 0; i < TIMEOUT_TIMERS_COUNT; i++)
	{
		curr = &timeout_timers[i];
		if(!timer_pending(&curr->timer))
		{
			if(curr->conn_row)
			{
				del_conn_row(curr->conn_row);
			}

			curr->conn_row = NULL;
		}
	} 

	return result;
}

// this function takes a packet and sets its fields. it is taken from the github example provided to us.
static void set_packet_fields(struct sk_buff *skb, ip_t src_ip, port_t src_port, ip_t dst_ip, port_t dst_port)
{
	int tcp_len;
	struct iphdr* iph = ip_hdr(skb);
	struct tcphdr* tcph = tcp_hdr(skb);

	iph->daddr = dst_ip;	
	tcph->dest = dst_port;
	iph->saddr = src_ip;
	tcph->source = src_port;

	/* Fix IP header checksum */
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

	/*
	* From Linux doc here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L90
	* CHECKSUM_NONE:
	*
	*   Device did not checksum this packet e.g. due to lack of capabilities.
	*   The packet contains full (though not verified) checksum in packet but
	*   not in skb->csum. Thus, skb->csum is undefined in this case.
	*/
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	/* Linearize the skb */
	if (skb_linearize(skb) < 0) {
		printk(KERN_ERR "failed skb_linearize\n");
	}

	/* Re-take headers. The linearize may change skb's pointers */
	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	/* Fix TCP header checksum */
	tcp_len = (ntohs(iph->tot_len) - ((iph->ihl) << 2));
	tcph->check = 0;
	tcph->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcp_len, 0));

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
	port_t src_port, dest_port, modified_dest_port;
	ip_t my_addr;
	conn_row_node *conn_row;
	conn_t skb_conn_inverse;
	
 
	if((iph->version != 4) || (packet_prot != PROT_UDP && packet_prot != PROT_ICMP && packet_prot != PROT_TCP) 
	|| rule_match(&loopback_rule, skb) || iph->daddr == OUT_NET_IP_ADDR || iph->daddr == IN_NET_IP_ADDR)
		return NF_ACCEPT;

	// if packet is TCP and ACK is set (or came from port 20, which is ftp data connection), manage with connection table
	if(packet_prot == PROT_TCP)
	{
		if(tcp_hdr(skb)->ack || tcp_hdr(skb)->rst || tcp_hdr(skb)->source == htons(PORT_FTP_DATA_CONNECTION_SERVER))
		{
			action = handle_by_conn_tab(skb);
			reason = action == NF_DROP ? REASON_ILLEGAL_VALUE : REASON_EXISTING_TCP_CONNECTION;
			goto post_decision;
		}
	}



	// else, check with static rule table
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
	// no rule is matched, activate default rule
	if(action == NO_DECISION)
	{
		action = default_rule.action;
		reason = REASON_NO_MATCHING_RULE;
		goto post_decision;
	}
	// after passing static rule table, manage the connection table according to the new SYN packet
	if(packet_prot == PROT_TCP && action == NF_ACCEPT)
	{
		action = handle_by_conn_tab(skb);
		reason = action == NF_DROP ? REASON_ILLEGAL_VALUE : reason;
		goto post_decision;
	}


post_decision:
	add_log(create_log(skb, action, reason));

	// manage MITM if needed
	if(packet_prot == PROT_TCP)
	{
		tcph = tcp_hdr(skb);
		dest_port = tcph->dest;
		src_port = tcph->source;

		my_addr = strcmp(skb->dev->name, OUT_NET_DEVICE_NAME)==0 ? OUT_NET_IP_ADDR : IN_NET_IP_ADDR;

		// divert packet from client to our userspace
		if(dest_port == htons(PORT_HTTP_SERVER) || dest_port == htons(PORT_FTP_SERVER))
		{
			modified_dest_port = htons(ntohs(dest_port)*10);
			set_packet_fields(skb, iph->saddr, tcph->source, my_addr, modified_dest_port);
		}
		// divert packet from server to our userspace
		if(src_port == htons(PORT_HTTP_SERVER) || src_port == htons(PORT_FTP_SERVER))
		{
			skb_conn_inverse.src_ip = iph->daddr;
			skb_conn_inverse.dst_ip = iph->saddr;
			skb_conn_inverse.src_port = tcph->dest;
			skb_conn_inverse.dst_port = tcph->source;
			conn_row = search_conn_table_by_conn(&skb_conn_inverse);


			if(conn_row)
			{
				set_packet_fields(skb, iph->saddr, tcph->source, my_addr, conn_row->mitm_src_port);
			}
		}
	}

	return action;
}


static int localout_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	conn_t *correct_conn;
	struct tcphdr* tcph;
	struct iphdr* iph = ip_hdr(skb);
	conn_row_node* conn_row;
	
	if((iph->version != 4) || (iph->protocol != PROT_TCP) || rule_match(&loopback_rule, skb))
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);

	// for packets from MITM userspace to client, disguise as the original server
	if(tcph->source == htons(PORT_HTTP_SERVER*10) || tcph->source == htons(PORT_FTP_SERVER*10))
	{
		if((conn_row = search_conn_table_by_dst(iph->daddr, tcph->dest)))
		{
			correct_conn = &conn_row->conn;
			set_packet_fields(skb, correct_conn->src_ip, correct_conn->src_port, correct_conn->dst_ip, correct_conn->dst_port);
		}
	}
	// for packets from MITM userspace to server, disguise as the original client
	else if ((conn_row = search_conn_table_by_mitm_port(tcph->source)))
	{
		correct_conn = &conn_row->conn;
		set_packet_fields(skb, correct_conn->src_ip, correct_conn->src_port, correct_conn->dst_ip, correct_conn->dst_port);
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

	COPY_FROM_VAR_AND_ADVANCE(curr, log->timestamp);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->protocol);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->action);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->src_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->dst_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->src_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->dst_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->reason);
	COPY_FROM_VAR_AND_ADVANCE(curr, log->count);

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

	COPY_TO_VAR_AND_ADVANCE(curr, rule->rule_name);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->direction);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->src_ip);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->src_prefix_size);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->dst_ip);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->dst_prefix_size);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->src_port);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->dst_port);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->protocol);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->ack);
	COPY_TO_VAR_AND_ADVANCE(curr, rule->action);

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
	
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->rule_name);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->direction);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->src_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->src_prefix_size);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->dst_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->dst_prefix_size);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->src_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->dst_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->protocol);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->ack);
	COPY_FROM_VAR_AND_ADVANCE(curr, rule->action);

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
void free_klist(struct klist* list)
{
	struct klist_iter iter;
	void* curr_node;
	struct klist_node *prev;
	struct klist_node *curr;
	void* tail = (list == &log_klist) ? (void*)tail_log : (void*)tail_conn;
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

// change mitm_src_port for the client's connection row
ssize_t modify_mitm(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	ip_t client_ip;
	port_t client_port;
	const char *curr = buf;
	struct klist_iter iter;
	conn_row_node *conn_row;


	COPY_TO_VAR_AND_ADVANCE(curr, client_ip);
	COPY_TO_VAR_AND_ADVANCE(curr, client_port);
	COPY_TO_VAR_AND_ADVANCE(curr, curr_mitm_port);
	
	klist_iter_init(&conn_klist, &iter);
	while(klist_next(&iter))
	{
		conn_row = cast_to_conn_row_node(iter.i_cur);
		if(conn_row->conn.src_ip == client_ip && conn_row->conn.src_port == client_port)
		{
			conn_row->mitm_src_port = curr_mitm_port;
			add_conn_row_to_conn_hash(conn_row, curr_mitm_port);
		}
	}
	klist_iter_exit(&iter);

	return count;
}

// get server address from the client's connection row (found by curr_mitm_port)
ssize_t display_mitm(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	char *curr = buf;
	conn_row_node *conn_row;


	conn_row = search_conn_table_by_mitm_port(curr_mitm_port);
	if(!conn_row)
	{
		printk("display_mitm not found\n");
	}

	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.dst_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.dst_port);

	return curr - buf;
}

// add connection row to the connection table (for setting up FTP data connection)
ssize_t modify_add_conn(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	const char *curr = buf;
	conn_row_node *conn_row;
	conn_row_node *conn_inv_row;
	conn_t conn, conn_inv;

	COPY_TO_VAR_AND_ADVANCE(curr, conn.src_ip);
	COPY_TO_VAR_AND_ADVANCE(curr, conn.dst_ip);
	COPY_TO_VAR_AND_ADVANCE(curr, conn.src_port);
	COPY_TO_VAR_AND_ADVANCE(curr, conn.dst_port);

	if(search_conn_table_by_conn(&conn))
		return count;

	conn_inv.src_ip = conn.dst_ip;
	conn_inv.dst_ip = conn.src_ip;
	conn_inv.src_port = conn.dst_port;
	conn_inv.dst_port = conn.src_port;

	conn_row = add_conn_row(&conn, TCP_LISTEN);
	conn_inv_row = add_conn_row(&conn_inv, TCP_CLOSE);
	add_conn_row_to_conn_hash(conn_row, hash_conn(&conn_row->conn));
	add_conn_row_to_conn_hash(conn_inv_row, hash_conn(&conn_inv_row->conn));

	return count;
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

	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.src_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.dst_ip);
	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.src_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->conn.dst_port);
	COPY_FROM_VAR_AND_ADVANCE(curr, conn_row->state);

	return curr;
}

// display all connection rows in connection table by copying data to userspace buffer
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
static DEVICE_ATTR(add_conn, S_IWUSR, NULL, modify_add_conn);

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

	if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_add_conn.attr))
		goto add_conn_attr_create_failed;

	return 0;

	// error handling
add_conn_attr_create_failed:
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
	int i;
	klist_init(&log_klist, NULL, NULL);
	klist_init(&conn_klist, NULL, NULL);
	hash_init(conn_hashtable);

	for (i = 0; i < TIMEOUT_TIMERS_COUNT; i++)
	{
		timer_setup(&timeout_timers[i].timer, timeout_handler, 0);
		timeout_timers[i].conn_row = NULL;
	}

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