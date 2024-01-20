#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO and for the Macros */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// nfho_x correlates to a netfilter hook on the x point in the routing diagram
static struct nf_hook_ops nfho_fwd;
static struct nf_hook_ops nfho_post;
static struct nf_hook_ops nfho_inp;


static int fwd_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    printk(KERN_INFO "*** Packet Dropped ***\n");
    return NF_DROP;
}

// used for both the post-routing hook and the input hook
static int post_inp_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    printk(KERN_INFO "*** Packet Accepted ***\n");
    return NF_ACCEPT;
}

static int __init my_module_init_function(void) {

    nfho_fwd.hook = (nf_hookfn*)fwd_hook_function;
    // defining the hook location on the routing diagram
    nfho_fwd.hooknum = NF_INET_FORWARD;
    // hooks on IPV4 packets
    nfho_fwd.pf = PF_INET;
    // this hook is the first to be called when a packet reaches the relevant point
    nfho_fwd.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_fwd);

    nfho_post.hook = (nf_hookfn*)post_inp_hook_function;
    nfho_post.hooknum = NF_INET_POST_ROUTING;
    nfho_post.pf = PF_INET;
    nfho_post.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_post);

    nfho_inp.hook = (nf_hookfn*)post_inp_hook_function;
    nfho_inp.hooknum = NF_INET_LOCAL_IN;
    nfho_inp.pf = PF_INET;
    nfho_inp.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_inp);

	printk(KERN_INFO "hw1secws module loaded\n");

	return 0; /* if non-0 return means init_module failed */
}
static void __exit my_module_exit_function(void) {
    nf_unregister_net_hook(&init_net, &nfho_fwd);
    nf_unregister_net_hook(&init_net, &nfho_post);
    nf_unregister_net_hook(&init_net, &nfho_inp);
	printk(KERN_INFO "hw1secws module unloaded\n");
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);

MODULE_LICENSE("GPL");