#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO and for the Macros */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Katee");

// nfho_x correlates to a netfilter hook on the x point in the routing diagram
static struct nf_hook_ops nfho_fwd;
static struct nf_hook_ops nfho_post;
static struct nf_hook_ops nfho_inp;

#define SYSFS_CLASS_NAME "firewall_devices"
#define SYSFS_DEVICE_NAME "packet_summary"

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int accepted = 0;
static unsigned int dropped = 0;


static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display_accepted(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", accepted);
}

ssize_t modify_accepted(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		accepted = temp;
	return count;	
}

ssize_t display_dropped(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", dropped);
}

ssize_t modify_dropped(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		dropped = temp;
	return count;	
}

static DEVICE_ATTR(accepted_attr, S_IWUSR | S_IRUGO , display_accepted, modify_accepted);
static DEVICE_ATTR(dropped_attr, S_IWUSR | S_IRUGO , display_dropped, modify_dropped);

static int register_sysfs_device(void)
{
	//create char device
	major_number = register_chrdev(0, SYSFS_DEVICE_NAME, &fops);
	if (major_number < 0)
		goto register_chrdev_failed;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, SYSFS_CLASS_NAME);
	if (IS_ERR(sysfs_class))
		goto class_create_failed;
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, SYSFS_CLASS_NAME "_" SYSFS_DEVICE_NAME);	
	if (IS_ERR(sysfs_device))
		goto device_create_failed;
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_dropped_attr.attr))
		goto attr_create_failed;

	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_accepted_attr.attr))
		goto attr_create_failed;
	
	// success
	return 0;

	// error handling
attr_create_failed:
	device_destroy(sysfs_class, MKDEV(major_number, 0));
device_create_failed:
	class_destroy(sysfs_class);
class_create_failed:
	unregister_chrdev(major_number, SYSFS_DEVICE_NAME);
register_chrdev_failed:
	return -1;

}

static int fwd_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    dropped++;
    printk(KERN_INFO "*** Packet Dropped ***\n");
    return NF_DROP;
}

// used for both the post-routing hook and the input hook
static int post_inp_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    accepted++;
    printk(KERN_INFO "*** Packet Accepted ***\n");
    return NF_ACCEPT;
}


static void register_net_hooks(void)
{
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
} 


static void unregister_net_hooks(void)
{
    nf_unregister_net_hook(&init_net, &nfho_fwd);
    nf_unregister_net_hook(&init_net, &nfho_post);
    nf_unregister_net_hook(&init_net, &nfho_inp);
}

static void unregister_sysfs_chrdev(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_accepted_attr.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_dropped_attr.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, SYSFS_DEVICE_NAME);
}

static int __init my_module_init_function(void) {
	register_net_hooks();
    if(register_sysfs_device())
	{
		printk(KERN_ERR "hw2secws module failed to load\n");
		return -1;
	}
	printk(KERN_INFO "hw2secws module loaded\n");
	return 0; /* if non-0 return means init_module failed */
}

static void __exit my_module_exit_function(void) {
    unregister_net_hooks();
    unregister_sysfs_chrdev();
	printk(KERN_INFO "hw2secws module unloaded\n");
}

module_init(my_module_init_function);
module_exit(my_module_exit_function);