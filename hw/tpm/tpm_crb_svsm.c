/*
 * tpm_crb_svsm.c - QEMU's TPM CRB_SVSM interface emulator
 *
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * tpm_crb_svsm is a device for TPM 2.0 Command Response Buffer (CRB) Interface
 * as defined in TCG PC Client Platform TPM Profile (PTP) Specification
 * Family “2.0” Level 00 Revision 01.03 v22
 */

#include "qemu/osdep.h"

#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/pci/pci_ids.h"
#include "hw/acpi/tpm.h"
#include "migration/vmstate.h"
#include "sysemu/tpm_backend.h"
#include "sysemu/tpm_util.h"
#include "sysemu/reset.h"
#include "tpm_prop.h"
#include "tpm_ppi.h"
#include "trace.h"
#include "qom/object.h"
#include "exec/address-spaces.h"

struct CRBSVSMState {
    DeviceState parent_obj;

    TPMBackendCmd cmd;

    uint32_t regs[TPM_CRB_R_MAX];
    size_t be_buffer_size;

    bool ppi_enabled;
    TPMPPI ppi;
};
typedef struct CRBSVSMState CRBSVSMState;

DECLARE_INSTANCE_CHECKER(CRBSVSMState, CRB_SVSM,
                         TYPE_TPM_CRB_SVSM)	

#define CRB_INTF_TYPE_CRB_ACTIVE 0b1
#define CRB_INTF_VERSION_CRB 0b1
#define CRB_INTF_CAP_LOCALITY_0_ONLY 0b0
#define CRB_INTF_CAP_IDLE_FAST 0b0
#define CRB_INTF_CAP_XFER_SIZE_64 0b11
#define CRB_INTF_CAP_FIFO_NOT_SUPPORTED 0b0
#define CRB_INTF_CAP_CRB_SUPPORTED 0b1
#define CRB_INTF_IF_SELECTOR_CRB 0b1

#define CRB_CTRL_CMD_SIZE (TPM_CRB_ADDR_SIZE - A_CRB_DATA_BUFFER)


static void tpm_crb_svsm_request_completed(TPMIf *ti, int ret)
{
    (void)ti;
    (void)ret;
}

static enum TPMVersion tpm_crb_svsm_get_version(TPMIf *ti)
{
    (void)ti;
    return TPM_VERSION_2_0;
}

static int tpm_crb_svsm_pre_save(void *opaque)
{
    (void)opaque;
    return 0;
}

static const VMStateDescription vmstate_tpm_crb_svsm = {
    .name = "tpm-crb-svsm",
    .pre_save = tpm_crb_svsm_pre_save,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, CRBSVSMState, TPM_CRB_R_MAX),
        VMSTATE_END_OF_LIST(),
    }
};

static Property tpm_crb_svsm_properties[] = {
    DEFINE_PROP_BOOL("ppi", CRBSVSMState, ppi_enabled, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void tpm_crb_svsm_reset(void *dev)
{
    CRBSVSMState *s = CRB_SVSM(dev);

    memset(s->regs, 0, sizeof(s->regs));

    ARRAY_FIELD_DP32(s->regs, CRB_LOC_STATE,
                     tpmRegValidSts, 1);
    ARRAY_FIELD_DP32(s->regs, CRB_CTRL_STS,
                     tpmIdle, 1);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceType, CRB_INTF_TYPE_CRB_ACTIVE);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceVersion, CRB_INTF_VERSION_CRB);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapLocality, CRB_INTF_CAP_LOCALITY_0_ONLY);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapCRBIdleBypass, CRB_INTF_CAP_IDLE_FAST);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapDataXferSizeSupport, CRB_INTF_CAP_XFER_SIZE_64);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapFIFO, CRB_INTF_CAP_FIFO_NOT_SUPPORTED);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     CapCRB, CRB_INTF_CAP_CRB_SUPPORTED);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     InterfaceSelector, CRB_INTF_IF_SELECTOR_CRB);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID,
                     RID, 0b0000);
    ARRAY_FIELD_DP32(s->regs, CRB_INTF_ID2,
                     VID, PCI_VENDOR_ID_IBM);

    s->regs[R_CRB_CTRL_CMD_SIZE] = CRB_CTRL_CMD_SIZE;
    s->regs[R_CRB_CTRL_CMD_LADDR] = TPM_CRB_ADDR_BASE + A_CRB_DATA_BUFFER;
    s->regs[R_CRB_CTRL_RSP_SIZE] = CRB_CTRL_CMD_SIZE;
    s->regs[R_CRB_CTRL_RSP_ADDR] = TPM_CRB_ADDR_BASE + A_CRB_DATA_BUFFER;

    s->be_buffer_size = CRB_CTRL_CMD_SIZE;
}

static void tpm_crb_svsm_realize(DeviceState *dev, Error **errp)
{
    CRBSVSMState *s = CRB_SVSM(dev);
    MemoryRegion *svsm_vtpm;


    if (!tpm_find()) {
        error_setg(errp, "at most one TPM device is permitted");
        return;
    }

    if (s->ppi_enabled) {
        //tpm_ppi_init(&s->ppi, get_system_memory(),
        //             TPM_PPI_ADDR_BASE, OBJECT(s));
    }

    svsm_vtpm = g_malloc(sizeof(*svsm_vtpm));

    memory_region_init_ram(svsm_vtpm, NULL, "svsm_vtpm.ram", TPM_CRB_ADDR_SIZE, &error_fatal);
    memory_region_add_subregion(get_system_memory(), TPM_CRB_ADDR_BASE, svsm_vtpm);

    qemu_register_reset(tpm_crb_svsm_reset, dev);
}

static void tpm_crb_svsm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    TPMIfClass *tc = TPM_IF_CLASS(klass);

    printf("%s\n", __func__);
    dc->realize = tpm_crb_svsm_realize;
    device_class_set_props(dc, tpm_crb_svsm_properties);
    dc->vmsd  = &vmstate_tpm_crb_svsm;
    dc->user_creatable = true;
    tc->model = TPM_MODEL_TPM_CRB;
    tc->get_version = tpm_crb_svsm_get_version;
    tc->request_completed = tpm_crb_svsm_request_completed;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo tpm_crb_svsm_info = {
    .name = TYPE_TPM_CRB_SVSM,
    /* could be TYPE_SYS_BUS_DEVICE (or LPC etc) */
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(CRBSVSMState),
    .class_init  = tpm_crb_svsm_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_TPM_IF },
        { }
    }
};

static void tpm_crb_svsm_register(void)
{
    printf("%s, called\n", __func__);
    type_register_static(&tpm_crb_svsm_info);
}

type_init(tpm_crb_svsm_register)
